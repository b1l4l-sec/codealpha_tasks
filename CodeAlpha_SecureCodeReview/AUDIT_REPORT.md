# Secure Coding Review — Audit Report

**Project:** CodeAlpha Cybersecurity Internship — Task 3  
**Author:** LBIEN Bilal | github.com/b1l4l-sec  
**Target:** Vulnerable Python Flask Web Application  
**Audit Tool:** Bandit v1.9.4 + Manual Code Review  
**Date:** May 2026  

---

## Executive Summary

A deliberately vulnerable Flask web application was developed and subjected to both automated static analysis (Bandit) and manual code review. A total of **7 vulnerabilities** were identified across multiple OWASP Top 10 categories. All findings were remediated in a secure version of the application.

| Severity | Count |
|----------|-------|
| High     | 2     |
| Medium   | 3     |
| Low      | 2     |
| **Total**| **7** |

---

## Audit Methodology

1. **Static Analysis** — Bandit scanned the source code for known insecure patterns
2. **Manual Review** — Line-by-line inspection of authentication, input handling, and configuration
3. **Dynamic Testing** — Live exploitation of each vulnerability in a controlled environment
4. **Remediation** — Secure version developed with all findings fixed

---

## Findings

---

### VULN-01 — SQL Injection

| Field      | Detail |
|------------|--------|
| Severity   | HIGH |
| CWE        | CWE-89 |
| OWASP      | A03:2021 — Injection |
| Location   | `vulnerable/app.py` — `/login` route |
| Tool       | Bandit B608 + Manual |

**Description:**  
User-supplied input is concatenated directly into an SQL query string without sanitization or parameterization. An attacker can manipulate the query logic to bypass authentication entirely.

**Vulnerable Code:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
c.execute(query)
```

**Exploit:**  
Username: `' OR '1'='1' --` | Password: `anything`  
Resulting query:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='anything'
```
The `--` comments out the password check. Login is bypassed.

**Fix — Parameterized Query:**
```python
c.execute("SELECT * FROM users WHERE username = ? AND password = ?",
          (username, hash_password(password)))
```

---

### VULN-02 — Command Injection

| Field      | Detail |
|------------|--------|
| Severity   | HIGH |
| CWE        | CWE-78 |
| OWASP      | A03:2021 — Injection |
| Location   | `vulnerable/app.py` — `/ping` route |
| Tool       | Bandit B605 + Manual |

**Description:**  
User-supplied hostname is passed directly to a shell command via `subprocess.getoutput()`. An attacker can inject arbitrary OS commands using shell metacharacters.

**Vulnerable Code:**
```python
output = subprocess.getoutput(f"ping -c 2 {host}")
```

**Exploit:**  
Input: `google.com; cat /etc/passwd`  
Executes: `ping -c 2 google.com; cat /etc/passwd`  
Result: Full contents of `/etc/passwd` returned to the attacker.

**Fix — Argument List with shell=False:**
```python
if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
    return error("Invalid hostname")

result = subprocess.run(
    ["ping", "-c", "2", host],
    capture_output=True, text=True,
    timeout=10, shell=False
)
```

---

### VULN-03 — Cross-Site Scripting (XSS)

| Field      | Detail |
|------------|--------|
| Severity   | MEDIUM |
| CWE        | CWE-79 |
| OWASP      | A03:2021 — Injection |
| Location   | `vulnerable/app.py` — `/dashboard` route |
| Tool       | Manual |

**Description:**  
User-controlled input from the URL query parameter `name` is interpolated directly into the HTML response via an f-string without escaping. An attacker can inject malicious JavaScript.

**Vulnerable Code:**
```python
name = request.args.get("name", session["user"])
return f"<h2>Welcome, {name}!</h2>"
```

**Exploit:**  
URL: `/dashboard?name=<script>alert('XSS')</script>`  
Result: JavaScript executes in the victim's browser — session hijacking, credential theft possible.

**Fix — Jinja2 Auto-Escaping:**
```python
# In template (Jinja2 escapes automatically)
<div>Welcome back, {{ session.user }}</div>
```

---

### VULN-04 — Hardcoded Secret Key

| Field      | Detail |
|------------|--------|
| Severity   | MEDIUM |
| CWE        | CWE-259 |
| OWASP      | A02:2021 — Cryptographic Failures |
| Location   | `vulnerable/app.py` line 14 |
| Tool       | Bandit B105 |

**Description:**  
The Flask secret key is hardcoded as a weak string. This key is used to sign session cookies. An attacker who knows the key can forge session tokens and impersonate any user.

**Vulnerable Code:**
```python
app.secret_key = "admin123"
```

**Fix — Environment Variable:**
```python
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
```

---

### VULN-05 — Path Traversal via File Upload

| Field      | Detail |
|------------|--------|
| Severity   | MEDIUM |
| CWE        | CWE-22 |
| OWASP      | A01:2021 — Broken Access Control |
| Location   | `vulnerable/app.py` — `/upload` route |
| Tool       | Manual |

**Description:**  
Uploaded filenames are used directly without sanitization. No extension validation is performed. An attacker can upload malicious files (web shells) or use `../` sequences to write files outside the intended directory.

**Vulnerable Code:**
```python
filepath = os.path.join(UPLOAD_FOLDER, f.filename)
f.save(filepath)
```

**Fix — secure_filename + Extension Whitelist:**
```python
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "csv"}

filename = secure_filename(f.filename)
if not allowed_file(filename):
    return error("File type not allowed")
f.save(os.path.join(UPLOAD_FOLDER, filename))
```

---

### VULN-06 — Plaintext Password Storage

| Field      | Detail |
|------------|--------|
| Severity   | LOW |
| CWE        | CWE-256 |
| OWASP      | A02:2021 — Cryptographic Failures |
| Location   | `vulnerable/app.py` — `init_db()` |
| Tool       | Manual |

**Description:**  
User passwords are stored in the database as plaintext. A database breach exposes all user credentials immediately.

**Vulnerable Code:**
```python
c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
```

**Fix — Hashed Storage:**
```python
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin')",
          (hash_password("admin123"),))
```
Note: In production, use `bcrypt` or `argon2` with salting.

---

### VULN-07 — Debug Mode Enabled + Exposed on All Interfaces

| Field      | Detail |
|------------|--------|
| Severity   | HIGH |
| CWE        | CWE-94 / CWE-605 |
| OWASP      | A05:2021 — Security Misconfiguration |
| Location   | `vulnerable/app.py` line 468 |
| Tool       | Bandit B201 + B104 |

**Description:**  
The Flask application is run with `debug=True` and bound to `0.0.0.0`. Debug mode exposes an interactive Werkzeug debugger that allows arbitrary Python code execution. Binding to all interfaces exposes the app to the entire network.

**Vulnerable Code:**
```python
app.run(host="0.0.0.0", port=5000, debug=True)
```

**Fix:**
```python
app.run(host="127.0.0.1", port=5001, debug=False)
```

---

## Bandit Static Analysis Summary

```
Run started: 2026-05-17

Total issues (by severity):
    High:   2  (Command Injection, Debug Mode)
    Medium: 2  (SQL Injection, Bind All Interfaces)
    Low:    2  (Subprocess Import, Hardcoded Password)

Total issues (by confidence):
    High:   2
    Medium: 3
    Low:    1
```

---

## Remediation Summary

| # | Vulnerability | Fix Applied |
|---|---------------|-------------|
| 1 | SQL Injection | Parameterized queries with `?` placeholders |
| 2 | Command Injection | `shell=False` + argument list + regex validation |
| 3 | XSS | Jinja2 template rendering with auto-escaping |
| 4 | Hardcoded Secret Key | `os.environ.get()` + `secrets.token_hex(32)` |
| 5 | Path Traversal | `werkzeug.utils.secure_filename()` + extension whitelist |
| 6 | Plaintext Passwords | SHA-256 hashing (bcrypt recommended for production) |
| 7 | Debug Mode + Open Bind | `debug=False`, bind to `127.0.0.1` only |

---

## Secure Coding Best Practices

- Never trust user input — validate, sanitize, and escape everything
- Use parameterized queries for all database interactions
- Store secrets in environment variables, never in source code
- Hash passwords with a strong algorithm (bcrypt, argon2)
- Apply the principle of least privilege to file uploads
- Disable debug mode before any deployment
- Use `shell=False` whenever calling subprocesses
- Leverage framework features (Jinja2 escaping, werkzeug utilities)

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Bandit v1.9.4 | Python static security analysis |
| Manual Review | Logic flaws, XSS, path traversal |
| curl + browser | Dynamic exploit verification |
| Python 3.12 + Flask 3.1 | Target application stack |

---

*CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review*  
*LBIEN Bilal | ENSA Fes | github.com/b1l4l-sec*
