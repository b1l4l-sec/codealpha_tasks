"""
VULNERABLE Flask App — for educational audit purposes only.
CodeAlpha Internship — Task 3: Secure Coding Review
Author: LBIEN Bilal
DO NOT deploy this in production.
"""

from flask import Flask, request, session, redirect, render_template_string
import sqlite3
import os
import subprocess

app = Flask(__name__)
app.secret_key = "admin123"  # VULN 1: Hardcoded weak secret key

UPLOAD_FOLDER = "uploads/"

# ── Shared CSS & layout ────────────────────────────────────────────────────────
BASE_STYLE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureApp — {{ title }}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
  :root {
    --green:   #00ff41;
    --dimgreen:#00c030;
    --red:     #ff2a2a;
    --yellow:  #ffd700;
    --bg:      #0a0a0a;
    --panel:   #0f1a0f;
    --border:  #1a3a1a;
    --text:    #b0ffb0;
    --muted:   #3a5a3a;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    min-height: 100vh;
    overflow-x: hidden;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,255,65,0.015) 2px, rgba(0,255,65,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,255,65,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,65,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .wrapper {
    position: relative; z-index: 1;
    min-height: 100vh;
    display: flex; flex-direction: column;
  }

  .topbar {
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,255,65,0.03);
  }

  .topbar .logo {
    font-family: 'Orbitron', monospace;
    font-weight: 900; font-size: 1.1rem;
    color: var(--green); letter-spacing: 3px;
    text-shadow: 0 0 20px var(--green);
  }

  .topbar .status { font-size: 0.7rem; color: var(--muted); display: flex; gap: 24px; }
  .topbar .status span { color: var(--dimgreen); }

  .dot {
    display: inline-block; width: 6px; height: 6px;
    background: var(--green); border-radius: 50%;
    margin-right: 6px;
    animation: blink 1.2s infinite;
    box-shadow: 0 0 6px var(--green);
  }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }

  .nav {
    display: flex; gap: 2px;
    padding: 0 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,0,0,0.4);
  }

  .nav a {
    padding: 10px 20px;
    color: var(--muted); text-decoration: none;
    font-size: 0.75rem; letter-spacing: 2px; text-transform: uppercase;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
  }

  .nav a:hover, .nav a.active {
    color: var(--green); border-bottom-color: var(--green);
    background: rgba(0,255,65,0.05);
  }

  .main {
    flex: 1; display: flex;
    align-items: center; justify-content: center;
    padding: 48px 32px;
  }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 40px 48px;
    width: 100%; max-width: 480px;
    position: relative;
    animation: fadeIn 0.4s ease;
  }

  .panel::before {
    content: '';
    position: absolute;
    top: -1px; left: 20px;
    width: 60px; height: 2px;
    background: var(--green);
    box-shadow: 0 0 12px var(--green);
  }

  .panel-wide { max-width: 800px; }

  @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

  .panel-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.85rem; font-weight: 700;
    color: var(--green); letter-spacing: 4px; text-transform: uppercase;
    margin-bottom: 32px; padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }

  .panel-title::before { content: '> '; color: var(--muted); }

  .field { margin-bottom: 20px; }

  label {
    display: block; font-size: 0.7rem;
    color: var(--muted); letter-spacing: 2px; text-transform: uppercase;
    margin-bottom: 8px;
  }

  input[type=text], input[type=password], input[type=file] {
    width: 100%;
    background: #050f05;
    border: 1px solid var(--border);
    color: var(--green);
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9rem;
    padding: 10px 14px;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  input[type=text]:focus, input[type=password]:focus {
    border-color: var(--green);
    box-shadow: 0 0 12px rgba(0,255,65,0.15);
  }

  input[type=file] { cursor: pointer; padding: 8px; }

  .btn {
    display: inline-block;
    background: transparent;
    border: 1px solid var(--green);
    color: var(--green);
    font-family: 'Orbitron', monospace;
    font-size: 0.7rem; font-weight: 700;
    letter-spacing: 3px; text-transform: uppercase;
    padding: 12px 32px;
    cursor: pointer;
    transition: all 0.2s;
    width: 100%; margin-top: 8px;
  }

  .btn:hover {
    background: var(--green); color: #000;
    box-shadow: 0 0 24px rgba(0,255,65,0.4);
  }

  .alert {
    padding: 10px 14px; font-size: 0.8rem;
    margin-bottom: 20px; border-left: 3px solid;
  }

  .alert-error  { border-color: var(--red);    color: var(--red);    background: rgba(255,42,42,0.05); }
  .alert-success{ border-color: var(--green);  color: var(--green);  background: rgba(0,255,65,0.05); }
  .alert-warn   { border-color: var(--yellow); color: var(--yellow); background: rgba(255,215,0,0.05); }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px; margin-bottom: 32px;
  }

  .card {
    border: 1px solid var(--border);
    padding: 24px;
    background: rgba(0,255,65,0.02);
    transition: border-color 0.2s, background 0.2s;
    text-decoration: none; display: block;
  }

  .card:hover { border-color: var(--green); background: rgba(0,255,65,0.05); }

  .card-icon { font-size: 1.4rem; margin-bottom: 12px; font-family: 'Orbitron', monospace; color: var(--green); }
  .card-title { font-family: 'Orbitron', monospace; font-size: 0.7rem; font-weight: 700; letter-spacing: 2px; color: var(--green); margin-bottom: 6px; }
  .card-desc  { font-size: 0.72rem; color: var(--muted); line-height: 1.6; }

  .terminal {
    background: #000;
    border: 1px solid var(--border);
    padding: 20px; font-size: 0.8rem;
    color: var(--dimgreen);
    white-space: pre-wrap; word-break: break-all;
    max-height: 400px; overflow-y: auto;
    margin-top: 16px; line-height: 1.6;
  }

  .terminal::-webkit-scrollbar { width: 4px; }
  .terminal::-webkit-scrollbar-track { background: #000; }
  .terminal::-webkit-scrollbar-thumb { background: var(--border); }

  .tag-vuln {
    display: inline-block;
    background: rgba(255,42,42,0.1);
    border: 1px solid var(--red);
    color: var(--red); font-size: 0.6rem;
    padding: 2px 8px; letter-spacing: 1px;
    margin-left: 8px; vertical-align: middle;
    font-family: 'Share Tech Mono', monospace;
  }

  .footer {
    padding: 12px 32px;
    border-top: 1px solid var(--border);
    font-size: 0.65rem; color: var(--muted);
    display: flex; justify-content: space-between;
  }
</style>
</head>
<body>
<div class="wrapper">
  <div class="topbar">
    <div class="logo"><span class="dot"></span>SECUREAPP v1.0</div>
    <div class="status">
      <span>SYS: <span>ONLINE</span></span>
      <span>ENV: <span>PRODUCTION</span></span>
      {% if session.user %}<span>USER: <span>{{ session.user|upper }}</span></span>{% endif %}
    </div>
  </div>
  {% if session.user %}
  <div class="nav">
    <a href="/dashboard" {% if title=='DASHBOARD' %}class="active"{% endif %}>Dashboard</a>
    <a href="/upload"    {% if title=='FILE UPLOAD' %}class="active"{% endif %}>Upload</a>
    <a href="/ping"      {% if title=='NETWORK TOOL' %}class="active"{% endif %}>Network</a>
    <a href="/logout">Logout</a>
  </div>
  {% endif %}
  <div class="main">
"""

BASE_END = """
  </div>
  <div class="footer">
    <span>CodeAlpha Cybersecurity Internship &mdash; Task 3: Secure Coding Review</span>
    <span>LBIEN Bilal &nbsp;|&nbsp; github.com/b1l4l-sec</span>
  </div>
</div>
</body>
</html>
"""

# ── Database setup ─────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")  # VULN: Plaintext password
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'bilal', 'password', 'user')")
    conn.commit()
    conn.close()

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # VULN: SQL Injection — raw string concatenation
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()
        if user:
            session["user"] = username  # VULN: No session security flags
            return redirect("/dashboard")
        else:
            error = "Authentication failed — invalid credentials"

    page = BASE_STYLE + """
    <div class="panel">
      <div class="panel-title">System Login <span class="tag-vuln">SQL INJECTION</span></div>
      {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
      <div class="alert alert-warn" style="font-size:0.7rem;margin-bottom:24px;">
        [!] SQL Injection: use &nbsp;<strong>' OR '1'='1' --</strong>&nbsp; as username
      </div>
      <form method="POST">
        <div class="field">
          <label>Username</label>
          <input type="text" name="username" placeholder="enter username" autocomplete="off">
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" name="password" placeholder="enter password">
        </div>
        <button class="btn" type="submit">Authenticate</button>
      </form>
      <div style="margin-top:20px;font-size:0.7rem;color:var(--muted);">
        Default &rarr; admin / admin123
      </div>
    </div>
    """ + BASE_END
    return render_template_string(page, error=error, title="LOGIN")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    name = request.args.get("name", session["user"])
    # VULN: XSS — unescaped f-string directly in HTML
    welcome = f"Welcome back, {name}"
    page = BASE_STYLE + """
    <div class="panel panel-wide">
      <div class="panel-title">Dashboard <span class="tag-vuln">XSS</span></div>
      <div class="alert alert-warn" style="font-size:0.7rem;margin-bottom:24px;">
        [!] XSS: visit /dashboard?name=&lt;script&gt;alert('XSS')&lt;/script&gt;
      </div>
      <div style="margin-bottom:28px;font-size:0.9rem;color:var(--green);">""" + welcome + """</div>
      <div class="cards">
        <a class="card" href="/upload">
          <div class="card-icon">[ F ]</div>
          <div class="card-title">File Upload</div>
          <div class="card-desc">Upload files to the server. No filename sanitization or extension validation.</div>
        </a>
        <a class="card" href="/ping">
          <div class="card-icon">[ N ]</div>
          <div class="card-title">Network Tool</div>
          <div class="card-desc">Ping a remote host. Raw shell command execution — command injection present.</div>
        </a>
      </div>
      <div style="font-size:0.68rem;color:var(--muted);line-height:1.8;">
        Active vulnerabilities &rarr;
        SQL Injection &bull; XSS &bull; Command Injection &bull;
        Path Traversal &bull; Hardcoded Secret &bull; Plaintext Passwords &bull; Debug Mode ON
      </div>
    </div>
    """ + BASE_END
    return render_template_string(page, title="DASHBOARD")

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect("/login")
    msg = ""
    msg_type = ""
    if request.method == "POST":
        f = request.files["file"]
        # VULN: Path traversal — no sanitization
        filepath = os.path.join(UPLOAD_FOLDER, f.filename)
        f.save(filepath)
        msg = f"[+] File saved: {filepath}"
        msg_type = "success"
    page = BASE_STYLE + """
    <div class="panel">
      <div class="panel-title">File Upload <span class="tag-vuln">PATH TRAVERSAL</span></div>
      <div class="alert alert-warn" style="font-size:0.7rem;margin-bottom:24px;">
        [!] No filename sanitization. Try uploading a shell.php or use ../../../etc/ as path.
      </div>
      {% if msg %}<div class="alert alert-{{ msg_type }}">{{ msg }}</div>{% endif %}
      <form method="POST" enctype="multipart/form-data">
        <div class="field">
          <label>Select File</label>
          <input type="file" name="file">
        </div>
        <button class="btn" type="submit">Upload</button>
      </form>
    </div>
    """ + BASE_END
    return render_template_string(page, msg=msg, msg_type=msg_type, title="FILE UPLOAD")

@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "user" not in session:
        return redirect("/login")
    output = ""
    if request.method == "POST":
        host = request.form["host"]
        # VULN: Command injection
        output = subprocess.getoutput(f"ping -c 2 {host}")
    page = BASE_STYLE + """
    <div class="panel panel-wide">
      <div class="panel-title">Network Tool <span class="tag-vuln">CMD INJECTION</span></div>
      <div class="alert alert-warn" style="font-size:0.7rem;margin-bottom:24px;">
        [!] Command injection: try &nbsp;<strong>google.com; whoami</strong>&nbsp; or &nbsp;<strong>google.com; cat /etc/passwd</strong>
      </div>
      <form method="POST">
        <div class="field">
          <label>Target Host</label>
          <input type="text" name="host" placeholder="e.g. google.com or google.com; whoami">
        </div>
        <button class="btn" type="submit">Execute</button>
      </form>
      {% if output %}
      <div class="terminal">{{ output }}</div>
      {% endif %}
    </div>
    """ + BASE_END
    return render_template_string(page, output=output, title="NETWORK TOOL")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")

if __name__ == "__main__":
    init_db()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # VULN: Debug mode on + all interfaces exposed
    app.run(host="0.0.0.0", port=5000, debug=True)
