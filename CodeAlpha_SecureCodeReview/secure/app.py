"""
SECURE Flask App — fixed version after security audit.
CodeAlpha Internship — Task 3: Secure Coding Review
Author: LBIEN Bilal
All vulnerabilities from the vulnerable version have been remediated.
"""

from flask import Flask, request, session, redirect, render_template_string
import sqlite3
import os
import subprocess
import secrets
import hashlib
import re
from werkzeug.utils import secure_filename
from datetime import timedelta

app = Flask(__name__)

# FIX 1: Secret key loaded from environment variable, never hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# FIX 2: Secure session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

UPLOAD_FOLDER = "secure_uploads/"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "csv"}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB max upload
ALLOWED_HOSTS = re.compile(r"^[a-zA-Z0-9.\-]+$")  # strict hostname pattern

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ── Shared CSS & layout ────────────────────────────────────────────────────────
BASE_STYLE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureApp [FIXED] — {{ title }}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
  :root {
    --green:   #00ff41;
    --dimgreen:#00c030;
    --red:     #ff2a2a;
    --yellow:  #ffd700;
    --blue:    #00bfff;
    --bg:      #0a0a0a;
    --panel:   #0a0f1a;
    --border:  #1a2a3a;
    --text:    #b0d0ff;
    --muted:   #2a4a6a;
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
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,191,255,0.012) 2px, rgba(0,191,255,0.012) 4px
    );
    pointer-events: none; z-index: 9999;
  }

  body::after {
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(0,191,255,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,191,255,0.025) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none; z-index: 0;
  }

  .wrapper { position: relative; z-index: 1; min-height: 100vh; display: flex; flex-direction: column; }

  .topbar {
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,191,255,0.03);
  }

  .topbar .logo {
    font-family: 'Orbitron', monospace;
    font-weight: 900; font-size: 1.1rem;
    color: var(--blue); letter-spacing: 3px;
    text-shadow: 0 0 20px var(--blue);
  }

  .topbar .status { font-size: 0.7rem; color: var(--muted); display: flex; gap: 24px; }
  .topbar .status span { color: var(--blue); }

  .dot {
    display: inline-block; width: 6px; height: 6px;
    background: var(--blue); border-radius: 50%;
    margin-right: 6px;
    animation: blink 1.2s infinite;
    box-shadow: 0 0 6px var(--blue);
  }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }

  .nav {
    display: flex; gap: 2px; padding: 0 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,0,0,0.4);
  }

  .nav a {
    padding: 10px 20px; color: var(--muted);
    text-decoration: none; font-size: 0.75rem;
    letter-spacing: 2px; text-transform: uppercase;
    border-bottom: 2px solid transparent; transition: all 0.2s;
  }

  .nav a:hover, .nav a.active {
    color: var(--blue); border-bottom-color: var(--blue);
    background: rgba(0,191,255,0.05);
  }

  .main {
    flex: 1; display: flex;
    align-items: center; justify-content: center;
    padding: 48px 32px;
  }

  .panel {
    background: var(--panel); border: 1px solid var(--border);
    padding: 40px 48px; width: 100%; max-width: 480px;
    position: relative; animation: fadeIn 0.4s ease;
  }

  .panel::before {
    content: ''; position: absolute;
    top: -1px; left: 20px; width: 60px; height: 2px;
    background: var(--blue); box-shadow: 0 0 12px var(--blue);
  }

  .panel-wide { max-width: 800px; }

  @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

  .panel-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.85rem; font-weight: 700;
    color: var(--blue); letter-spacing: 4px; text-transform: uppercase;
    margin-bottom: 32px; padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }

  .panel-title::before { content: '> '; color: var(--muted); }

  .field { margin-bottom: 20px; }

  label {
    display: block; font-size: 0.7rem; color: var(--muted);
    letter-spacing: 2px; text-transform: uppercase; margin-bottom: 8px;
  }

  input[type=text], input[type=password], input[type=file] {
    width: 100%; background: #05080f;
    border: 1px solid var(--border); color: var(--blue);
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9rem; padding: 10px 14px; outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  input[type=text]:focus, input[type=password]:focus {
    border-color: var(--blue); box-shadow: 0 0 12px rgba(0,191,255,0.15);
  }

  input[type=file] { cursor: pointer; padding: 8px; }

  .btn {
    display: inline-block; background: transparent;
    border: 1px solid var(--blue); color: var(--blue);
    font-family: 'Orbitron', monospace;
    font-size: 0.7rem; font-weight: 700;
    letter-spacing: 3px; text-transform: uppercase;
    padding: 12px 32px; cursor: pointer;
    transition: all 0.2s; width: 100%; margin-top: 8px;
  }

  .btn:hover {
    background: var(--blue); color: #000;
    box-shadow: 0 0 24px rgba(0,191,255,0.4);
  }

  .alert {
    padding: 10px 14px; font-size: 0.8rem;
    margin-bottom: 20px; border-left: 3px solid;
  }

  .alert-error   { border-color: var(--red);    color: var(--red);    background: rgba(255,42,42,0.05); }
  .alert-success { border-color: var(--green);  color: var(--green);  background: rgba(0,255,65,0.05); }
  .alert-info    { border-color: var(--blue);   color: var(--blue);   background: rgba(0,191,255,0.05); }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px; margin-bottom: 32px;
  }

  .card {
    border: 1px solid var(--border); padding: 24px;
    background: rgba(0,191,255,0.02);
    transition: border-color 0.2s, background 0.2s;
    text-decoration: none; display: block;
  }

  .card:hover { border-color: var(--blue); background: rgba(0,191,255,0.05); }
  .card-icon  { font-family: 'Orbitron', monospace; font-size: 1.4rem; margin-bottom: 12px; color: var(--blue); }
  .card-title { font-family: 'Orbitron', monospace; font-size: 0.7rem; font-weight: 700; letter-spacing: 2px; color: var(--blue); margin-bottom: 6px; }
  .card-desc  { font-size: 0.72rem; color: var(--muted); line-height: 1.6; }

  .terminal {
    background: #000; border: 1px solid var(--border);
    padding: 20px; font-size: 0.8rem; color: #00bfff;
    white-space: pre-wrap; word-break: break-all;
    max-height: 400px; overflow-y: auto;
    margin-top: 16px; line-height: 1.6;
  }

  .fix-badge {
    display: inline-block;
    background: rgba(0,255,65,0.1);
    border: 1px solid var(--green);
    color: var(--green); font-size: 0.6rem;
    padding: 2px 8px; letter-spacing: 1px;
    margin-left: 8px; vertical-align: middle;
    font-family: 'Share Tech Mono', monospace;
  }

  .fixes-list {
    font-size: 0.72rem; color: var(--muted);
    line-height: 2; margin-top: 20px;
    border-top: 1px solid var(--border); padding-top: 16px;
  }

  .fixes-list span { color: var(--green); margin-right: 6px; }

  .footer {
    padding: 12px 32px; border-top: 1px solid var(--border);
    font-size: 0.65rem; color: var(--muted);
    display: flex; justify-content: space-between;
  }
</style>
</head>
<body>
<div class="wrapper">
  <div class="topbar">
    <div class="logo"><span class="dot"></span>SECUREAPP v2.0 [PATCHED]</div>
    <div class="status">
      <span>SYS: <span>ONLINE</span></span>
      <span>SEC: <span>HARDENED</span></span>
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
    <span>CodeAlpha Cybersecurity Internship &mdash; Task 3: Secure Coding Review [FIXED]</span>
    <span>LBIEN Bilal &nbsp;|&nbsp; github.com/b1l4l-sec</span>
  </div>
</div>
</body>
</html>
"""

# ── Helpers ────────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """FIX 3: Hash passwords with SHA-256 (use bcrypt in real production)."""
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename: str) -> bool:
    """FIX 4: Whitelist allowed extensions."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ── Database setup ─────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("secure_users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )""")
    # FIX 3: Store hashed passwords
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin')", (hash_password("admin123"),))
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'bilal', ?, 'user')",  (hash_password("password"),))
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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # FIX 5: Parameterized query — no SQL injection possible
        conn = sqlite3.connect("secure_users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                  (username, hash_password(password)))
        user = c.fetchone()
        conn.close()

        if user:
            session.permanent = True
            session["user"] = username
            session["role"] = user[3]
            return redirect("/dashboard")
        else:
            error = "Authentication failed — invalid credentials"

    page = BASE_STYLE + """
    <div class="panel">
      <div class="panel-title">Secure Login <span class="fix-badge">PATCHED</span></div>
      {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
      <div class="alert alert-info" style="font-size:0.7rem;margin-bottom:24px;">
        [+] Parameterized queries active. SQL injection not possible.
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
      <div class="fixes-list">
        <div><span>[FIX]</span> Parameterized SQL queries</div>
        <div><span>[FIX]</span> Passwords hashed with SHA-256</div>
        <div><span>[FIX]</span> Session cookie HttpOnly + SameSite</div>
        <div><span>[FIX]</span> Session expires after 30 minutes</div>
      </div>
    </div>
    """ + BASE_END
    return render_template_string(page, error=error, title="LOGIN")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    # FIX 6: Use Jinja2 template rendering — auto-escapes XSS
    page = BASE_STYLE + """
    <div class="panel panel-wide">
      <div class="panel-title">Dashboard <span class="fix-badge">XSS FIXED</span></div>
      <div class="alert alert-info" style="font-size:0.7rem;margin-bottom:24px;">
        [+] All output rendered via Jinja2 — HTML auto-escaped. XSS not possible.
      </div>
      <div style="margin-bottom:28px;font-size:0.9rem;color:var(--blue);">
        Welcome back, {{ session.user }}
      </div>
      <div class="cards">
        <a class="card" href="/upload">
          <div class="card-icon">[ F ]</div>
          <div class="card-title">File Upload</div>
          <div class="card-desc">Secure upload with extension whitelist, filename sanitization, and size limit.</div>
        </a>
        <a class="card" href="/ping">
          <div class="card-icon">[ N ]</div>
          <div class="card-title">Network Tool</div>
          <div class="card-desc">Ping tool using strict input validation — no shell injection possible.</div>
        </a>
      </div>
      <div class="fixes-list">
        <div><span>[FIX]</span> XSS: Jinja2 auto-escaping replaces f-string rendering</div>
        <div><span>[FIX]</span> Secret key loaded from environment variable</div>
        <div><span>[FIX]</span> Debug mode disabled</div>
        <div><span>[FIX]</span> App binds to localhost only</div>
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
        f = request.files.get("file")
        if not f or f.filename == "":
            msg = "[!] No file selected"
            msg_type = "error"
        elif not allowed_file(f.filename):
            msg = f"[!] File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
            msg_type = "error"
        else:
            # FIX 7: Sanitize filename — prevents path traversal
            filename = secure_filename(f.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            f.save(filepath)
            msg = f"[+] File uploaded securely: {filename}"
            msg_type = "success"

    page = BASE_STYLE + """
    <div class="panel">
      <div class="panel-title">Secure Upload <span class="fix-badge">PATH TRAVERSAL FIXED</span></div>
      <div class="alert alert-info" style="font-size:0.7rem;margin-bottom:24px;">
        [+] secure_filename() applied. Extension whitelist enforced. 2MB size limit active.
      </div>
      {% if msg %}<div class="alert alert-{{ msg_type }}">{{ msg }}</div>{% endif %}
      <form method="POST" enctype="multipart/form-data">
        <div class="field">
          <label>Select File (txt, pdf, png, jpg, csv only)</label>
          <input type="file" name="file">
        </div>
        <button class="btn" type="submit">Upload Securely</button>
      </form>
      <div class="fixes-list">
        <div><span>[FIX]</span> werkzeug.utils.secure_filename() sanitizes path</div>
        <div><span>[FIX]</span> Extension whitelist: txt, pdf, png, jpg, csv</div>
        <div><span>[FIX]</span> Max upload size: 2MB</div>
      </div>
    </div>
    """ + BASE_END
    return render_template_string(page, msg=msg, msg_type=msg_type, title="FILE UPLOAD")

@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "user" not in session:
        return redirect("/login")

    output = ""
    error = ""
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        # FIX 8: Strict hostname validation — no shell metacharacters allowed
        if not host or not ALLOWED_HOSTS.match(host):
            error = "[!] Invalid hostname. Only alphanumeric characters, dots, and hyphens allowed."
        else:
            # FIX 9: shell=False with argument list — no command injection
            result = subprocess.run(
                ["ping", "-c", "2", host],
                capture_output=True, text=True,
                timeout=10, shell=False
            )
            output = result.stdout + result.stderr

    page = BASE_STYLE + """
    <div class="panel panel-wide">
      <div class="panel-title">Secure Network Tool <span class="fix-badge">CMD INJECTION FIXED</span></div>
      <div class="alert alert-info" style="font-size:0.7rem;margin-bottom:24px;">
        [+] Input validated against strict regex. subprocess called with shell=False.
      </div>
      {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
      <form method="POST">
        <div class="field">
          <label>Target Host</label>
          <input type="text" name="host" placeholder="e.g. google.com">
        </div>
        <button class="btn" type="submit">Execute Ping</button>
      </form>
      {% if output %}
      <div class="terminal">{{ output }}</div>
      {% endif %}
      <div class="fixes-list">
        <div><span>[FIX]</span> Hostname validated with strict regex ^[a-zA-Z0-9.\-]+$</div>
        <div><span>[FIX]</span> subprocess.run() with shell=False and argument list</div>
        <div><span>[FIX]</span> 10 second timeout to prevent DoS</div>
      </div>
    </div>
    """ + BASE_END
    return render_template_string(page, output=output, error=error, title="NETWORK TOOL")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    init_db()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # FIX 10: Debug mode OFF, bind to localhost only
    app.run(host="127.0.0.1", port=5001, debug=False)
