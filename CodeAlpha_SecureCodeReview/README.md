# CodeAlpha Secure Coding Review — Task 3

CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review
Author: LBIEN Bilal | github.com/b1l4l-sec

---

## Screenshots

### Vulnerable App — SQL Injection Active
![Vulnerable App](secureapp%20review.png)

### Secure App — Patched Version
![Secure App Patched](secureapp%20patched.png)

### Bandit Static Analysis Results
![Bandit Results](bandit%20results.png)

---

## Overview

A deliberately vulnerable Python Flask web application was built, audited using Bandit static analysis and manual code review, then fully remediated in a secure version. Every vulnerability is documented with exploit proof and fix.

---

## Vulnerabilities Found & Fixed

| # | Vulnerability | Severity | OWASP | Status |
|---|--------------|----------|-------|--------|
| 1 | SQL Injection | HIGH | A03 | Fixed |
| 2 | Command Injection | HIGH | A03 | Fixed |
| 3 | Cross-Site Scripting (XSS) | MEDIUM | A03 | Fixed |
| 4 | Hardcoded Secret Key | MEDIUM | A02 | Fixed |
| 5 | Path Traversal (File Upload) | MEDIUM | A01 | Fixed |
| 6 | Plaintext Password Storage | LOW | A02 | Fixed |
| 7 | Debug Mode + Open Bind | HIGH | A05 | Fixed |

---

## Project Structure

    CodeAlpha_SecureCodeReview/
    |-- vulnerable/
    |   |-- app.py          # Intentionally vulnerable Flask app (7 vulns)
    |   |-- uploads/        # Unsanitized upload directory
    |-- secure/
    |   |-- app.py          # Fully remediated secure version
    |   |-- secure_uploads/ # Sanitized upload directory
    |-- AUDIT_REPORT.md     # Full audit report with exploits and fixes
    |-- audit_report.txt    # Bandit raw output
    |-- README.md

---

## Running the Vulnerable App

    cd vulnerable
    python3 app.py
    # Visit http://127.0.0.1:5000/login

    # SQL Injection: username = ' OR '1'='1' --  | password = anything
    # XSS: /dashboard?name=<script>alert('XSS')</script>
    # Command Injection: ping tool -> google.com; whoami

---

## Running the Secure App

    cd secure
    export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    python3 app.py
    # Visit http://127.0.0.1:5001/login

---

## Audit Tool

    pip3 install bandit --break-system-packages
    bandit -r vulnerable/app.py -f txt -o audit_report.txt
    cat audit_report.txt

---

## Legal Notice

This project is developed strictly for educational purposes as part of the CodeAlpha Cybersecurity Internship.
The vulnerable application must never be deployed on a public or production network.

---

*CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review*
*LBIEN Bilal | ENSA Fes | github.com/b1l4l-sec*
