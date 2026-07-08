# Security Audit Report: case3_api.py

**File:** `D:\code\agent\miko\miko\miko\data\skills\code-audit\evals\files\case3_api.py`

**Date:** 2026-06-18

**Severity Legend:**

| Level | Description |
|-------|-------------|
| Critical | Immediate risk of full system compromise, data exfiltration, or remote code execution |
| High | Direct path to significant data breach, authentication bypass, or privilege escalation |
| Medium | Weakness that degrades security posture or enables attacks under certain conditions |
| Low | Best-practice violation with limited direct attack surface |
| Info | Notable observation without immediate risk |

---

## Executive Summary

This Python module contains **6 vulnerabilities**: 2 Critical, 2 High, 1 Medium, and 1 Low. The most severe issues are **remote code execution via `exec()`** and **hardcoded credentials in source code**. An attacker who controls the URL passed to `download_and_import()` gains arbitrary code execution on the server. The hardcoded JWT bearer token exposes internal API authentication to anyone with read access to the source code (developers, contractors, or anyone who acquires the repository).

---

## Findings

### Finding 1: Remote Code Execution via `exec()` (Critical)

**Severity:** Critical  
**CWE:** CWE-94 (Code Injection)  
**Location:** Lines 49-55, method `download_and_import`

```python
def download_and_import(self, url):
    """Download and dynamically import a Python module from URL."""
    resp = self.session.get(url)
    module_code = resp.text
    namespace = {}
    exec(module_code, namespace)
    return namespace
```

**Description:**  
This method downloads arbitrary text content from a user-supplied URL and immediately executes it as Python code via `exec()`. There is no validation of the URL scheme, the domain, the contents of the response, or any form of sandboxing. This is a textbook remote code execution (RCE) vulnerability.

**Attack scenario:**  
An attacker who can influence the `url` parameter (via any API endpoint, webhook, or configuration that feeds into this method) can point it to a URL hosting malicious Python code. When `exec()` runs, the attacker's code executes with the same privileges as the Python process, allowing them to:
- Read/write arbitrary files
- Exfiltrate environment variables and secrets
- Establish reverse shells
- Pivot to internal network resources
- Persist malware on the system

**Remediation:**
- Remove this method entirely. Downloading and executing remote code is fundamentally unsafe.
- If dynamic module loading is absolutely required, use `importlib` with a pre-approved whitelist of module names only (never from URLs).
- If plugin loading is the goal, implement a strict plugin system with sandboxing (e.g., subprocess with restricted permissions, or a sandboxed interpreter) and cryptographic signature verification of all loaded code.

---

### Finding 2: Hardcoded JWT Bearer Token (Critical)

**Severity:** Critical  
**CWE:** CWE-798 (Hardcoded Credentials)  
**Location:** Line 8

```python
INTERNAL_TOKEN = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret-token'
```

**Description:**  
A JWT bearer token is hardcoded as a module-level constant. This token is used to authenticate all API requests (line 15: `self.session.headers['Authorization'] = INTERNAL_TOKEN`). Anyone with read access to the source repository can extract this credential and impersonate the application against the internal API.

**Additional concerns:**
- The header portion `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` decodes to `{"alg":"HS256","typ":"JWT"}`. HS256 is a symmetric signing algorithm -- if the signing secret is also hardcoded or guessable, the token could be forged or manipulated.
- The payload appears to be `secret-token` rather than a valid Base64-encoded JWT payload segment, suggesting this may be a placeholder. However, the pattern is dangerous regardless of whether it is a placeholder or a real token.

**Remediation:**
- Never hardcode secrets in source code. Use environment variables (`os.environ.get("INTERNAL_TOKEN")`), a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault), or a secure configuration file excluded from version control (`.gitignore`).
- Rotate this token immediately since it has been exposed.
- For JWT specifically, prefer RS256 (asymmetric) over HS256 (symmetric) to avoid shared-secret risks.

---

### Finding 3: Server-Side Request Forgery (SSRF) (High)

**Severity:** High  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Location:** Lines 17-20 (`fetch_resource`), 22-25 (`forward_webhook`), 42-47 (`upload_file`), 49-55 (`download_and_import`)

```python
def fetch_resource(self, resource_url):
    """Fetch an external resource by URL."""
    resp = self.session.get(resource_url, timeout=10)
    ...
```

**Description:**  
Multiple methods accept a URL from the caller and make HTTP requests to it without any validation of the target. An attacker can supply URLs pointing to:
- Internal/private IP addresses (`127.0.0.1`, `10.x.x.x`, `192.168.x.x`, `169.254.x.x`)
- Cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/` on AWS) to steal IAM credentials
- Internal services that are not intended to be publicly accessible (databases, admin panels, configuration services)
- File-based URLs (`file:///etc/passwd`) to read local files

The `requests` library does support `file://` URLs, so `file:///etc/passwd` would return the contents of that file (on Linux). The `forward_webhook` method additionally sends attacker-controlled JSON payloads to arbitrary internal endpoints.

**Affected methods:**
1. `fetch_resource(resource_url)` -- GET request to arbitrary URL
2. `forward_webhook(target_url, payload)` -- POST request with attacker-controlled body to arbitrary URL
3. `upload_file(file_url, local_path)` -- GET request to arbitrary URL, saves content to disk
4. `download_and_import(url)` -- GET + `exec()` (also covered in Finding 1)

**Remediation:**
- Implement a strict URL allowlist (e.g., only `https://api.example.com/*`).
- If dynamic URLs are required, validate and sanitize all URLs:
  - Resolve the hostname to IP and reject private/internal IP ranges (RFC 1918, loopback, link-local, etc.).
  - Restrict to HTTPS only (`https://`).
  - Use a dedicated outbound proxy with network-level egress filtering.
- Perform DNS resolution through a secure resolver that blocks internal addresses.
- Never pass unsanitized user input directly to HTTP client methods.

---

### Finding 4: Sensitive Token Exposure in Logs/Print (High)

**Severity:** High  
**CWE:** CWE-532 (Insertion of Sensitive Information into Log Files)  
**Location:** Line 30

```python
print(f'Fetching user data from {url} with token {INTERNAL_TOKEN}')
```

**Description:**  
The `get_user_data` method logs the full `INTERNAL_TOKEN` (the JWT Bearer token) to stdout via `print()`. In production environments, stdout is typically captured by log aggregators, container runtimes (Docker, Kubernetes), CI/CD systems, and monitoring platforms. This means the authentication token is leaked into every log persistence layer.

**Impact:**
- The token appears in plaintext in application logs, systemd journal, Docker logs, Kubernetes pod logs.
- Anyone with access to log aggregation tools (Splunk, ELK, CloudWatch, Datadog) can extract and reuse the token.
- This is often a compliance violation (PCI-DSS, SOC 2, GDPR).

**Remediation:**
- Never log secrets, tokens, passwords, or API keys.
- Use a logging library with built-in secret redaction (e.g., Python `logging` with a custom filter).
- If you must log which token is in use, log only a truncated hash or token identifier:
  ```python
  token_id = hashlib.sha256(token.encode()).hexdigest()[:8]
  logger.info(f"Fetching user data from {url} with token id={token_id}")
  ```

---

### Finding 5: XML External Entity (XXE) Injection (Medium)

**Severity:** Medium  
**CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)  
**Location:** Lines 34-40, method `parse_xml_payload`

```python
def parse_xml_payload(self, xml_data):
    """Parse an XML payload and extract fields."""
    root = ET.fromstring(xml_data)
    ...
```

**Description:**  
The method uses Python's `xml.etree.ElementTree.fromstring()` to parse XML payloads. While `etree` is not vulnerable to XXE in Python 3.x (it does not process external entities by default), it is still a member of the `xml` module family known for security issues. More critically:

1. **Billion Laughs / XML Bomb attack:** `etree` is vulnerable to entity expansion denial-of-service attacks. A small XML payload can expand to consume gigabytes of memory:
   ```xml
   <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     ...
   ]>
   ```
2. **No input validation:** The parsed XML structure and field values are not validated. Any XML is accepted, and all tags/text are blindly inserted into the result dictionary. This can lead to unexpected behavior downstream.

**Remediation:**
- Use `defusedxml` library, which is specifically designed to safely parse untrusted XML:
  ```python
  from defusedxml.ElementTree import fromstring
  ```
- If `defusedxml` is unavailable, explicitly disable entity expansion:
  ```python
  parser = ET.XMLParser(resolve_entities=False)
  root = ET.fromstring(xml_data, parser=parser)
  ```
- Add input validation on the parsed XML: validate against a schema, enforce field name allowlists, and sanitize field values.

---

### Finding 6: Missing Input Validation on `user_id` (Low)

**Severity:** Low  
**CWE:** CWE-20 (Improper Input Validation)  
**Location:** Lines 27-32, method `get_user_data`

```python
def get_user_data(self, user_id):
    """Get user data by ID."""
    url = f'{self.base_url}/users/{user_id}'
    ...
```

**Description:**  
The `user_id` parameter is interpolated directly into a URL string without any validation or sanitization. While this does not pose an injection risk against the URL construction itself (Python f-strings do not introduce injection), it does allow:
- Path traversal within the API path: `user_id = "../admin/delete-all"` constructs `https://api.example.com/users/../admin/delete-all`
- Injection of special characters: `user_id = "123?admin=true"` or `user_id = "123#fragment"`
- Unexpected API calls if the ID is not restricted to expected formats

**Remediation:**
- Validate that `user_id` conforms to the expected format (e.g., UUID, integer, alphanumeric with defined length):
  ```python
  if not re.match(r'^[a-zA-Z0-9_-]+$', str(user_id)):
      raise ValueError("Invalid user_id format")
  ```
- URL-encode the `user_id` value to prevent path manipulation.
- Use `urllib.parse.quote()` to safely encode dynamic URL path segments.

---

## Summary Table

| # | Finding | Severity | CWE | Line(s) |
|---|---------|----------|-----|---------|
| 1 | Remote Code Execution via `exec()` | Critical | CWE-94 | 49-55 |
| 2 | Hardcoded JWT Bearer Token | Critical | CWE-798 | 8 |
| 3 | Server-Side Request Forgery (SSRF) | High | CWE-918 | 17-55 |
| 4 | Sensitive Token Leaked via `print()` | High | CWE-532 | 30 |
| 5 | XML External Entity / Billion Laughs | Medium | CWE-611 | 34-40 |
| 6 | Missing `user_id` Validation | Low | CWE-20 | 27-32 |

---

## Overall Risk Assessment

**Risk Level: Critical**

This module has fundamental security flaws that would allow an attacker to:
1. Execute arbitrary code on the server (RCE via `exec()`)
2. Authenticate to internal services (hardcoded token)
3. Probe and attack internal network infrastructure (SSRF)
4. Steal credentials from log files and monitoring systems (token in logs)

The code should not be deployed to any production or staging environment in its current state. A comprehensive remediation plan addressing all findings is required before any further use.
