<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Output Encoding Security Controls

Domain: OUTPUT (04)
STRIDE Category: T (Tampering), I (Information Disclosure)

## Overview

输出编码安全控制关注数据从应用程序输出到各种目标时的安全处理，防止注入攻击和信息泄露。

## Control ID Prefix: OUTPUT

---

## OUTPUT-01: Context-Aware Output Encoding

**Description**: 根据输出上下文选择正确的编码方式

**Implementation**:
```python
# HTML Context
from markupsafe import escape
safe_html = escape(user_input)  # &lt;script&gt; → &amp;lt;script&amp;gt;

# JavaScript Context
import json
safe_js = json.dumps(user_input)  # Properly escaped for JS string

# URL Context
from urllib.parse import quote
safe_url = quote(user_input, safe='')

# CSS Context - Allow-list approach
def safe_css_value(value):
    if re.match(r'^[a-zA-Z0-9#\-_\.]+$', value):
        return value
    raise ValueError("Invalid CSS value")
```

**Checklist**:
- [ ] HTML context uses HTML entity encoding
- [ ] JavaScript context uses JSON encoding
- [ ] URL context uses percent encoding
- [ ] CSS context uses allow-list validation
- [ ] Attribute values are always quoted

---

## OUTPUT-02: Template Engine Security

**Description**: 安全使用模板引擎，防止服务端模板注入 (SSTI)

**Implementation**:
```python
# Jinja2 - Enable autoescape (default in Flask)
from jinja2 import Environment, select_autoescape
env = Environment(
    autoescape=select_autoescape(['html', 'xml']),
    # Disable dangerous features
    extensions=[]  # No sandboxed extension
)

# Never render user input as template
# BAD: template.render(user_template)
# GOOD: template.render(user_data=sanitized_input)
```

```javascript
// Node.js - Avoid eval-like template features
// BAD: ejs.render(userInput)
// GOOD: ejs.render(template, { data: sanitizedInput })

// Use strict mode in Handlebars
const template = Handlebars.compile(source, { strict: true });
```

**Checklist**:
- [ ] Autoescape enabled by default
- [ ] User input never used as template source
- [ ] Sandbox mode enabled where available
- [ ] Template syntax characters escaped in user data

---

## OUTPUT-03: File Export Security

**Description**: 安全导出文件（PDF、Excel、CSV等），防止注入和信息泄露

**Implementation**:
```python
# CSV Export - Prevent formula injection
import csv

def safe_csv_value(value):
    """Prevent CSV formula injection"""
    if isinstance(value, str):
        # Prefix dangerous characters with single quote
        if value.startswith(('=', '+', '-', '@', '\t', '\r')):
            return "'" + value
    return value

def export_csv(data, filename):
    with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        for row in data:
            writer.writerow([safe_csv_value(cell) for cell in row])
```

```python
# PDF Export - Sanitize content
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from markupsafe import escape

def safe_pdf_paragraph(text):
    """Sanitize text for PDF output"""
    sanitized = escape(text)
    return Paragraph(str(sanitized), getSampleStyleSheet()['Normal'])
```

**Checklist**:
- [ ] CSV exports prefix formula characters
- [ ] Excel exports use proper cell formatting
- [ ] PDF content is HTML-escaped
- [ ] Filename sanitized (no path traversal)
- [ ] Content-Disposition header set correctly

---

## OUTPUT-04: API Response Security

**Description**: API响应的安全编码和头设置

**Implementation**:
```python
from flask import jsonify, make_response

def secure_json_response(data, status=200):
    """Create secure JSON response"""
    response = make_response(jsonify(data), status)

    # Security headers
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'

    # Prevent JSON hijacking (legacy browsers)
    # Response starts with )]}' which breaks direct script inclusion

    return response

# Sensitive data filtering
def filter_sensitive_fields(obj, sensitive_fields=['password', 'token', 'secret']):
    """Remove sensitive fields from response"""
    if isinstance(obj, dict):
        return {k: filter_sensitive_fields(v, sensitive_fields)
                for k, v in obj.items()
                if k.lower() not in sensitive_fields}
    elif isinstance(obj, list):
        return [filter_sensitive_fields(item, sensitive_fields) for item in obj]
    return obj
```

**Checklist**:
- [ ] Content-Type explicitly set
- [ ] X-Content-Type-Options: nosniff
- [ ] Sensitive fields filtered from responses
- [ ] Error responses don't leak internal details
- [ ] Pagination prevents data enumeration

---

## OUTPUT-05: Log Output Sanitization

**Description**: 日志输出的敏感数据脱敏

**Implementation**:
```python
import re
import logging

class SanitizingFormatter(logging.Formatter):
    """Formatter that sanitizes sensitive data"""

    PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'password=***REDACTED***'),
        (r'token["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'token=***REDACTED***'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'api_key=***REDACTED***'),
        (r'\b\d{16}\b', '***CARD***'),  # Credit card
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***EMAIL***'),
    ]

    def format(self, record):
        message = super().format(record)
        for pattern, replacement in self.PATTERNS:
            message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)
        return message

# Usage
handler = logging.StreamHandler()
handler.setFormatter(SanitizingFormatter('%(asctime)s - %(message)s'))
logger = logging.getLogger()
logger.addHandler(handler)
```

**Checklist**:
- [ ] Passwords never logged
- [ ] Tokens and API keys redacted
- [ ] PII (email, phone, SSN) masked
- [ ] Credit card numbers masked
- [ ] Stack traces filtered in production

---

## OUTPUT-06: Error Message Security

**Description**: 错误消息的安全输出，防止信息泄露

**Implementation**:
```python
from flask import jsonify
import logging

logger = logging.getLogger(__name__)

class SecureErrorHandler:
    """Handle errors without leaking sensitive information"""

    # Generic messages for external users
    ERROR_MESSAGES = {
        400: "Invalid request",
        401: "Authentication required",
        403: "Access denied",
        404: "Resource not found",
        500: "Internal server error",
    }

    @staticmethod
    def handle_error(error, status_code=500):
        # Log full details internally
        logger.error(f"Error: {error}", exc_info=True)

        # Return generic message externally
        return jsonify({
            "error": SecureErrorHandler.ERROR_MESSAGES.get(
                status_code, "An error occurred"
            ),
            "status": status_code
        }), status_code

# Usage
@app.errorhandler(Exception)
def handle_exception(e):
    return SecureErrorHandler.handle_error(e, 500)
```

**Checklist**:
- [ ] Stack traces hidden from users
- [ ] Database errors return generic messages
- [ ] File paths not exposed
- [ ] Internal IPs/hostnames not leaked
- [ ] Detailed errors logged server-side only

---

## STRIDE Mapping

| Control | Mitigates | Description |
|---------|-----------|-------------|
| OUTPUT-01 | T, I | Context-aware encoding prevents injection |
| OUTPUT-02 | T | Template security prevents SSTI |
| OUTPUT-03 | T, I | File export security prevents injection and leaks |
| OUTPUT-04 | I | API response security prevents data exposure |
| OUTPUT-05 | I | Log sanitization prevents credential leaks |
| OUTPUT-06 | I | Error handling prevents info disclosure |

---

## Related References

- reference-set-04-output-encoding.md (when available)
- reference-set-03-input-validation.md (related INPUT controls)
- reference-set-07-error-handling.md (ERROR domain)
