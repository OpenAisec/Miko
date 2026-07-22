<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

---
description: Error handling and information disclosure prevention (safe failures, error messages, stack traces)
languages:
- c
- go
- java
- javascript
- kotlin
- php
- python
- ruby
- swift
- typescript
alwaysApply: false
---

rule_id: control-set-08-error-handling

## Error Handling & Information Disclosure Prevention

Implement secure error handling that prevents information leakage while maintaining system integrity and enabling effective debugging.

---

## Core Principles

### Fail Secure
- When errors occur, default to the most secure state (deny access, close connection).
- Never assume "success" when an operation fails; treat unknown states as failures.
- Ensure partial failures don't leave the system in an insecure intermediate state.

### Defense in Depth
- Multiple layers of error handling: application, framework, infrastructure.
- Errors at one layer should not bypass security controls at other layers.
- Log errors at the appropriate layer for debugging without duplication.

---

## Error Message Design

### User-Facing Messages
- Return generic, non-technical messages to users (e.g., "An error occurred. Please try again.").
- Never expose internal details: database names, table structures, file paths, stack traces, SQL queries.
- Use consistent error message format across the application.
- Provide actionable guidance without revealing system internals.

**Good Examples:**
```
"Invalid username or password."
"Unable to process your request. Please try again later."
"Access denied."
```

**Bad Examples:**
```
"SQLException: Table 'users' not found in database 'prod_db'"
"NullPointerException at UserService.java:142"
"Error: /var/www/app/config/database.yml not readable"
```

### Internal/Developer Messages
- Log detailed error information for debugging (stack traces, context, variables).
- Include correlation IDs to link user-facing errors to detailed logs.
- Store logs securely with access controls; never expose via API or UI.

---

## Stack Trace Protection

### Production Environment
- Disable stack trace display in production; enable only in development.
- Configure web frameworks to use custom error pages.
- Remove debug endpoints and verbose error modes before deployment.

### Framework Configuration Examples

**Python/Flask:**
```python
app.config['DEBUG'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Error: {e}", exc_info=True)
    return {"error": "An unexpected error occurred"}, 500
```

**Node.js/Express:**
```javascript
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'An unexpected error occurred' });
});
```

**Java/Spring:**
```java
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception e) {
        log.error("Error occurred", e);
        return ResponseEntity.status(500)
            .body(new ErrorResponse("An unexpected error occurred"));
    }
}
```

---

## Error Categories and Handling

### Authentication Errors
- Use identical messages for invalid username vs. invalid password.
- Maintain consistent response times to prevent timing attacks.
- Log failed attempts with enough context for threat detection.

### Authorization Errors
- Return 403 Forbidden without revealing why access was denied.
- Don't disclose whether a resource exists when access is denied.
- Log authorization failures with user context.

### Validation Errors
- Provide specific field-level feedback without exposing validation logic.
- Sanitize error messages to prevent injection via error content.
- Rate-limit validation attempts to prevent enumeration.

### System Errors
- Catch and handle all exceptions at application boundaries.
- Use circuit breakers for downstream service failures.
- Implement graceful degradation when dependencies fail.

---

## Information Disclosure Prevention

### Sensitive Data in Errors
- Never include passwords, tokens, API keys, or secrets in error messages or logs.
- Mask or redact PII in logs (credit cards, SSNs, email addresses).
- Sanitize user input before including in error messages.

### System Information
- Remove server version headers (Server, X-Powered-By, X-AspNet-Version).
- Disable directory listing and default error pages.
- Use generic 404 pages that don't reveal application structure.

### Error Response Headers
```
# Remove revealing headers
X-Powered-By: (remove)
Server: (remove or set to generic value)

# Add security headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

---

## Logging and Monitoring

### What to Log
- Error timestamp, type, and severity level.
- Correlation ID linking to user request.
- User identifier (non-PII) if authenticated.
- Affected resource or operation.
- Stack trace (to secure logs only).

### What NOT to Log
- Passwords, tokens, session IDs (full).
- Credit card numbers, SSNs, PII.
- Detailed query parameters containing sensitive data.
- Encryption keys or secrets.

### Log Format
```json
{
    "timestamp": "2025-01-01T12:00:00Z",
    "level": "ERROR",
    "correlation_id": "abc-123-xyz",
    "user_id_hash": "sha256:...",
    "error_type": "DatabaseConnectionError",
    "message": "Failed to connect to primary database",
    "action": "failover_initiated"
}
```

---

## Recovery and Resilience

### Transaction Rollback
- Ensure database transactions are rolled back on error.
- Release locks and resources on failure.
- Return system to consistent state.

### Retry Logic
- Implement exponential backoff for transient errors.
- Set maximum retry limits to prevent infinite loops.
- Log retry attempts for monitoring.

### Circuit Breaker Pattern
- Open circuit after threshold of failures.
- Allow periodic probes to detect recovery.
- Fail fast when circuit is open.

---

## Implementation Checklist

### Error Messages
- [ ] Generic user-facing error messages (no technical details).
- [ ] Detailed logging for developers (secure storage).
- [ ] Correlation IDs linking user errors to logs.
- [ ] Consistent error format across application.

### Stack Traces
- [ ] Disabled in production environment.
- [ ] Custom error pages configured.
- [ ] Debug modes disabled before deployment.

### Information Disclosure
- [ ] Sensitive data excluded from errors and logs.
- [ ] Server version headers removed.
- [ ] Directory listing disabled.
- [ ] 404 pages don't reveal structure.

### Security Headers
- [ ] X-Content-Type-Options: nosniff
- [ ] X-Frame-Options configured.
- [ ] Revealing headers removed.

### Resilience
- [ ] Transactions rolled back on error.
- [ ] Resources released on failure.
- [ ] Circuit breakers for external services.
- [ ] Retry logic with backoff.

---

## Test Plan

### Unit Tests
- Verify generic error messages for each error type.
- Confirm sensitive data not in error responses.
- Test correlation ID generation and propagation.

### Integration Tests
- Verify custom error pages in production mode.
- Test error handling at API boundaries.
- Confirm transaction rollback on failure.

### Security Tests
- Attempt to trigger verbose error messages.
- Check for information disclosure in 404/500 pages.
- Verify stack traces not exposed.
- Test error-based enumeration resistance.

---

## OWASP References

- Error_Handling_Cheat_Sheet.md
- Logging_Cheat_Sheet.md
- XS_Leaks_Cheat_Sheet.md
