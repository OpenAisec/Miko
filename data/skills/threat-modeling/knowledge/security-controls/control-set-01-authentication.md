<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

---
description: Authentication, MFA, and Session Management (passwords, MFA, OAuth/OIDC, SAML, sessions, cookies)
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

rule_id: control-set-01-authentication

## Authentication, MFA & Session Management

Build a resilient, user-friendly authentication system that resists credential attacks, protects secrets, supports strong MFA, and implements secure session handling.

---

## Part 1: Authentication & MFA

### Account Identifiers and UX
- Use non-public, random, and unique internal user identifiers. Allow login via verified email or username.
- Always return generic error messages (e.g., "Invalid username or password"). Keep timing consistent to prevent account enumeration.
- Support password managers: `<input type="password">`, allow paste, no JS blocks.

### Password Policy
- Accept passphrases and full Unicode; minimum 8 characters; avoid composition rules. Set only a reasonable maximum length (64+).
- Check new passwords against breach corpora (e.g., k‑anonymity APIs); reject breached/common passwords.

### Password Storage (Hashing)
- Hash, do not encrypt. Use slow, memory‑hard algorithms with unique per‑user salts and constant‑time comparison.
- Preferred order and parameters (tune to your hardware; target <1s on server):
  - Argon2id: m=19–46 MiB, t=2–1, p=1 (or equivalent security trade‑offs)
  - scrypt: N=2^17, r=8, p=1 (or equivalent)
  - bcrypt (legacy only): cost ≥10, be aware of 72‑byte input limit
  - PBKDF2 (FIPS): PBKDF2‑HMAC‑SHA‑256 ≥600k, or SHA‑1 ≥1.3M
- Optional pepper: store outside DB (KMS/HSM); if used, apply via HMAC or pre‑hashing. Plan for user resets if pepper rotates.
- Unicode and null bytes must be supported end‑to‑end by the library.

### Authentication Flow Hardening
- Enforce TLS for all auth endpoints and token transport; enable HSTS.
- Implement rate limits per IP, account, and globally; add proof‑of‑work or CAPTCHA only as last resort.
- Lockouts/throttling: progressive backoff; avoid permanent lockout via resets/alerts.
- Uniform responses and code paths to reduce oracle/timing signals.

### Multi‑Factor Authentication (MFA)
- Adopt phishing‑resistant factors by default for sensitive accounts: passkeys/WebAuthn (FIDO2) or hardware U2F.
- Acceptable: TOTP (app‑based), smart cards with PIN. Avoid for sensitive use: SMS/voice, email codes; never rely on security questions.
- Require MFA for: login, password/email changes, disabling MFA, privilege elevation, high‑value transactions, new devices/locations.
- Risk‑based MFA signals: new device, geo‑velocity, IP reputation, unusual time, breached credentials.
- MFA recovery: provide single‑use backup codes, encourage multiple factors, and require strong identity verification for resets.
- Handle failed MFA: offer alternative enrolled methods, notify users of failures, and log context (no secrets).

### Federation and Protocols (OAuth 2.0 / OIDC / SAML)
- Use standard protocols only; do not build your own.
- OAuth 2.0/OIDC:
  - Prefer Authorization Code with PKCE for public/native apps; avoid Implicit and ROPC.
  - Validate state and nonce; use exact redirect URI matching; prevent open redirects.
  - Constrain tokens to audience/scope; use DPoP or mTLS for sender‑constraining when possible.
  - Rotate refresh tokens; revoke on logout or risk signals.
- SAML:
  - TLS 1.2+; sign responses/assertions; encrypt sensitive assertions.
  - Validate issuers, InResponseTo, timestamps (NotBefore/NotOnOrAfter), Recipient; verify against trusted keys.
  - Prevent XML signature wrapping with strict schema validation and hardened XPath selection.
  - Keep response lifetimes short; prefer SP‑initiated flows; validate RelayState; implement replay detection.

### Tokens (JWT and Opaque)
- Prefer opaque server‑managed tokens for simplicity and revocation. If using JWTs:
  - Explicitly pin algorithms; reject "none"; validate iss/aud/exp/iat/nbf; use short lifetimes and rotation.
  - Store secrets/keys securely (KMS/HSM). Use strong HMAC secrets or asymmetric keys; never hardcode.
  - Consider binding tokens to a client context (e.g., fingerprint hash in cookie) to reduce replay.
  - Implement denylist/allowlist for revocation on logout and critical events.

### Recovery and Reset
- Return the same response for existing and non‑existing accounts (no enumeration). Normalize timing.
- Generate 32+ byte, CSPRNG tokens; single‑use; store as hashes; short expiry.
- Use HTTPS reset links to pinned, trusted domains; add referrer policy (no‑referrer) on UI.
- After reset: require re‑authentication, rotate sessions, and do not auto‑login.
- Never lock accounts due to reset attempts; rate‑limit and monitor instead.

### Administrative and Internal Accounts
- Separate admin login from public forms; enforce stronger MFA, device posture checks, IP allowlists, and step‑up auth.
- Use distinct session contexts and stricter timeouts for admin operations.

---

## Part 2: Session Management & Cookies

### Session ID Generation and Properties
- Generate session IDs with a CSPRNG; ≥64 bits of entropy (prefer 128+). Opaque, unguessable, and free of meaning.
- Use generic cookie names (e.g., `id`) rather than framework defaults. Reject any incoming ID not created by the server.
- Store all session data server-side; never embed PII or privileges in the token. If sensitive, encrypt server-side session store at rest.

### Cookie Security Configuration
- Set `Secure`, `HttpOnly`, `SameSite=Strict` (or `Lax` if necessary for flows) on session cookies.
- Scope cookies narrowly with `Path` and `Domain`. Avoid cross-subdomain exposure.
- Prefer non-persistent session cookies (no Expires/Max-Age). Require full HTTPS; enable HSTS site-wide.

Example header:
```
Set-Cookie: id=<opaque>; Secure; HttpOnly; SameSite=Strict; Path=/
```

### Session Lifecycle and Rotation
- Create sessions only server-side; treat provided IDs as untrusted input.
- Regenerate session ID on authentication, password changes, and any privilege elevation. Invalidate the prior ID.
- Use distinct pre‑auth and post‑auth cookie names if framework patterns require it.

### Expiration and Logout
- Idle timeout: 2–5 minutes for high-value, 15–30 minutes for lower risk. Absolute timeout: 4–8 hours.
- Enforce timeouts server-side. Provide a visible logout button that fully invalidates the server session and clears the cookie client-side.

### Transport and Caching
- Enforce HTTPS for the entire session journey. Never mix HTTP/HTTPS in one session.
- Send `Cache-Control: no-store` on responses containing session identifiers or sensitive data.

### Cookie Theft Detection and Response
- Fingerprint session context server-side at establishment (IP, User-Agent, Accept-Language, relevant `sec-ch-ua` where available).
- Compare incoming requests to the stored fingerprint, allowing for benign drift (e.g., subnet changes, UA updates).
- Risk-based responses:
  - High risk: require re-authentication; rotate session ID.
  - Medium risk: step-up verification (challenge); rotate session ID.
  - Low risk: log suspicious activity.
- Always regenerate the session ID when potential hijacking is detected.

### Client-Side Storage
- Do not store session tokens in `localStorage`/`sessionStorage` due to XSS risk. Prefer HttpOnly cookies for transport.
- If client-side storage is unavoidable for non-session secrets, isolate via Web Workers and never expose in page context.

### Framework and Multi-Cookie Scenarios
- Prefer built-in session frameworks; keep them updated and hardened.
- Validate relationships when multiple cookies participate in session state; avoid same cookie names across paths/domains.

---

## Monitoring and Telemetry

- Log auth events (failures/successes, MFA enroll/verify, resets, lockouts) with stable fields and correlation IDs; never log secrets or raw tokens.
- Log session lifecycle events (creation, rotation, termination) using salted hashes of the session ID, not raw values.
- Detect credential stuffing: high failure rates, many IPs/agents, impossible travel. Notify users of new device logins.
- Monitor for brute force of session IDs and anomalous concurrent usage.

---

## Implementation Checklist

### Authentication
- [ ] Passwords: Argon2id (preferred) with per‑user salt, constant‑time verify; breached password checks on change/set.
- [ ] MFA: WebAuthn/passkeys or hardware tokens for high‑risk; TOTP as fallback; secure recovery with backup codes.
- [ ] Federation: Authorization Code + PKCE; strict redirect URI validation; audience/scope enforced; token rotation.
- [ ] Tokens: short‑lived, sender‑constrained where possible; revocation implemented; secrets in KMS/HSM.
- [ ] Recovery: single‑use, hashed, time‑boxed tokens; consistent responses; re‑auth required after reset; sessions rotated.
- [ ] Abuse: rate limits, throttling, and anomaly detection on auth endpoints; uniform error handling.
- [ ] Admin: isolated flows with stricter policies and device checks.

### Session Management
- [ ] CSPRNG session IDs (≥64 bits entropy), opaque and server-issued only.
- [ ] Cookie flags: `Secure`, `HttpOnly`, `SameSite` set; tight domain/path.
- [ ] HTTPS-only with HSTS; no mixed content.
- [ ] Regenerate IDs on auth and privilege changes; invalidate old IDs.
- [ ] Idle and absolute timeouts enforced server-side; full logout implemented.
- [ ] `Cache-Control: no-store` for sensitive responses.
- [ ] Server-side fingerprinting and risk-based responses to anomalies.
- [ ] No client storage of session tokens; framework defaults hardened.

---

## Test Plan

- Unit/integration tests for login, MFA enroll/verify, resets, and lockouts with uniform errors.
- Protocol tests: PKCE, state/nonce, redirect URI validation, token audience/scope.
- Dynamic tests for credential stuffing resistance and token replay; validate revocation after logout and role change.
- Session ID entropy validation; cookie attribute verification.
- Session fixation and hijacking scenario tests.

---

## OWASP References

- Authentication_Cheat_Sheet.md
- Password_Storage_Cheat_Sheet.md
- Multifactor_Authentication_Cheat_Sheet.md
- Session_Management_Cheat_Sheet.md
- Cookie_Theft_Mitigation_Cheat_Sheet.md
- Forgot_Password_Cheat_Sheet.md
- OAuth2_Cheat_Sheet.md
- SAML_Security_Cheat_Sheet.md
- JSON_Web_Token_for_Java_Cheat_Sheet.md
