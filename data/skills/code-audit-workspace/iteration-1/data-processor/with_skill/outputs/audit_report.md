# 安全审计报告

## 审计摘要
- **审计范围**：D:\code\agent\miko\miko\miko\data\skills\code-audit\evals\files\case2_processor.py
- **审计时间**：2026-06-18
- **文件数量**：1
- **发现问题**：9（Critical: 3, High: 2, Medium: 3, Low: 1）

---

## 发现清单

### [Critical] 硬编码密钥 — case2_processor.py:14

**描述**：API Token 以明文方式硬编码在源代码中。
**代码**：
```python
API_TOKEN = 'sk-proj-abc123def456ghi789jkl'
```
**风险**：任何能访问源码的人（开发者、运维、代码仓库访客）都可以直接获取该 Token。如果代码被提交到 Git 仓库，即使后续删除，该 Token 也会永远存在于 Git 历史记录中。攻击者获取此 Token 后可冒充合法服务发起 API 请求。
**CWE**：CWE-798 (Use of Hard-coded Credentials)
**修复建议**：
```python
import os
API_TOKEN = os.environ.get('API_TOKEN')
if not API_TOKEN:
    raise RuntimeError("API_TOKEN environment variable is required")
```
**参考**：https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure

---

### [Critical] 反序列化漏洞 (pickle) — case2_processor.py:23-26

**描述**：`load_state()` 函数使用 `pickle.load()` 加载 pickle 文件，未对数据来源做任何验证。pickle 反序列化可以执行任意代码。
**代码**：
```python
def load_state(state_file):
    """Load processing state from a pickle file."""
    with open(state_file, 'rb') as f:
        return pickle.load(f)
```
**风险**：攻击者如果能够控制 state_file 路径指向的内容（例如上传恶意 pickle 文件或覆盖已有 state 文件），则在 pickle 反序列化时可执行任意 Python 代码，完全控制服务器。
**CWE**：CWE-502 (Deserialization of Untrusted Data)
**修复建议**：
```python
import json

def load_state(state_file):
    """Load processing state from a JSON file."""
    with open(state_file, 'r') as f:
        return json.load(f)
```
如果业务必须使用 pickle，至少加入 HMAC 签名验证并在沙箱环境中运行。
**参考**：https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

---

### [Critical] 反序列化漏洞 (yaml) — case2_processor.py:17-20

**描述**：`load_config()` 函数使用 `yaml.load()` 而非 `yaml.safe_load()`。默认的 `yaml.load()` 可以构造并执行任意 Python 对象，存在远程代码执行风险。
**代码**：
```python
def load_config():
    """Load and return configuration from YAML file."""
    with open(CONFIG_FILE, 'r') as f:
        return yaml.load(f)
```
**风险**：如果攻击者能够修改 `config.yml` 的内容，可以在 YAML 中嵌入恶意 Python 对象声明，在加载时触发任意代码执行。
**CWE**：CWE-502 (Deserialization of Untrusted Data)
**修复建议**：
```python
def load_config():
    """Load and return configuration from YAML file."""
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)
```
**参考**：https://pyyaml.org/wiki/PyYAMLDocumentation

---

### [High] 路径遍历 (Zip Slip) — case2_processor.py:34-39

**描述**：`extract_archive()` 使用 `tarfile.extractall()` 解压 tar.gz 文件，未对压缩包内文件的路径做任何过滤。压缩包内可以包含以 `../` 开头的文件路径，导致文件被写入到目标目录之外的任意位置（Zip Slip / Tar Slip 攻击）。
**代码**：
```python
def extract_archive(archive_path, dest_dir=None):
    """Extract uploaded tar.gz archive."""
    if dest_dir is None:
        dest_dir = DATA_DIR
    with tarfile.open(archive_path, 'r:gz') as tar:
        tar.extractall(path=dest_dir)
```
**风险**：攻击者可以提供包含路径遍历 payload 的恶意 tar.gz 文件（例如 `../../../etc/cron.d/backdoor`），覆盖系统关键文件，获取持久化访问或提权。
**CWE**：CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))
**修复建议**：
```python
import os

def extract_archive(archive_path, dest_dir=None):
    """Extract uploaded tar.gz archive with path traversal protection."""
    if dest_dir is None:
        dest_dir = DATA_DIR
    dest_dir = os.path.realpath(dest_dir)
    with tarfile.open(archive_path, 'r:gz') as tar:
        for member in tar.getmembers():
            member_path = os.path.realpath(os.path.join(dest_dir, member.name))
            if not member_path.startswith(dest_dir + os.sep):
                raise ValueError(f"Path traversal detected: {member.name}")
            tar.extract(member, path=dest_dir)
```

---

### [High] 路径遍历 — case2_processor.py:53-58

**描述**：`process_file()` 将用户传入的 `filename` 直接拼接到 `DATA_DIR` 路径上，未做任何路径规范化或权限检查，攻击者可以使用 `../../etc/passwd` 等路径读取任意文件。
**代码**：
```python
def process_file(filename):
    """Read and process a file from the data directory."""
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, 'r') as f:
        content = f.read()
    return content.upper()
```
**风险**：攻击者传入 `../../../etc/shadow` 作为 filename，可以读取系统敏感文件（如密码文件、SSH 密钥、配置文件），导致信息泄露。
**CWE**：CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))
**修复建议**：
```python
import os

def process_file(filename):
    """Read and process a file from the data directory."""
    filepath = os.path.join(DATA_DIR, filename)
    realpath = os.path.realpath(filepath)
    if not realpath.startswith(os.path.realpath(DATA_DIR) + os.sep):
        raise ValueError(f"Access denied: {filename}")
    with open(realpath, 'r') as f:
        content = f.read()
    return content.upper()
```

---

### [Medium] 弱加密算法 (MD5) — case2_processor.py:42-45

**描述**：密码哈希使用 MD5 算法，且使用硬编码的固定盐值（`'fixed-salt-123'`）。MD5 已被证明存在碰撞漏洞，不适合安全场景。
**代码**：
```python
def hash_password(password):
    """Hash a password for storage."""
    salt = 'fixed-salt-123'
    return hashlib.md5((salt + password).encode()).hexdigest()
```
**风险**：
1. MD5 算法已被破解，攻击者可以通过彩虹表快速反查密码
2. 固定盐值意味着所有用户共享同一个盐，无法抵御针对性的彩虹表攻击
3. MD5 计算速度快，使得暴力破解成本极低
**CWE**：CWE-328 (Use of Weak Hash), CWE-759 (Use of a One-Way Hash without a Salt)
**修复建议**：
```python
import hashlib
import os

def hash_password(password):
    """Hash a password for storage using PBKDF2."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return salt.hex() + ':' + key.hex()
```
更推荐使用 `bcrypt` 或 `argon2-cffi` 库。
**参考**：https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

### [Medium] 不安全的文件权限 — case2_processor.py:77

**描述**：`DataProcessor.process()` 在处理结果输出文件时，通过 `os.chmod(output_path, 0o777)` 设置了过于宽松的权限（所有用户可读、可写、可执行）。
**代码**：
```python
def process(self, input_path, output_path):
    with open(input_path, 'r') as f:
        data = f.read()
    result = self._transform(data)
    os.chmod(output_path, 0o777)
    with open(output_path, 'w') as f:
        f.write(result)
    self.processed_count += 1
```
**风险**：`0o777` 权限意味着系统上的任何用户都可以读取甚至修改该文件。攻击者如果获得系统上的低权限 shell，可以篡改输出文件内容，破坏数据完整性或植入恶意内容。
**CWE**：CWE-732 (Incorrect Permission Assignment for Critical Resource)
**修复建议**：
```python
def process(self, input_path, output_path):
    with open(input_path, 'r') as f:
        data = f.read()
    result = self._transform(data)
    with open(output_path, 'w') as f:
        f.write(result)
    os.chmod(output_path, 0o640)  # owner read/write, group read
    self.processed_count += 1
```

---

### [Medium] 弱随机数生成器用于安全 Token — case2_processor.py:48-50

**描述**：`generate_token()` 使用 `random.choice()` 生成 API Token。`random` 模块使用的是 Mersenne Twister 算法，其输出是可预测的，不适合安全场景。
**代码**：
```python
def generate_token():
    """Generate a random API token."""
    return ''.join(random.choice('abcdef0123456789') for _ in range(32))
```
**风险**：攻击者可以通过观察一定数量的随机输出推断出 `random` 模块的内部状态，从而预测后续生成的 Token。如果此 Token 用于身份认证，攻击者可以伪造有效的 Token 绕过认证。
**CWE**：CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG))
**修复建议**：
```python
import secrets

def generate_token():
    """Generate a cryptographically random API token."""
    return secrets.token_hex(16)  # 32 hex characters
```

---

### [Low] 不安全的临时文件操作 — case2_processor.py:61-65

**描述**：`cleanup_temp_files()` 直接遍历 `/tmp/processor` 目录并删除所有文件，没有过滤只删除自己创建的文件。如果该目录中存在符号链接或其他进程的文件，可能被利用。
**代码**：
```python
def cleanup_temp_files():
    """Remove all temp files."""
    temp_dir = '/tmp/processor'
    for f in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, f))
```
**风险**：如果攻击者能够在 `/tmp/processor` 中创建符号链接指向系统关键文件，`cleanup_temp_files()` 可能会通过符号链接跟踪删除（unlink）任意文件。另外，`os.listdir()` 在遍历过程中没有处理子目录，如果目录中含子目录 `os.remove()` 会失败（静默放过），属于健壮性问题。
**CWE**：CWE-61 (UNIX Symbolic Link (Symlink) Following), CWE-459 (Incomplete Cleanup)
**修复建议**：
```python
import os
import tempfile

def cleanup_temp_files():
    """Remove only temp files created by this application."""
    temp_dir = '/tmp/processor'
    for f in os.listdir(temp_dir):
        full_path = os.path.join(temp_dir, f)
        # Check for symlink and skip
        if os.path.islink(full_path):
            continue
        if os.path.isfile(full_path):
            os.remove(full_path)
```
更推荐使用 Python 标准库 `tempfile` 模块管理临时文件。

---

## 安全评分
- **总分**：100 - (3x25) - (2x15) - (3x8) - (1x3) = 100 - 75 - 30 - 24 - 3 = **-32** → 最低分 **0/100**
- **评级**：**F**

---

## 利用链分析

该脚本中存在一条高危害的利用链：

1. **入口**：攻击者上传恶意 tar.gz 压缩包（通过 `extract_archive()` 的路径遍历漏洞）
2. **持久化**：利用 Zip Slip 覆盖 `/var/data/processor/config.yml`，在其中嵌入 YAML 反序列化 payload
3. **代码执行**：下次调用 `load_config()` 时，`yaml.load()` 触发恶意代码执行，攻击者获得服务器控制权
4. **横向移动**：通过 `API_TOKEN` 硬编码密钥访问其他依赖同一 Token 的服务

这个组合使得一个路径遍历漏洞升级为完整的远程代码执行攻击链。

---

## 修复优先级建议

| 优先级 | 问题 | 原因 |
|--------|------|------|
| P0 | 硬编码密钥 (CWE-798) | 立即轮换 Token 并从代码中移除 |
| P0 | yaml.load() 反序列化 (CWE-502) | 配合路径遍历可触发 RCE |
| P0 | pickle.load() 反序列化 (CWE-502) | 独立即可触发 RCE |
| P1 | 路径遍历：extract_archive (CWE-22) | 攻击入口点 |
| P1 | 路径遍历：process_file (CWE-22) | 任意文件读取 |
| P2 | 弱密码哈希 MD5 (CWE-328) | 密码库安全问题 |
| P2 | 不安全文件权限 0o777 (CWE-732) | 数据完整性风险 |
| P2 | 弱随机数 token (CWE-338) | 身份伪造风险 |
| P3 | 临时文件操作 (CWE-61) | 低权限下的利用场景 |
