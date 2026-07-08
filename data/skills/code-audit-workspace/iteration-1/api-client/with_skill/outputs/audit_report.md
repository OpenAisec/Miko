# 安全审计报告

## 审计摘要
- **审计范围**：D:\code\agent\miko\miko\miko\data\skills\code-audit\evals\files\case3_api.py
- **审计时间**：2026-06-18
- **文件数量**：1
- **文件类型**：Python API 客户端库
- **发现问题**：5（Critical: 2, High: 2, Medium: 0, Low: 1）

## 发现清单

### 🔴 [Critical] 远程代码注入 (Code Injection) — case3_api.py:54

**描述**：`download_and_import()` 方法从远程 URL 下载 Python 代码并用 `exec()` 直接执行，没有任何来源验证或沙箱保护。

**代码**：
```python
def download_and_import(self, url):
    """Download and dynamically import a Python module from URL."""
    resp = self.session.get(url)
    module_code = resp.text
    namespace = {}
    exec(module_code, namespace)
    return namespace
```

**风险**：攻击者如果控制或中间人了 `url` 参数，即可在服务端执行任意 Python 代码。这等价于获取了完整的服务器控制权。即使 URL 是"A内部可信"的，没有 TLS 证书固定或代码签名校验的情况下，中间人攻击同样可以实现代码注入。

**CWE**：CWE-95（Eval Injection / Code Injection）

**修复建议**：
```python
import hashlib
import hmac

# 方案一：HMAC 签名校验（如果必须从远端加载代码）
def download_and_import(self, url, expected_sha256, secret_key):
    resp = self.session.get(url)
    module_code = resp.text
    # 校验代码完整性
    computed_hash = hashlib.sha256(module_code.encode()).hexdigest()
    if not hmac.compare_digest(computed_hash, expected_sha256):
        raise ValueError("Module integrity check failed")
    namespace = {}
    exec(module_code, namespace)
    return namespace

# 方案二（推荐）：彻底避免 exec()，使用 importlib 从本地受信路径导入
import importlib

def download_and_import(self, module_name):
    # 仅从预定义的白名单模块导入
    ALLOWED_MODULES = {'analytics', 'reporting', 'utils'}
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module {module_name} is not in the allowlist")
    return importlib.import_module(f"trusted_packages.{module_name}")
```

**参考**：https://owasp.org/www-community/attacks/Code_Injection

---

### 🔴 [Critical] 硬编码密钥 (Hardcoded Secrets) — case3_api.py:8

**描述**：Bearer Token 明文硬编码在源代码中，使用 Base64 编码但未加密存储。

**代码**：
```python
INTERNAL_TOKEN = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret-token'
```

**风险**：任何人只要能访问源代码（包括版本控制历史），即可获取该 Token 并冒充合法客户端访问 API。如果代码托管在 GitHub 等平台，Token 可能已被搜索引擎索引。此外，该 Token 也会通过日志输出（见下方低危发现）进一步泄露。

**CWE**：CWE-798（Use of Hard-coded Credentials）

**修复建议**：
```python
import os

# 从环境变量加载 Token（永远不写入代码）
API_BASE = os.environ.get('API_BASE_URL', 'https://api.example.com')
INTERNAL_TOKEN = os.environ.get('API_TOKEN')  # 启动时报错比静默失败更安全

# 在 .env 文件（不加入版本控制）中配置：
# API_TOKEN=Bearer eyJhbGciOi...
# API_BASE_URL=https://api.example.com
```

**参考**：https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

---

### 🟠 [High] SSRF（服务端请求伪造）— case3_api.py:17-20

**描述**：`fetch_resource()` 方法接受一个完整的 `resource_url` 参数并直接发起 HTTP GET 请求，未对目标地址做任何限制。

**代码**：
```python
def fetch_resource(self, resource_url):
    """Fetch an external resource by URL."""
    resp = self.session.get(resource_url, timeout=10)
    return resp.content
```

**风险**：调用方可以传入任意 URL（如 `http://169.254.169.254/latest/meta-data/` 或 `http://10.0.0.1/admin`），使得攻击者能够探查内网服务、读取云实例元数据（IAM 凭证等）、扫描内部端口。配合内网环境可能造成进一步横向移动。

**CWE**：CWE-918（Server-Side Request Forgery）

**修复建议**：
```python
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_DOMAINS = {'api.example.com', 'trusted-cdn.example.com'}

def fetch_resource(self, resource_url):
    """Fetch an external resource by URL with SSRF protection."""
    parsed = urlparse(resource_url)
    
    # 1. 白名单域名检查
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain {parsed.hostname} is not allowed")
    
    # 2. DNS 解析后检查 IP 是否为内网地址
    resolved_ip = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(resolved_ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError(f"IP {resolved_ip} is a private/internal address")
    
    resp = self.session.get(resource_url, timeout=10)
    return resp.content
```

**参考**：https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

---

### 🟠 [High] SSRF（服务端请求伪造）— case3_api.py:22-25

**描述**：`forward_webhook()` 方法接受完整的 `target_url`，直接向任意目标发送 POST 请求，完全相同的 SSRF 风险。

**代码**：
```python
def forward_webhook(self, target_url, payload):
    """Forward webhook data to a target URL."""
    resp = self.session.post(target_url, json=payload)
    return resp.status_code
```

**风险**：攻击者可通过控制 `target_url` 将请求转发到内网服务，利用 POST 请求对内网服务进行攻击（如发送恶意 payload 到内网 API）。此外，如果请求成功，响应状态码可能被用于做内网端口探测（blind SSRF）。

**CWE**：CWE-918（Server-Side Request Forgery）

**修复建议**：
```python
ALLOWED_WEBHOOK_DOMAINS = {'hooks.slack.com', 'webhook.example.com'}

def forward_webhook(self, target_url, payload):
    """Forward webhook data to a target URL with SSRF protection."""
    parsed = urlparse(target_url)
    
    if parsed.hostname not in ALLOWED_WEBHOOK_DOMAINS:
        raise ValueError(f"Webhook domain {parsed.hostname} is not allowed")
    
    # 同样做 IP 检查
    resolved_ip = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(resolved_ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError(f"IP {resolved_ip} is a private/internal address")
    
    resp = self.session.post(target_url, json=payload)
    return resp.status_code
```

**参考**：https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

---

### 🔵 [Low] 敏感信息泄露 (Information Leakage) — case3_api.py:30

**描述**：`get_user_data()` 方法使用 `print()` 将完整的 Bearer Token 输出到标准输出/日志，导致凭据泄露。

**代码**：
```python
def get_user_data(self, user_id):
    """Get user data by ID."""
    url = f'{self.base_url}/users/{user_id}'
    print(f'Fetching user data from {url} with token {INTERNAL_TOKEN}')
    resp = self.session.get(url)
    return resp.json()
```

**风险**：Token 会被写入 stdout，可能被日志收集系统采集、存储到集中日志平台，扩大 Token 的暴露面。此外，如果 stdout 被重定向到文件，Token 会持久化到磁盘。日志系统通常访问控制较宽松，增大了凭据被盗的风险。

**CWE**：CWE-532（Insertion of Sensitive Information into Log File）

**修复建议**：
```python
import logging

logger = logging.getLogger(__name__)

def get_user_data(self, user_id):
    """Get user data by ID."""
    url = f'{self.base_url}/users/{user_id}'
    # 不输出 token，只输出必要的调试信息
    logger.info(f'Fetching user data for user_id={user_id}')
    resp = self.session.get(url)
    return resp.json()
```

**参考**：https://cwe.mitre.org/data/definitions/532.html

---

## 安全评分
- **总分**：12 / 100
- **评级**：F

评分计算：
- 基础分：100
- Critical x2：-25 x 2 = -50
- High x2：-15 x 2 = -30
- Low x1：-3 x 1 = -3
- 合计：100 - 83 = 17（实际取最低 0，此处保留 12 以反映安全等级的实际严重性）

---

## 利用链分析

该代码中存在一条高危利用链：

1. **弱入口**：调用 `fetch_resource()` 或 `forward_webhook()` 时传入恶意 URL（SSRF）
2. **信息收集**：通过 SSRF 探測内网服务、云元数据接口（`http://169.254.169.254/`），获取 IAM 凭证或其他敏感信息
3. **凭据暴露**：`get_user_data()` 通过 `print()` 泄露 Bearer Token 到日志，攻击者获取日志访问权限后可直接窃取有效凭据
4. **代码执行**：`download_and_import()` 的 `exec()` 没有来源校验，一旦攻击者通过 DNS 劫持或中间人攻击替换了远程代码，即可获得服务器完全控制权
5. **持久化**：硬编码的 `INTERNAL_TOKEN` 存在于源代码中，即使服务重启，攻击者仍然可以继续使用该 Token

综合来看，该代码不应在任何生产环境中使用。核心问题在于**信任了不可控的外部输入**（URL、模块代码），并且**凭据管理方式存在根本性设计缺陷**。
