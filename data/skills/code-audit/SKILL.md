---
category: audit
name: code-audit
description: >-
  对 Python 代码进行安全漏洞审计。当用户提到"代码审计"、"安全审查"、"安全检查"、"漏洞扫描"、
  "安全评估"、"代码 review 安全"、"找漏洞"、"有没有安全问题"、"帮我看看这段代码有没有安全问题"、
  "review this code for security"、"audit"、"security audit"、"vulnerability scan" 时，
  必须使用此 skill。适用于 Python 项目、代码片段、模块或整个仓库的安全审计。
---

# Python 代码安全审计

对 Python 代码进行系统性的安全漏洞审计，输出结构化的安全报告。

## 审计流程

按以下步骤进行审计，每一步完成后才进入下一步：

### 第一步：范围确定

1. 确认要审计的代码范围（文件、目录或代码片段）
2. 如果是项目，先了解项目结构：读取入口文件、配置文件、依赖文件（requirements.txt, setup.py, pyproject.toml）
3. 识别项目类型：Web 应用（Flask/Django/FastAPI）、CLI 工具、数据处理脚本、库等

### 第二步：逐文件扫描

对每个 Python 文件，逐行检查以下漏洞类别。每发现一个问题，立即记录位置和上下文。

### 第三步：生成报告

汇总所有发现，按严重程度排序，生成结构化报告。

## 漏洞检查清单

### 🔴 Critical（严重）

**1. 命令注入 (Command Injection)**
- `os.system()`, `os.popen()` 接收用户可控参数
- `subprocess.call()`, `subprocess.Popen()` 使用 `shell=True` 且参数来自外部
- `eval()`, `exec()`, `compile()` 执行用户可控代码
- 反引号或 `$()` 中包含外部输入（较少见但仍需注意）
- 修复：使用 `subprocess.run()` 传参列表，避免 `shell=True`；禁止 `eval/exec` 接外部输入

**2. 反序列化漏洞 (Deserialization)**
- `pickle.load()` / `pickle.loads()` 加载不可信数据
- `yaml.load()` 使用默认 Loader（应使用 `yaml.safe_load()`）
- `marshal.loads()` 处理外部数据
- `torch.load()` 加载不可信模型（PyTorch 反序列化风险）
- 修复：用 JSON 替代 pickle；yaml 用 `safe_load()`；校验数据来源

**3. 代码注入 (Code Injection)**
- `__import__()` 参数来自用户输入
- `importlib.import_module()` 动态导入不可信模块名
- `getattr()` / `setattr()` 使用外部可控的属性名访问敏感对象
- 修复：白名单限制可导入模块/属性

**4. 硬编码密钥 (Hardcoded Secrets)**
- 密码、API Key、Token、私钥直接写在代码中
- 数据库连接字符串包含明文密码
- JWT Secret、加密密钥硬编码
- 修复：使用环境变量或密钥管理服务

### 🟠 High（高危）

**5. SQL 注入 (SQL Injection)**
- 使用 `%` 格式化、`.format()`、f-string 拼接 SQL 查询
- `cursor.execute()` 直接传入拼接字符串（参数化查询是安全的方式）
- ORM 中的 `raw()` / `execute()` 使用拼接 SQL
- 修复：始终使用参数化查询（`cursor.execute(query, params)`）；ORM 优先

**6. 路径遍历 (Path Traversal)**
- `open()` 路径由用户输入拼接且未做路径规范化
- `os.path.join()` 中包含 `..` 未被过滤
- `zipfile.extractall()` 解压不可信压缩包（Zip Slip）
- `tarfile.extractall()` 同样存在路径遍历风险
- 修复：用 `os.path.realpath()` 验证最终路径在允许目录内

**7. SSRF（服务端请求伪造）**
- `requests.get()` / `urllib.request.urlopen()` URL 由用户控制
- 未对请求目标做 IP/域名白名单限制
- 可被用于访问内网服务（169.254.x.x, 10.x.x.x, 127.x.x.x）
- 修复：DNS 解析后检查 IP；白名单限制允许的目标

**8. SSTI（服务端模板注入）**
- `render_template_string()` 传入用户输入
- Jinja2 环境中用户可控内容拼入模板字符串
- 修复：使用 `render_template()` 替代；沙箱化模板环境

### 🟡 Medium（中危）

**9. XSS（跨站脚本）**
- 用户输入未转义直接写入响应 HTML
- `Markup()` 包装用户输入（绕过自动转义）
- 修复：使用模板引擎自动转义；手动转义用 `html.escape()`

**10. 弱加密算法**
- 使用 MD5、SHA1 进行密码哈希
- 对称加密使用 ECB 模式
- 使用 `random` 模块生成安全 token（应用 `secrets`）
- 硬编码的盐值或 IV
- 修复：密码用 bcrypt/scrypt/argon2；随机数用 `secrets` 模块

**11. XML 外部实体注入 (XXE)**
- 使用 `xml.etree.ElementTree` 或 `lxml` 解析不可信 XML
- 未禁用外部实体解析
- 修复：使用 `defusedxml` 库

**12. 不安全的文件权限**
- `os.chmod()` 设置过于宽松的权限（如 0o777）
- `os.umask(0)` 后创建文件
- 临时文件创建在共享目录
- 修复：使用最严格权限；临时文件用 `tempfile` 模块

### 🔵 Low（低危）

**13. 信息泄露**
- Debug 模式在生产环境开启（`DEBUG=True`）
- 异常堆栈信息直接返回给用户
- 敏感信息通过 `print()` / logging 输出
- 修复：生产环境关闭 debug；定制错误页面；日志脱敏

**14. 不安全的重定向**
- `redirect()` 目标由用户输入控制且未验证
- 开放重定向可被用于钓鱼攻击
- 修复：白名单验证重定向目标域名

**15. 依赖安全**
- `requirements.txt` 中依赖版本过旧或有已知 CVE
- 缺少依赖版本锁定
- 修复：定期更新依赖；使用 `pip-audit` 或 `safety` 检查

**16. 竞态条件 (TOCTOU)**
- 文件操作：先检查再使用（check-then-use）
- 共享资源无锁保护
- 修复：使用原子操作；文件操作用 `os.open()` 的文件描述符

## 报告模板

审计完成时，必须按以下格式输出报告：

```
# 安全审计报告

## 审计摘要
- **审计范围**：<文件/目录列表>
- **审计时间**：<当前时间>
- **文件数量**：<N>
- **发现问题**：<总数>（Critical: N, High: N, Medium: N, Low: N）

## 发现清单

### [严重程度] <漏洞类型> — <文件:行号>

**描述**：<用一句话描述问题>
**代码**：
```python
<出问题的代码片段>
```
**风险**：<说明攻击者可以做什么>
**CWE**：<对应的 CWE 编号>
**修复建议**：
```python
<安全的替代代码>
```
**参考**：<OWASP/文档链接（可选）>

（每个发现重复上述结构）

## 安全评分
- **总分**：X/100
- **评级**：<A/B/C/D/F>
```

评分规则：
- 基础分 100
- 每个 Critical 扣 25 分
- 每个 High 扣 15 分
- 每个 Medium 扣 8 分
- 每个 Low 扣 3 分
- 最低 0 分
- 评级：A=90+ / B=75-89 / C=60-74 / D=40-59 / F=0-39

## 审计原则

1. **不要产生误报** — 如果外部输入来源不明确（如函数内部但不确定调用方如何传参），标注为"潜在风险"而非确认漏洞
2. **给出可操作的修复** — 每条建议必须包含具体代码示例，而非笼统描述
3. **解释风险** — 说明攻击场景，让开发者理解为什么这是问题
4. **关注利用链** — 如果多个低危问题组合可构成高危攻击，在报告末尾特别指出
5. **优先排序** — Critical > High > Medium > Low，确保最严重的问题排前面
