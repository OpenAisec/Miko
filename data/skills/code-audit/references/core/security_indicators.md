# Security Indicators Pattern Library

> 安全指标模式库 - 借鉴 RAG 系统的预检测机制
> 覆盖: 危险函数识别、敏感信息检测、风险分级

---

## Overview

安全指标 (Security Indicators) 是在代码中标识潜在安全风险的模式。本模块提供完整的模式库，用于快速识别需要深入审计的代码区域。

---

## 指标分级

```
┌─────────────────────────────────────────────────────────┐
│  🔴 Critical: 高危险函数，通常直接导致 RCE/注入          │
│  🟠 High: 危险函数，需要验证参数来源                     │
│  🟡 Medium: 潜在风险，需要上下文分析                     │
│  🔵 Sensitive: 敏感信息，可能导致信息泄露               │
└─────────────────────────────────────────────────────────┘
```

---

## Python 安全指标

### 🔴 Critical

```bash
# 代码执行
grep -rn "\bexec\s*(" --include="*.py"
grep -rn "\beval\s*(" --include="*.py"
grep -rn "\bcompile\s*(" --include="*.py"

# 命令执行
grep -rn "os\.system\s*(" --include="*.py"
grep -rn "os\.popen\s*(" --include="*.py"
grep -rn "subprocess\.(call|run|Popen|check_output)" --include="*.py"
grep -rn "commands\.(getoutput|getstatusoutput)" --include="*.py"

# 反序列化
grep -rn "pickle\.(loads?|Unpickler)" --include="*.py"
grep -rn "cPickle\.(loads?|Unpickler)" --include="*.py"
grep -rn "yaml\.load\s*(" --include="*.py"           # 不带 Loader
grep -rn "yaml\.unsafe_load" --include="*.py"
grep -rn "jsonpickle\.decode" --include="*.py"
grep -rn "shelve\.open" --include="*.py"
grep -rn "marshal\.loads?" --include="*.py"
```

### 🟠 High

```bash
# SQL 操作
grep -rn "\.execute\s*(" --include="*.py"
grep -rn "\.executemany\s*(" --include="*.py"
grep -rn "\.raw\s*(" --include="*.py"               # Django ORM
grep -rn "\.extra\s*(" --include="*.py"             # Django ORM
grep -rn "text\s*(" --include="*.py"                # SQLAlchemy

# HTTP 请求 (SSRF)
grep -rn "requests\.(get|post|put|delete|patch|head)" --include="*.py"
grep -rn "urllib\.request\.urlopen" --include="*.py"
grep -rn "urllib2\.urlopen" --include="*.py"
grep -rn "httplib\." --include="*.py"
grep -rn "aiohttp\." --include="*.py"

# 文件操作
grep -rn "\bopen\s*(" --include="*.py"
grep -rn "shutil\.(copy|move|rmtree)" --include="*.py"
grep -rn "os\.(remove|unlink|rename|chmod)" --include="*.py"
grep -rn "pathlib\.Path.*\.(read|write|open)" --include="*.py"

# 模板渲染 (SSTI)
grep -rn "render_template_string" --include="*.py"
grep -rn "Template\s*(" --include="*.py"
grep -rn "Environment\s*(" --include="*.py"
```

### 🟡 Medium

```bash
# XML 解析 (XXE)
grep -rn "xml\.etree\." --include="*.py"
grep -rn "lxml\.(etree|objectify)" --include="*.py"
grep -rn "xml\.dom\." --include="*.py"
grep -rn "xml\.sax\." --include="*.py"
grep -rn "defusedxml" --include="*.py"              # 安全! 但需确认使用

# 正则表达式 (ReDoS)
grep -rn "re\.(match|search|findall|sub)\s*(" --include="*.py"

# 随机数
grep -rn "random\.(random|randint|choice)" --include="*.py"
```

### 🔵 Sensitive

```bash
# 凭证相关
grep -rni "password\s*=" --include="*.py"
grep -rni "secret\s*=" --include="*.py"
grep -rni "api[_-]?key\s*=" --include="*.py"
grep -rni "token\s*=" --include="*.py"
grep -rni "private[_-]?key" --include="*.py"
grep -rni "credential" --include="*.py"
grep -rni "auth[_-]?token" --include="*.py"

# 调试信息
grep -rn "DEBUG\s*=\s*True" --include="*.py"
grep -rn "print\s*(" --include="*.py"               # 生产环境
grep -rn "\.exception\s*(" --include="*.py"
```

---

## Java 安全指标

### 🔴 Critical

```bash
# 命令执行
grep -rn "Runtime\.getRuntime\(\)\.exec" --include="*.java"
grep -rn "ProcessBuilder" --include="*.java"
grep -rn "ScriptEngine.*eval" --include="*.java"
grep -rn "GroovyShell.*evaluate" --include="*.java"

# 反序列化
grep -rn "ObjectInputStream" --include="*.java"
grep -rn "\.readObject\s*(" --include="*.java"
grep -rn "XMLDecoder" --include="*.java"
grep -rn "XStream" --include="*.java"
grep -rn "ObjectMapper.*enableDefaultTyping" --include="*.java"
grep -rn "Yaml\.load\s*(" --include="*.java"        # SnakeYAML

# JNDI 注入
grep -rn "InitialContext" --include="*.java"
grep -rn "\.lookup\s*(" --include="*.java"
grep -rn "ldap://\|rmi://\|iiop://" --include="*.java"

# 表达式注入
grep -rn "SpelExpressionParser" --include="*.java"
grep -rn "parseExpression" --include="*.java"
grep -rn "Ognl\.getValue" --include="*.java"
grep -rn "VelocityEngine" --include="*.java"
grep -rn "FreeMarkerConfigurer" --include="*.java"
```

### 🟠 High

```bash
# SQL 注入
grep -rn "createQuery\|createNativeQuery" --include="*.java"
grep -rn "\.executeQuery\s*(" --include="*.java"
grep -rn "\.executeUpdate\s*(" --include="*.java"
grep -rn 'Statement\.' --include="*.java"
grep -rn '\$\{' --include="*Mapper.xml"             # MyBatis

# SSRF
grep -rn "URL\s*(" --include="*.java"
grep -rn "HttpURLConnection" --include="*.java"
grep -rn "HttpClient" --include="*.java"
grep -rn "RestTemplate" --include="*.java"
grep -rn "WebClient" --include="*.java"

# 文件操作
grep -rn "new\s+File\s*(" --include="*.java"
grep -rn "FileInputStream\|FileOutputStream" --include="*.java"
grep -rn "Files\.(read|write|copy|move)" --include="*.java"
grep -rn "MultipartFile" --include="*.java"

# XXE
grep -rn "DocumentBuilder\|SAXParser\|XMLReader" --include="*.java"
grep -rn "TransformerFactory" --include="*.java"
```

### 🟡 Medium

```bash
# 认证相关
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed" --include="*.java"
grep -rn "SecurityContextHolder" --include="*.java"
grep -rn "Authentication\|Principal" --include="*.java"

# 加密
grep -rn "MessageDigest\.(getInstance|digest)" --include="*.java"
grep -rn "Cipher\.(getInstance|init)" --include="*.java"
grep -rn "SecretKeySpec" --include="*.java"

# 日志
grep -rn "logger\.(info|debug|error|warn)" --include="*.java"
grep -rn "printStackTrace" --include="*.java"
```

### 🔵 Sensitive

```bash
# 硬编码凭证
grep -rni "password\s*=" --include="*.java" --include="*.properties" --include="*.yml"
grep -rni "secret\s*=" --include="*.java" --include="*.properties" --include="*.yml"
grep -rni "apiKey\s*=" --include="*.java"
grep -rni "jdbc:.*password" --include="*.java" --include="*.properties" --include="*.yml"

# 配置文件
grep -rn "spring\.datasource\.password" --include="*.yml" --include="*.properties"
grep -rn "jwt\.secret" --include="*.yml" --include="*.properties"
```

---

## JavaScript/Node.js 安全指标

### 🔴 Critical

```bash
# 代码执行
grep -rn "\beval\s*(" --include="*.js" --include="*.ts"
grep -rn "new\s+Function\s*(" --include="*.js" --include="*.ts"
grep -rn "setTimeout\s*(\s*['\"]" --include="*.js"
grep -rn "setInterval\s*(\s*['\"]" --include="*.js"

# 命令执行
grep -rn "child_process\.(exec|spawn|execFile|fork)" --include="*.js" --include="*.ts"
grep -rn "shelljs\." --include="*.js"

# 原型污染
grep -rn "__proto__" --include="*.js" --include="*.ts"
grep -rn "constructor\[" --include="*.js" --include="*.ts"
grep -rn "Object\.assign\s*(" --include="*.js" --include="*.ts"
grep -rn "_\.merge\|_\.extend\|_\.defaultsDeep" --include="*.js" --include="*.ts"
```

### 🟠 High

```bash
# XSS
grep -rn "\.innerHTML\s*=" --include="*.js" --include="*.ts" --include="*.html"
grep -rn "\.outerHTML\s*=" --include="*.js" --include="*.ts"
grep -rn "document\.write\s*(" --include="*.js" --include="*.html"
grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx"

# SQL 注入
grep -rn "\.query\s*(\s*['\`]" --include="*.js" --include="*.ts"
grep -rn "\.raw\s*(\s*['\`]" --include="*.js" --include="*.ts"

# SSRF
grep -rn "axios\.(get|post|put|delete)" --include="*.js" --include="*.ts"
grep -rn "fetch\s*(" --include="*.js" --include="*.ts"
grep -rn "request\s*(" --include="*.js" --include="*.ts"
grep -rn "got\s*(" --include="*.js" --include="*.ts"

# 文件操作
grep -rn "fs\.(readFile|writeFile|readFileSync|writeFileSync)" --include="*.js" --include="*.ts"
grep -rn "path\.join\s*(" --include="*.js" --include="*.ts"
```

### 🟡 Medium

```bash
# 模板
grep -rn "ejs\.render" --include="*.js"
grep -rn "pug\.render" --include="*.js"
grep -rn "handlebars\.compile" --include="*.js"

# 正则 (ReDoS)
grep -rn "new\s+RegExp\s*(" --include="*.js" --include="*.ts"
grep -rn "\.match\s*(\s*/" --include="*.js" --include="*.ts"

# JWT
grep -rn "jwt\.(sign|verify|decode)" --include="*.js" --include="*.ts"
grep -rn "algorithms.*none" --include="*.js" --include="*.ts"
```

### 🔵 Sensitive

```bash
# 凭证
grep -rni "password\s*[=:]" --include="*.js" --include="*.ts" --include="*.json"
grep -rni "apiKey\s*[=:]" --include="*.js" --include="*.ts" --include="*.json"
grep -rni "secret\s*[=:]" --include="*.js" --include="*.ts" --include="*.json"
grep -rni "token\s*[=:]" --include="*.js" --include="*.ts" --include="*.json"

# 环境变量
grep -rn "process\.env\." --include="*.js" --include="*.ts"
```

---

## PHP 安全指标

### 🔴 Critical

```bash
# 代码执行
grep -rn "\beval\s*(" --include="*.php"
grep -rn "\bassert\s*(" --include="*.php"
grep -rn "create_function\s*(" --include="*.php"
grep -rn "preg_replace.*\/e" --include="*.php"

# 命令执行
grep -rn "\bexec\s*(" --include="*.php"
grep -rn "\bsystem\s*(" --include="*.php"
grep -rn "\bshell_exec\s*(" --include="*.php"
grep -rn "\bpassthru\s*(" --include="*.php"
grep -rn "\bpopen\s*(" --include="*.php"
grep -rn "\bproc_open\s*(" --include="*.php"
grep -rn "\`.*\$" --include="*.php"                 # 反引号

# 反序列化
grep -rn "\bunserialize\s*(" --include="*.php"
grep -rn "phar://" --include="*.php"

# 文件包含
grep -rn "\binclude\s*(" --include="*.php"
grep -rn "\binclude_once\s*(" --include="*.php"
grep -rn "\brequire\s*(" --include="*.php"
grep -rn "\brequire_once\s*(" --include="*.php"
```

### 🟠 High

```bash
# SQL 注入
grep -rn "mysql_query\s*(" --include="*.php"
grep -rn "mysqli_query\s*(" --include="*.php"
grep -rn "->query\s*(" --include="*.php"
grep -rn "->exec\s*(" --include="*.php"

# 文件操作
grep -rn "file_get_contents\s*(" --include="*.php"
grep -rn "file_put_contents\s*(" --include="*.php"
grep -rn "fopen\s*(" --include="*.php"
grep -rn "readfile\s*(" --include="*.php"
grep -rn "move_uploaded_file\s*(" --include="*.php"

# SSRF
grep -rn "curl_exec\s*(" --include="*.php"
grep -rn "file_get_contents.*http" --include="*.php"
grep -rn "fsockopen\s*(" --include="*.php"

# 用户输入
grep -rn '\$_GET\[' --include="*.php"
grep -rn '\$_POST\[' --include="*.php"
grep -rn '\$_REQUEST\[' --include="*.php"
grep -rn '\$_COOKIE\[' --include="*.php"
grep -rn '\$_SERVER\[' --include="*.php"
```

### 🟡 Medium

```bash
# XSS
grep -rn "echo\s*\\\$" --include="*.php"
grep -rn "print\s*\\\$" --include="*.php"
grep -rn "htmlspecialchars" --include="*.php"       # 检查是否正确使用

# 会话
grep -rn "session_start\s*(" --include="*.php"
grep -rn "\$_SESSION\[" --include="*.php"

# 头注入
grep -rn "header\s*(" --include="*.php"
grep -rn "setcookie\s*(" --include="*.php"
```

---

## Go 安全指标

### 🔴 Critical

```bash
# 命令执行
grep -rn "exec\.Command\s*(" --include="*.go"
grep -rn "os/exec" --include="*.go"

# 不安全操作
grep -rn "unsafe\." --include="*.go"
grep -rn "reflect\.(Value|Type)" --include="*.go"
```

### 🟠 High

```bash
# SQL 注入
grep -rn "db\.Query\s*(" --include="*.go"
grep -rn "db\.Exec\s*(" --include="*.go"
grep -rn "fmt\.Sprintf.*SELECT\|INSERT\|UPDATE\|DELETE" --include="*.go"

# SSRF
grep -rn "http\.Get\s*(" --include="*.go"
grep -rn "http\.Post\s*(" --include="*.go"
grep -rn "http\.NewRequest\s*(" --include="*.go"

# 文件操作
grep -rn "os\.Open\s*(" --include="*.go"
grep -rn "ioutil\.ReadFile\s*(" --include="*.go"
grep -rn "os\.Create\s*(" --include="*.go"
grep -rn "filepath\.Join\s*(" --include="*.go"

# 模板
grep -rn "template\.HTML\s*(" --include="*.go"      # 不安全的 HTML
grep -rn "template\.JS\s*(" --include="*.go"
```

### 🟡 Medium

```bash
# 并发安全
grep -rn "go\s+func\s*(" --include="*.go"
grep -rn "sync\.(Mutex|RWMutex)" --include="*.go"
grep -rn "atomic\." --include="*.go"

# 加密
grep -rn "crypto/md5\|crypto/sha1" --include="*.go"
grep -rn "math/rand" --include="*.go"               # 非加密安全
```

---

## 使用指南

### 快速扫描脚本

```bash
#!/bin/bash
# quick_security_scan.sh

PROJECT_DIR=${1:-.}

echo "=== Critical Indicators ==="
grep -rn "eval\|exec\|system\|pickle\|unserialize" "$PROJECT_DIR" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.php"

echo "=== High Indicators ==="
grep -rn "execute\|query\|request\|open\|File" "$PROJECT_DIR" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.php"

echo "=== Sensitive Info ==="
grep -rni "password\|secret\|api.key\|token" "$PROJECT_DIR" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.php" \
    --include="*.yml" --include="*.yaml" --include="*.json" --include="*.properties"
```

### 风险评分

```
每个文件的风险分数计算:
Score = (Critical × 10) + (High × 5) + (Medium × 2) + (Sensitive × 1)

分数区间:
├─ 0-5:   Low Risk    (常规审计)
├─ 6-15:  Medium Risk (重点审计)
├─ 16-30: High Risk   (深度审计)
└─ 30+:   Critical    (优先审计)
```

---

## 参考资源

- [Semgrep Registry](https://semgrep.dev/r)
- [CodeQL Queries](https://github.com/github/codeql)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
