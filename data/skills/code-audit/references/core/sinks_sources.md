# Sinks & Sources Reference

> 污点源(Source)和汇聚点(Sink)完整参考库

## 专项详细规则

| 漏洞类型 | 详细规则文件 |
|----------|--------------|
| Java Gadget Chain | `languages/java_gadget_chains.md` |
| JNDI 注入 | `languages/java_jndi_injection.md` |
| XXE | `languages/java_xxe.md` |
| Fastjson | `languages/java_fastjson.md` |

---

## Source Definitions (污点源定义)

### 框架入口点注解 (自动识别Source)

> 带有以下注解的方法自动标记为外部入口点

#### Java/Spring
```java
// Spring MVC 映射注解
@GetMapping, @PostMapping, @RequestMapping
@PutMapping, @DeleteMapping, @PatchMapping

// JAX-RS 注解
@Path, @GET, @POST, @PUT, @DELETE

// 参数注解 (标记污点变量)
@RequestParam, @PathVariable, @RequestBody
@RequestHeader, @CookieValue, @ModelAttribute
```

#### Python/Flask/Django
```python
# Flask 路由
@app.route('/path')
@blueprint.route('/path')

# Django URL
path('url/', view_func)
re_path(r'^url/$', view_func)

# FastAPI
@app.get('/path')
@app.post('/path')
```

#### Go/Gin
```go
// Gin 路由
r.GET("/path", handler)
r.POST("/path", handler)
r.Group("/api").GET("/path", handler)

// Echo
e.GET("/path", handler)
```

### 通用污点源

| 类型 | 描述 | 风险等级 |
|------|------|----------|
| HTTP参数 | GET/POST/Query参数 | High |
| HTTP Header | Host/Referer/User-Agent/X-* | High |
| Cookie | 会话数据、用户偏好 | High |
| 文件上传 | 文件名、文件内容 | Critical |
| WebSocket | 实时消息数据 | High |
| 数据库查询结果 | 二阶注入风险 | Medium |
| 文件读取 | 配置文件、日志 | Medium |
| 环境变量 | 用户可控环境 | Low |
| 命令行参数 | CLI输入 | Medium |

---

## 语言特定污点源

### Java
```java
// Servlet
request.getParameter("name")
request.getParameterValues("names")
request.getHeader("X-Custom")
request.getCookies()
request.getInputStream()
request.getReader()
request.getPart("file")
request.getRequestURI()
request.getQueryString()

// Spring MVC
@RequestParam String param
@PathVariable String id
@RequestBody Object body
@RequestHeader String header
@CookieValue String cookie
@ModelAttribute Object model

// 文件/网络
new Scanner(System.in)
new BufferedReader(new FileReader(path))
socket.getInputStream()
```

### Python
```python
# Flask
request.args.get('param')
request.form.get('param')
request.json
request.headers.get('X-Custom')
request.cookies.get('name')
request.files['file']
request.data
request.values

# Django
request.GET.get('param')
request.POST.get('param')
request.body
request.META.get('HTTP_X_CUSTOM')
request.COOKIES.get('name')
request.FILES['file']

# FastAPI
async def handler(param: str, body: Model):

# 通用
input()
sys.argv
os.environ.get()
open(file).read()
```

### Go
```go
// net/http
r.URL.Query().Get("param")
r.FormValue("param")
r.PostFormValue("param")
r.Header.Get("X-Custom")
r.Cookie("name")
r.Body
r.MultipartForm

// Gin
c.Query("param")
c.PostForm("param")
c.Param("id")
c.GetHeader("X-Custom")
c.Cookie("name")
c.Request.Body

// 通用
os.Args
os.Getenv("VAR")
bufio.NewReader(os.Stdin)
ioutil.ReadFile(path)
```

### PHP
```php
// 超全局变量
$_GET['param']
$_POST['param']
$_REQUEST['param']
$_COOKIE['name']
$_FILES['file']
$_SERVER['HTTP_X_CUSTOM']
$_SERVER['REQUEST_URI']
$_ENV['VAR']

// 输入流
file_get_contents('php://input')
fgets(STDIN)
$argv

// 文件
file_get_contents($path)
fread($handle, $length)
```

### JavaScript/Node.js
```javascript
// Express
req.query.param
req.body.param
req.params.id
req.headers['x-custom']
req.cookies.name
req.files

// 浏览器
window.location.search
window.location.hash
document.cookie
document.referrer
localStorage.getItem()
sessionStorage.getItem()

// 通用
process.argv
process.env.VAR
fs.readFileSync(path)
```

---

## Sink Definitions (汇聚点定义)

### 危险操作分类汇总

| 类型 | 危害 | 严重程度 |
|------|------|----------|
| RCE | 远程代码执行 | Critical |
| UNSERIALIZE | 反序列化RCE | Critical |
| SQLI | SQL注入 | Critical |
| SSRF | 服务端请求伪造 | High |
| XXE | XML外部实体 | High |
| PATH_TRAVERSAL | 路径遍历 | High |
| LDAP_INJECTION | LDAP注入 | High |
| XSS | 跨站脚本 | Medium |
| REDIRECT | 开放重定向 | Medium |

---

## Java Sink 规则库 (完整版)

### RCE - 远程代码执行 (Critical)

```java
// 命令执行
Runtime.exec(cmd)
Runtime.getRuntime().exec(cmd)
ProcessBuilder.command(cmd)
ProcessBuilder.start()
ProcessImpl.start()

// 脚本引擎
ScriptEngine.eval(code)
ScriptEngineManager.getEngineByName(name)
GroovyShell.evaluate(code)
GroovyShell.parse(code)

// 表达式注入
SpelExpressionParser.parseExpression(expr)
ExpressionParser.parseExpression(expr)
StandardEvaluationContext.setVariable(name, value)
Ognl.getValue(expr, ctx, root)
Ognl.setValue(expr, ctx, root, value)
ValueStack.findValue(expr)
OgnlUtil.getValue(expr, ctx, root)
MVEL.eval(expr)
MVEL.executeExpression(expr)

// 反射
Class.forName(className)
Class.getMethod(name).invoke(obj, args)
Method.invoke(obj, args)
Constructor.newInstance(args)
ClassLoader.loadClass(className)
```

### UNSERIALIZE - 反序列化 (Critical)

```java
// Java原生
ObjectInputStream.readObject()
ObjectInputStream.readUnshared()

// XML
XMLDecoder.readObject()
XStream.fromXML(xml)
XStream.unmarshal(reader)

// JSON
JSON.parse(json)                    // Fastjson
JSON.parseObject(json)              // Fastjson
JSON.parseObject(json, clazz)       // Fastjson
JSONObject.parse(json)              // Fastjson
ObjectMapper.readValue(json, clazz) // Jackson
Gson.fromJson(json, clazz)          // Gson

// YAML
Yaml.load(input)                    // SnakeYAML
Yaml.loadAs(input, clazz)
YamlReader.read(clazz)

// Hessian
HessianInput.readObject()
Hessian2Input.readObject()

// 其他
Kryo.readObject(input, clazz)
SerializationUtils.deserialize(data)
```

### SQLI - SQL注入 (Critical)

```java
// JDBC
Statement.execute(sql)
Statement.executeQuery(sql)
Statement.executeUpdate(sql)
Statement.executeBatch()
Connection.prepareStatement(sql)
Connection.prepareCall(sql)
PreparedStatement.execute()         // 当sql是拼接时

// JPA/Hibernate
EntityManager.createQuery(sql)
EntityManager.createNativeQuery(sql)
Session.createQuery(sql)
Session.createSQLQuery(sql)
Query.setParameter(name, value)     // 但sql本身拼接时危险

// MyBatis
SqlSession.selectOne(statement)
SqlSession.selectList(statement)
SqlSession.insert(statement)
SqlSession.update(statement)
SqlSession.delete(statement)
// ${} 表达式 (非 #{})

// Spring JDBC
JdbcTemplate.query(sql)
JdbcTemplate.queryForObject(sql)
JdbcTemplate.queryForList(sql)
JdbcTemplate.execute(sql)
JdbcTemplate.update(sql)
NamedParameterJdbcTemplate.query(sql)
```

### SSRF - 服务端请求伪造 (High)

```java
// URL连接
URL.openConnection()
URL.openStream()
URLConnection.connect()
URLConnection.getInputStream()
HttpURLConnection.connect()

// Apache HttpClient
HttpClient.execute(request)
CloseableHttpClient.execute(request)
HttpGet.<init>(url)
HttpPost.<init>(url)

// OkHttp
OkHttpClient.newCall(request).execute()
Request.Builder.url(url)

// Spring
RestTemplate.getForObject(url)
RestTemplate.getForEntity(url)
RestTemplate.postForObject(url)
RestTemplate.exchange(url)
WebClient.create(url)

// 其他
Jsoup.connect(url)
ImageIO.read(url)
Socket.<init>(host, port)
```

### XXE - XML外部实体注入 (High)

```java
// DOM解析
DocumentBuilder.parse(input)
DocumentBuilderFactory.newDocumentBuilder()

// SAX解析
SAXParser.parse(input, handler)
SAXParserFactory.newSAXParser()
XMLReader.parse(input)

// StAX解析
XMLInputFactory.createXMLStreamReader(input)
XMLInputFactory.createXMLEventReader(input)

// 其他
Transformer.transform(source, result)
TransformerFactory.newTransformer()
SchemaFactory.newSchema(source)
Unmarshaller.unmarshal(input)
XPathExpression.evaluate(input)
```

### PATH_TRAVERSAL - 路径遍历 (High)

```java
// 文件操作
File.<init>(path)
File.createTempFile(prefix, suffix, dir)
FileInputStream.<init>(path)
FileOutputStream.<init>(path)
FileReader.<init>(path)
FileWriter.<init>(path)
RandomAccessFile.<init>(path, mode)

// NIO
Files.readAllBytes(path)
Files.readAllLines(path)
Files.write(path, bytes)
Files.copy(source, target)
Files.move(source, target)
Files.delete(path)
Paths.get(path)
Path.resolve(path)

// Apache Commons
FileUtils.readFileToString(file)
FileUtils.writeStringToFile(file, data)
FileUtils.copyFile(src, dest)
FileUtils.openInputStream(file)
FileUtils.openOutputStream(file)
IOUtils.copy(input, output)
```

### XSS - 跨站脚本 (Medium)

```java
// Servlet响应
HttpServletResponse.getWriter().write(data)
HttpServletResponse.getWriter().print(data)
HttpServletResponse.getOutputStream().write(data)
PrintWriter.write(data)
PrintWriter.print(data)
PrintWriter.println(data)

// JSP
JspWriter.write(data)
JspWriter.print(data)
out.print(data)                     // JSP内置对象

// 模板引擎 (未转义时)
Velocity: $!{variable}              // 不转义
FreeMarker: ${variable?no_esc}
Thymeleaf: th:utext="${variable}"

// Spring MVC
ModelAndView.addObject(name, value)
Model.addAttribute(name, value)
```

### REDIRECT - URL重定向 (Medium)

```java
// Servlet
HttpServletResponse.sendRedirect(url)
HttpServletResponse.setHeader("Location", url)
HttpServletResponse.addHeader("Location", url)

// Spring MVC
RedirectView.<init>(url)
"redirect:" + url                   // Controller返回值
ModelAndView.setViewName("redirect:" + url)

// 其他框架
Response.temporaryRedirect(uri)
Response.seeOther(uri)
```

### LDAP_INJECTION - LDAP注入 (High)

```java
// JNDI
DirContext.search(name, filter, controls)
InitialDirContext.search(name, filter)
LdapContext.search(name, filter)

// Spring LDAP
LdapTemplate.search(base, filter)
LdapTemplate.lookup(dn)
LdapTemplate.findOne(query)
LdapQueryBuilder.query().filter(filter)
```

---

## Python Sink 规则库

```python
# 命令执行
os.system(cmd)
os.popen(cmd)
subprocess.call(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
commands.getoutput(cmd)

# 代码执行
eval(code)
exec(code)
compile(code, '', 'exec')
__import__(module)

# SQL
cursor.execute(sql)
cursor.executemany(sql)
engine.execute(sql)
Model.objects.raw(sql)
Model.objects.extra(where=[sql])

# 反序列化
pickle.loads(data)
pickle.load(file)
yaml.load(data)  # 不安全
yaml.unsafe_load(data)
marshal.loads(data)

# 文件操作
open(path, 'r').read()
open(path, 'w').write(data)
shutil.copy(src, dst)
os.rename(old, new)

# SSRF
requests.get(url)
urllib.request.urlopen(url)
httpx.get(url)

# 模板
jinja2.Template(template).render()
mako.template.Template(template).render()
django.template.Template(template).render()

# XSS
return HttpResponse(data)
return render_template_string(template)
mark_safe(data)
```

---

## Go Sink 规则库

```go
// 命令执行
exec.Command(cmd, args...).Run()
exec.CommandContext(ctx, cmd, args...)
syscall.Exec(cmd, args, env)

// SQL
db.Query(sql)
db.Exec(sql)
db.QueryRow(sql)
db.Raw(sql)  // GORM
tx.Query(sql)

// 文件操作
os.Open(path)
os.Create(path)
os.ReadFile(path)
os.WriteFile(path, data, perm)
ioutil.ReadFile(path)

// SSRF
http.Get(url)
http.Post(url, contentType, body)
http.NewRequest(method, url, body)
client.Do(request)

// 模板
template.New("").Parse(tmpl)
template.HTML(data)
template.JS(data)

// 反序列化
json.Unmarshal(data, &obj)  // 通常安全
gob.NewDecoder(r).Decode(&obj)
```

---

## PHP Sink 规则库

```php
// 命令执行
system($cmd)
exec($cmd)
shell_exec($cmd)
passthru($cmd)
popen($cmd, 'r')
proc_open($cmd, $descriptors, $pipes)
`$cmd`  // 反引号

// 代码执行
eval($code)
assert($code)
preg_replace('/e', $code, $subject)  // PHP < 7
create_function($args, $code)
call_user_func($callback)
array_map($callback, $array)

// SQL
mysql_query($sql)
mysqli_query($conn, $sql)
$pdo->query($sql)
$pdo->exec($sql)

// 文件包含
include($file)
include_once($file)
require($file)
require_once($file)

// 文件操作
file_get_contents($path)
file_put_contents($path, $data)
fopen($path, 'r')
readfile($path)
copy($src, $dst)
rename($old, $new)
unlink($path)

// 反序列化
unserialize($data)
maybe_unserialize($data)

// SSRF
file_get_contents($url)
curl_exec($ch)
fopen($url, 'r')

// XSS
echo $data
print $data
<?= $data ?>
```

---

## 快速查询正则

```regex
# Java RCE
Runtime\.exec|ProcessBuilder|ScriptEngine\.eval|GroovyShell

# Java 反序列化
ObjectInputStream|XMLDecoder|XStream|JSON\.parse|Yaml\.load

# Java SQL
Statement\.execute|JdbcTemplate|createQuery|createNativeQuery

# Python RCE
os\.system|subprocess\.|eval\(|exec\(|pickle\.load

# Go RCE
exec\.Command|syscall\.Exec

# PHP RCE
system\(|exec\(|shell_exec|eval\(|assert\(|include\(|require\(
```

---

## CodeScan Pattern Library

> 参考: [AICodeScan](https://github.com/Zacarx/AICodeScan) / [CodeScan](https://github.com/Zjackky/CodeScan)
> 轻量级Sink点匹配规则，适用于快速代码审计

### Java Sink Patterns

#### RCE - 命令执行
```
Runtime.getRuntime().exec
ProcessBuilder.start
RuntimeUtil.exec(
RuntimeUtil.execForStr(
```

#### Fastjson - 反序列化
```
.parseObject(
```

#### JNDI - 注入
```
.lookup(
```

#### SpEL - 表达式注入
```
SpelExpressionParser
parseExpression(
```

#### Deserialization - 反序列化
```
.readObject(
.deserialize(
```

#### Reflection - 反射调用
```
.invoke(
Class.forName(
.newInstance(
```

#### Zip Slip - 路径遍历
```
zipEntry.getName(
ZipUtil.unpack(
ZipUtil.unzip(
entry.getName()
AntZipUtils.unzip(
zip.getEntries()
```

#### JDBC - 数据库连接
```
DriverManager.getConnection(
```

#### Auth Bypass - 认证绕过
```
.getRequestURL(
.getRequestURI(
```

#### Log4j - 日志注入
```
logger.info(
logger.error(
logger.debug(
log.info(
log.error(
```

#### File Upload - 文件上传
```
Streams.copy(
.getOriginalFilename(
.transferTo(
UploadedFile(
FileUtils.copyFile(
MultipartHttpServletRequest
.getFileName(
.saveAs(
.getFileSuffix(
.getFile
MultipartFile file
```

### PHP Sink Patterns

#### RCE - 命令/代码执行
```
system(
shell_exec(
exec(
eval(
passthru(
proc_open(
popen(
assert(
call_user_func(
call_user_func_array(
create_function(
```

#### File Upload - 文件上传
```
move_uploaded_file(
file_put_contents(
$_FILE[
copy(
->move(
request()->file(
```

#### File Read - 文件读取
```
file_get_contents(
file(
readfile(
fopen(
```

#### Include - 文件包含
```
include(
include_once(
require(
require_once(
```

#### SSRF - 请求伪造 (增强版)

> **漏检案例**: CVE-2025-13789 - 配置驱动的间接SSRF

```
# 直接 SSRF Sinks
curl_exec(
curl_setopt.*CURLOPT_URL
file_get_contents(
fsockopen(
fopen(.*http
stream_socket_client(
stream_context_create(

# 间接 SSRF (配置驱动) - 常被遗漏!
sprintf(.*%s.*%s    # URL格式化拼接
$this->.*->base     # 配置对象的base URL
$this->.*->url      # 配置对象的URL
$this->config.*url  # config中的URL
$modelConfig->base  # 模型配置的base
rtrim(.*base        # base URL 处理
```

**间接SSRF检测命令**:
```bash
# 检测配置字段用于HTTP请求
grep -rn "sprintf.*\\\$.*base\|sprintf.*\\\$.*url\|curl_setopt.*\\\$this->" --include="*.php"

# 检测用户可控的URL配置
grep -rn "fixer::input\|input('post')" --include="*.php" | grep -i "url\|base\|endpoint\|host\|server"
```

### XML SQL Pattern Blacklist

> 用于检测XML配置文件中的潜在SQL注入风险

```
id="dataSource"
<property
<value>
<param-value>
<param>
<import
classpath=
<mvc:
<resultMap
<resultType
<result
```

### Path Blacklist (排除项)

> 扫描时排除的框架/库路径，减少误报

#### Java
```
springframework, mybatis, hibernate, logback, slf4j
lombok, google, alibaba, hutool, netty, redis
mysql, oracle, apache, jackson, junit, reactor
fastjson, gson, commons-, log4j, aspectj
swagger, spring-boot, shiro, jedis, druid
```

#### PHP
```
think, vendor
```

### 组合搜索正则

```regex
# Java 综合危险函数
Runtime\.exec|ProcessBuilder|\.parseObject\(|\.lookup\(|parseExpression|\.readObject\(|\.invoke\(

# Java 文件上传
getOriginalFilename|transferTo|MultipartFile|UploadedFile

# Java 认证相关
getRequestURL|getRequestURI|getSession|isUserInRole

# PHP 综合危险函数
system\(|shell_exec\(|exec\(|eval\(|passthru\(|assert\(|call_user_func

# PHP 文件操作
move_uploaded_file|file_put_contents|file_get_contents|include\(|require\(

# 反序列化通用
readObject|deserialize|parseObject|unserialize|pickle\.load|yaml\.load
```

---

## AuditLuma Pattern Library

> 参考: AuditLuma 代码审计工具 (Python实现)
> 包含数据流分析、假阳性过滤、净化规则等高级特性

### Python Taint Source Patterns (正则匹配)

```python
# 用户输入源
user_input = [
    r'request\.',           # Flask/Django request
    r'input\s*\(',          # input()函数
    r'sys\.argv',           # 命令行参数
    r'os\.environ',         # 环境变量
    r'form\.',              # 表单数据
    r'args\.',              # URL参数
    r'cookies\.',           # Cookie
    r'headers\.',           # HTTP头
]

# 文件输入源
file_input = [
    r'open\s*\(',           # 文件打开
    r'read\s*\(',           # 读取操作
    r'csv\.reader',         # CSV读取
    r'json\.load',          # JSON读取
]

# 网络输入源
network_input = [
    r'requests\.',          # requests库
    r'urllib\.',            # urllib库
    r'socket\.',            # socket
    r'http\.',              # http库
]
```

### Python Sink Patterns (正则匹配)

```python
# SQL查询
sql_query = [
    r'execute\s*\(',        # 执行SQL
    r'query\s*\(',          # 查询
    r'cursor\.',            # 游标操作
    r'SELECT\s+.*FROM',     # SELECT语句
    r'INSERT\s+INTO',       # INSERT语句
    r'UPDATE\s+.*SET',      # UPDATE语句
    r'DELETE\s+FROM',       # DELETE语句
]

# 命令执行
command_exec = [
    r'os\.system\s*\(',     # os.system
    r'subprocess\.',        # subprocess模块
    r'eval\s*\(',           # eval
    r'exec\s*\(',           # exec
    r'shell=True',          # shell=True参数
]

# 文件写入
file_write = [
    r'write\s*\(',          # 写入
    r'writelines\s*\(',     # 写入多行
]

# 模板渲染
template_render = [
    r'render\s*\(',         # render函数
    r'template\.',          # 模板对象
    r'jinja',               # Jinja模板
]

# 响应输出
response_output = [
    r'response\.',          # response对象
    r'jsonify\s*\(',        # jsonify
    r'return\s+.*Response', # 返回Response
]
```

### Sanitization Rules (净化规则)

| 净化函数 | 有效性评分 | 适用场景 |
|----------|------------|----------|
| `html.escape` | 0.9 | XSS防护 |
| `urllib.parse.quote` | 0.8 | URL编码 |
| `bleach.clean` | 0.95 | HTML净化 |
| `validate_input` | 0.7 | 通用验证 |
| `sanitize_sql` | 0.9 | SQL净化 |
| `escape_shell` | 0.8 | 命令转义 |

### Sanitization Keywords (净化关键词)

```python
sanitization_keywords = [
    'escape',        # 转义
    'sanitize',      # 净化
    'clean',         # 清理
    'validate',      # 验证
    'filter',        # 过滤
    'quote',         # 引用
    'encode',        # 编码
    'htmlentities',  # HTML实体
    'htmlspecialchars', # PHP特殊字符
    'strip_tags',    # 移除标签
    'bleach',        # bleach库
    'purify',        # 净化
]
```

### Protection Indicators (保护措施标识)

> 用于假阳性过滤，检测代码中的安全保护措施

```python
protection_indicators = [
    'validate',      # 验证
    'sanitize',      # 净化
    'escape',        # 转义
    'filter',        # 过滤
    'check',         # 检查
    'verify',        # 校验
    'authenticate',  # 认证
    'authorize',     # 授权
    'permission',    # 权限
    'csrf',          # CSRF保护
    'xss_clean',     # XSS清理
    'sql_escape',    # SQL转义
    'prepared_statement',    # 预处理语句
    'parameterized_query',   # 参数化查询
]
```

### CWE to Sink Type Mapping

| Sink类型 | CWE编号 | 漏洞类型 |
|----------|---------|----------|
| sql_query | CWE-89 | SQL Injection |
| command_exec | CWE-78 | Command Injection |
| file_write | CWE-22 | Path Traversal |
| template_render | CWE-79 | XSS |
| response_output | CWE-79 | XSS |
| ldap_query | CWE-90 | LDAP Injection |
| xpath_query | CWE-643 | XPath Injection |
| xml_parse | CWE-611 | XXE |
| deserialization | CWE-502 | Unsafe Deserialization |

### Taint Propagation Types

| 传播类型 | 描述 | 风险权重 |
|----------|------|----------|
| DIRECT | 直接赋值传播 | +0.1 |
| INDIRECT | 间接传播(通过中间变量) | +0.08 |
| CONDITIONAL | 条件分支传播 | +0.05 |
| LOOP | 循环内传播 | +0.07 |
| RETURN | 函数返回值传播 | +0.12 |
| PARAMETER | 函数参数传播 | +0.15 |

### False Positive Filter Rules

#### 文件路径过滤

```python
# 测试文件
test_file_patterns = [
    r'test[s]?[/\\]',       # test/ tests/
    r'[/\\]test[s]?[/\\]',  # /test/ /tests/
    r'\.test\.',            # .test.
    r'_test\.',             # _test.
    r'spec[s]?[/\\]',       # spec/ specs/
    r'mock[s]?[/\\]',       # mock/ mocks/
    r'fixture[s]?[/\\]',    # fixture/ fixtures/
]

# 示例代码
example_patterns = [
    r'example[s]?[/\\]',    # example/ examples/
    r'demo[s]?[/\\]',       # demo/ demos/
    r'sample[s]?[/\\]',     # sample/ samples/
    r'tutorial[s]?[/\\]',   # tutorial/ tutorials/
    r'playground[/\\]',     # playground/
]

# 文档
documentation_patterns = [
    r'doc[s]?[/\\]',        # doc/ docs/
    r'readme',              # readme
    r'\.md$',               # .md
    r'\.rst$',              # .rst
    r'changelog',           # changelog
    r'license',             # license
]
```

#### 占位符内容过滤

```python
placeholder_patterns = [
    r'<placeholder>',       # 占位符标签
    r'\{\{.*\}\}',          # Mustache模板
    r'\$\{.*\}',            # 模板变量
    r'example\.com',        # 示例域名
    r'localhost',           # 本地地址
    r'127\.0\.0\.1',        # 回环地址
    r'TODO',                # TODO标记
    r'FIXME',               # FIXME标记
    r'XXX',                 # XXX标记
]
```

---

## Fenrir Audit Methodology

> 参考: Fenrir-CodeAuditTool 代码审计指南
> 结合OWASP、腾讯安全指南等业界最佳实践

### 漏洞类型清单

| 漏洞类型 | 英文名 | 严重程度 |
|----------|--------|----------|
| 账户接管 | Account Takeover | Critical |
| 跨站脚本 | XSS | High |
| SQL注入 | SQL Injection | Critical |
| 命令注入 | Command Injection | Critical |
| 跨域资源共享 | CORS | Medium |
| 跨站请求伪造 | CSRF | Medium |
| 服务端请求伪造 | SSRF | High |
| 服务端模板注入 | SSTI | High |
| XPath注入 | XPath Injection | High |
| XML外部实体 | XXE | High |
| 路径遍历 | Path Traversal | High |
| 业务逻辑绕过 | Business Logic Bypass | Medium-High |
| WAF绕过 | WAF Bypass | Medium |
| 竞争条件 | Race Condition | Medium |

### Spring Boot 审计要点

```markdown
1. 解析项目结构，列出主要模块及职责
2. 识别敏感路径：
   - 登录/认证模块
   - 文件操作模块
   - 外部调用模块
3. 定位高危API使用位置：
   - 反射调用
   - 序列化/反序列化
   - 文件读写
   - 外部HTTP请求
4. 按OWASP Top 10提取漏洞点
5. 输出按严重级别排序的审计报告
```

### 审计资源引用

| 资源 | 用途 |
|------|------|
| [HackTricks](https://book.hacktricks.xyz/) | 渗透技术百科 |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payload集合 |
| [Tencent SecGuide](https://github.com/Tencent/secguide) | 腾讯安全编码指南 |
| OWASP Top 10 | 十大Web安全风险 |

---

## Risk Scoring Algorithm

> 基于AuditLuma的风险评分算法

### 评分因素

```python
# 基础风险分
base_risk = 0.5

# 路径长度因素 (路径越长风险越高)
length_factor = min(1.0, path_length / 10.0) * 0.2

# 传播类型因素
propagation_weights = {
    'DIRECT': 0.1,
    'PARAMETER': 0.15,
    'RETURN': 0.12,
    'CONDITIONAL': 0.05,
    'LOOP': 0.07,
    'INDIRECT': 0.08
}

# 净化因素 (每个净化点降低20%)
sanitization_factor = 1.0 - (sanitization_count * 0.2)

# 漏洞严重程度因素
severity_bonus = {
    'critical': 0.2,
    'high': 0.15,
    'medium': 0.1,
    'low': 0.05
}
```

### 风险等级判定

| 风险分数 | 污点等级 | 建议处理 |
|----------|----------|----------|
| ≥ 0.8 | DANGEROUS | 立即修复 |
| 0.6 - 0.8 | TAINTED | 高优先级修复 |
| 0.4 - 0.6 | PARTIALLY_SANITIZED | 评估后修复 |
| < 0.4 | SAFE | 持续监控 |

---

## Java Deserialization Gadget Chain Detection

> 专门用于检测 Java 反序列化 Gadget Chain 的中间节点

### Gadget Chain 中间节点分类

#### 1. Transformer 类 (Commons Collections)

```java
// 危险的 Transformer 实现
org.apache.commons.collections.functors.InvokerTransformer
org.apache.commons.collections.functors.ChainedTransformer
org.apache.commons.collections.functors.ConstantTransformer
org.apache.commons.collections.functors.InstantiateTransformer
org.apache.commons.collections4.functors.InvokerTransformer
org.apache.commons.collections4.functors.ChainedTransformer

// 触发点
org.apache.commons.collections.map.LazyMap.get()
org.apache.commons.collections.map.TransformedMap.checkSetValue()
org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
org.apache.commons.collections.bag.TreeBag.compare()
org.apache.commons.collections.comparators.TransformingComparator.compare()
```

**检测规则**:
```regex
# 检测 Transformer 构造
(Invoker|Chained|Constant|Instantiate)Transformer\s*\(
ChainedTransformer.*new\s+Transformer\[\]

# 检测 LazyMap 使用
LazyMap\.decorate\(
LazyMap\.get\(

# 检测 TiedMapEntry
TiedMapEntry\s*\(.*Map
TiedMapEntry\.getValue\(
TiedMapEntry\.hashCode\(
```

---

#### 2. TemplatesImpl 字节码加载

```java
// 关键类
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet

// 触发方法
TemplatesImpl.newTransformer()
TemplatesImpl.getOutputProperties()
TemplatesImpl.getTransletInstance()
TemplatesImpl.defineTransletClasses()

// 字段设置
TemplatesImpl._bytecodes
TemplatesImpl._name
TemplatesImpl._tfactory
TemplatesImpl._class
```

**检测规则**:
```regex
# 检测 TemplatesImpl 使用
TemplatesImpl\s*\(\)
new\s+TemplatesImpl\(

# 检测字段赋值
_bytecodes\s*=
_tfactory\s*=
setFieldValue.*"_bytecodes"

# 检测触发方法
\.newTransformer\(\)
\.getOutputProperties\(\)
\.getTransletInstance\(\)

# 检测恶意类继承
extends\s+AbstractTranslet
AbstractTranslet
```

---

#### 3. BeanComparator & PropertyUtils (Commons Beanutils)

```java
// 关键类
org.apache.commons.beanutils.BeanComparator
org.apache.commons.beanutils.PropertyUtils

// 触发方法
BeanComparator.compare()
PropertyUtils.getProperty()
PropertyUtils.getSimpleProperty()

// 配合使用
java.util.PriorityQueue
```

**检测规则**:
```regex
# 检测 BeanComparator
BeanComparator\s*\(
new\s+BeanComparator

# 检测 PropertyUtils
PropertyUtils\.getProperty\(
PropertyUtils\.getSimpleProperty\(

# 检测配合 PriorityQueue
PriorityQueue.*BeanComparator
PriorityQueue.*Comparator
```

---

#### 4. Spring 反射工具链

```java
// 关键类
org.springframework.core.SerializableTypeWrapper
org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider
org.springframework.core.SerializableTypeWrapper$TypeProvider
org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler
org.springframework.util.ReflectionUtils

// 触发方法
SerializableTypeWrapper.TypeProvider.getType()
ReflectionUtils.invokeMethod()
ReflectionUtils.findMethod()
ObjectFactoryDelegatingInvocationHandler.invoke()
```

**检测规则**:
```regex
# 检测 Spring 反序列化类
SerializableTypeWrapper
MethodInvokeTypeProvider
TypeProvider.*getType

# 检测 Spring 反射工具
ReflectionUtils\.invokeMethod\(
ReflectionUtils\.findMethod\(

# 检测 ObjectFactory
ObjectFactory.*getObject
ObjectFactoryDelegatingInvocationHandler
AutowireUtils
```

---

#### 5. C3P0 JNDI 注入链

```java
// 关键类
com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase
com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized
com.mchange.v2.c3p0.WrapperConnectionPoolDataSource
com.mchange.v2.c3p0.JndiRefForwardingDataSource

// 触发方法
PoolBackedDataSourceBase.readObject()
ReferenceIndirector$ReferenceSerialized.getObject()
ReferenceableUtils.referenceToObject()

// JNDI 调用
javax.naming.InitialContext.lookup()
javax.naming.spi.NamingManager.getObjectInstance()
```

**检测规则**:
```regex
# 检测 C3P0 类
PoolBackedDataSource
WrapperConnectionPoolDataSource
JndiRefForwardingDataSource

# 检测 Reference 相关
Reference(Indirector|able|Serialized)
ReferenceableUtils

# 检测 connectionPoolDataSource 设置
connectionPoolDataSource\s*=
setConnectionPoolDataSource\(

# 检测 JNDI lookup
InitialContext.*lookup\(
NamingManager\.getObjectInstance\(
```

---

#### 6. ROME ToStringBean 链

```java
// 关键类
com.sun.syndication.feed.impl.ToStringBean
com.sun.syndication.feed.impl.EqualsBean
com.sun.syndication.feed.impl.ObjectBean
com.rometools.rome.feed.impl.ToStringBean (新版本)

// 触发方法
ToStringBean.toString()
EqualsBean.hashCode()
EqualsBean.equals()
ObjectBean.toString()
```

**检测规则**:
```regex
# 检测 ROME 类
(ToStringBean|EqualsBean|ObjectBean)
com\.sun\.syndication
com\.rometools\.rome

# 检测 toString 链
ToStringBean\.toString\(
EqualsBean\.hashCode\(

# 检测配合 HashMap
HashMap.*EqualsBean
HashMap.*ObjectBean
```

---

#### 7. Fastjson 利用链

```java
// 关键方法
com.alibaba.fastjson.JSON.parse()
com.alibaba.fastjson.JSON.parseObject()
com.alibaba.fastjson.parser.ParserConfig.checkAutoType()

// 常见利用类
com.sun.rowset.JdbcRowSetImpl
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
org.apache.tomcat.dbcp.dbcp.BasicDataSource
com.mchange.v2.c3p0.JndiRefForwardingDataSource

// 关键配置
ParserConfig.setAutoTypeSupport(true)
Feature.SupportAutoType
```

**检测规则**:
```regex
# 检测 Fastjson 解析
JSON\.(parse|parseObject)\(
JSONObject\.parse(Object)?\(

# 检测 @type 指令
@type["']?\s*:\s*["']

# 检测危险配置
autoTypeSupport\s*=\s*true
Feature\.SupportAutoType
ParserConfig\.getGlobalInstance

# 检测利用类
JdbcRowSetImpl
dataSourceName\s*=
autoCommit\s*=
```

---

#### 8. Jackson 反序列化链

```java
// 关键配置
com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping()

// 注解
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)

// 利用类
com.sun.rowset.JdbcRowSetImpl
org.springframework.context.support.ClassPathXmlApplicationContext
ch.qos.logback.core.db.JNDIConnectionSource
```

**检测规则**:
```regex
# 检测危险配置
enableDefaultTyping\(\)
ObjectMapper\.enableDefaultTyping

# 检测类型注解
@JsonTypeInfo.*Id\.CLASS
@JsonTypeInfo.*MINIMAL_CLASS

# 检测类型字段
\["@class"\]
\["@c"\]
```

---

#### 9. SnakeYAML 利用链

```java
// 关键类
org.yaml.snakeyaml.Yaml

// 危险方法
Yaml.load()
Yaml.loadAs()
Yaml.loadAll()

// 利用类型标签
!!javax.script.ScriptEngineManager
!!java.net.URLClassLoader
!!com.sun.rowset.JdbcRowSetImpl
```

**检测规则**:
```regex
# 检测 YAML 加载
Yaml\.load(As|All)?\(
new\s+Yaml\(\)\.load

# 检测类型标签
!!java\.
!!javax\.
!!com\.sun\.

# 检测危险类
ScriptEngineManager
URLClassLoader
JdbcRowSetImpl
```

---

### Gadget Chain 检测流程

```yaml
gadget_detection_workflow:
  1_identify_entry:
    - "检测反序列化入口: ObjectInputStream.readObject()"
    - "检测 JSON 解析: JSON.parse(), XStream.fromXML()"
  
  2_trace_path:
    - "追踪从入口到 Transformer/BeanComparator 的路径"
    - "识别 HashMap/PriorityQueue/HashSet 等触发容器"
  
  3_identify_gadget:
    - "匹配已知 Gadget 模式 (CC1-CC13, CB1, Spring1, etc.)"
    - "检测关键中间类: InvokerTransformer, LazyMap, TiedMapEntry"
  
  4_verify_sink:
    - "确认最终 Sink: Runtime.exec(), TemplatesImpl.newTransformer()"
    - "确认 JNDI 注入: InitialContext.lookup()"
  
  5_assess_exploitability:
    - "检查依赖版本是否匹配"
    - "检查 JDK 版本限制"
    - "验证完整调用链可达性"
```

---

### 复合检测规则示例

```bash
# 检测 CC1 Gadget Chain
grep -rn "InvokerTransformer" --include="*.java" | \
  xargs -I {} grep -l "LazyMap" {} | \
  xargs -I {} grep -l "AnnotationInvocationHandler" {}

# 检测 TemplatesImpl 利用
grep -rn "_bytecodes" --include="*.java" | \
  xargs -I {} grep -l "newTransformer" {}

# 检测 C3P0 JNDI
grep -rn "PoolBackedDataSource" --include="*.java" | \
  xargs -I {} grep -l "connectionPoolDataSource" {}

# 检测 Fastjson @type
grep -rn "@type" --include="*.json" | \
  grep -E "(JdbcRowSetImpl|TemplatesImpl|BasicDataSource)"
```

---

### Gadget Chain 特征库

| Gadget | 关键类 | 关键方法 | 触发容器 |
|--------|--------|----------|----------|
| CC1 | InvokerTransformer, LazyMap | LazyMap.get() | AnnotationInvocationHandler |
| CC2 | InvokerTransformer, TemplatesImpl | TransformingComparator.compare() | PriorityQueue |
| CC3 | InvokerTransformer, TemplatesImpl | LazyMap.get() | AnnotationInvocationHandler |
| CC5 | TiedMapEntry, LazyMap | TiedMapEntry.toString() | BadAttributeValueExpException |
| CC6 | TiedMapEntry, LazyMap | TiedMapEntry.hashCode() | HashMap/HashSet |
| CC7 | LazyMap | AbstractMap.equals() | Hashtable |
| CB1 | BeanComparator, TemplatesImpl | BeanComparator.compare() | PriorityQueue |
| Spring1 | TypeProvider, TemplatesImpl | TypeProvider.getType() | MethodInvokeTypeProvider |
| C3P0 | PoolBackedDataSource | ReferenceIndirector.getObject() | PoolBackedDataSourceBase |
| ROME | ToStringBean, EqualsBean | ToStringBean.toString() | HashMap |
| Fastjson | @type, JdbcRowSetImpl | JSON.parseObject() | - |

---

**最后更新**: 2024-12-26
**参考**: JYso, ysoserial, marshalsec

