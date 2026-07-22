# .NET/C# Security Audit

> .NET/C# 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: ASP.NET Core, ASP.NET MVC, Blazor, WPF, .NET MAUI

---

## 审计方法论

### 双轨并行框架

```
                    .NET/C# 代码安全审计
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  轨道A (50%)    │ │  轨道B (40%)    │ │  补充 (10%)     │
│  控制建模法     │ │  数据流分析法   │ │  配置+依赖审计  │
│                 │ │                 │ │                 │
│ 缺失类漏洞:     │ │ 注入类漏洞:     │ │ • 硬编码凭据    │
│ • 认证缺失      │ │ • SQL注入       │ │ • appsettings   │
│ • 授权缺失      │ │ • 反序列化      │ │ • NuGet CVE     │
│ • IDOR          │ │ • 命令注入      │ │                 │
│ • 竞态条件      │ │ • SSRF          │ │                 │
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
# ASP.NET Core控制器 - 数据修改操作
grep -rn "\[HttpPost\]\|\[HttpPut\]\|\[HttpDelete\]\|\[HttpPatch\]" --include="*.cs"

# 数据访问操作 (带参数)
grep -rn "\[HttpGet.*{.*}\]" --include="*.cs"

# 批量操作
grep -rn "Export\|Download\|Batch\|Import" --include="*Controller.cs"

# 资金操作
grep -rn "Transfer\|Payment\|Refund\|Balance" --include="*.cs"

# 外部HTTP请求
grep -rn "HttpClient\|WebClient\|GetAsync\|PostAsync" --include="*.cs"

# 文件操作
grep -rn "IFormFile\|FileStream\|File\.Open\|File\.Read\|File\.Write" --include="*.cs"

# 命令执行
grep -rn "Process\.Start\|ProcessStartInfo" --include="*.cs"
```

### 1.2 输出模板

```markdown
## .NET敏感操作清单

| # | 端点/方法 | HTTP方法 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|----------|----------|------|----------|
| 1 | /api/user/{id} | DELETE | 数据修改 | UserController.cs:45 | 高 |
| 2 | /api/user/{id} | GET | 数据访问 | UserController.cs:32 | 中 |
| 3 | /api/transfer | POST | 资金操作 | PaymentController.cs:56 | 严重 |
```

---

## A2. 安全控制建模

### 2.1 .NET安全控制实现方式

| 控制类型 | ASP.NET Core实现 | 检查方法 |
|----------|------------------|----------|
| **认证控制** | `[Authorize]`, `RequireAuthorization()` | 检查属性和策略 |
| **授权控制** | `[Authorize(Roles="Admin")]`, Policy-based | 检查角色/策略 |
| **资源所有权** | `IAuthorizationHandler`, 手动检查 | 检查Handler或代码 |
| **输入验证** | `[Required]`, FluentValidation, DataAnnotations | 检查验证属性 |
| **并发控制** | EF Core `RowVersion`, `IsolationLevel` | 检查事务配置 |
| **审计日志** | Serilog, ILogger, AuditLog中间件 | 检查日志配置 |

### 2.2 控制矩阵模板 (.NET)

```yaml
敏感操作: DELETE /api/user/{id}
位置: UserController.cs:45
类型: 数据修改

应有控制:
  认证控制:
    要求: 必须登录
    实现: [Authorize] 属性

  授权控制:
    要求: 管理员或本人
    实现: [Authorize(Roles = "Admin")] 或 Policy

  资源所有权:
    要求: 非管理员只能删除自己的数据
    验证: user.Id == resource.OwnerId
```

---

## A3. 控制存在性验证

### 3.1 数据修改操作验证清单

```markdown
## 控制验证: [端点名称]

| 控制项 | 应有 | ASP.NET Core实现 | 结果 |
|--------|------|------------------|------|
| 认证控制 | 必须 | [Authorize] | ✅/❌ |
| 授权控制 | 必须 | [Authorize(Roles/Policy)] | ✅/❌ |
| 资源所有权 | 必须 | IAuthorizationHandler | ✅/❌ |
| 输入验证 | 必须 | [Required], FluentValidation | ✅/❌ |

### 验证命令
```bash
# 检查认证授权属性
grep -B 3 "\[HttpDelete\]\|\[HttpPost\]" [Controller文件] | grep "\[Authorize"

# 检查资源所有权
grep -A 20 "public.*Delete\|public.*Update" [Controller文件] | grep "OwnerId\|UserId"
```
```

### 3.2 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | .NET检测方法 |
|----------|----------|-----|--------------|
| 无[Authorize] | 认证缺失 | CWE-306 | 检查Controller属性 |
| 无Roles/Policy | 授权缺失 | CWE-862 | 检查授权配置 |
| 无OwnerId检查 | IDOR | CWE-639 | 检查查询条件 |
| 无RowVersion | 竞态条件 | CWE-362 | 检查并发控制 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞

## B1. .NET Source

```csharp
// ASP.NET Core
Request.Query["name"]
Request.Form["name"]
Request.Headers["X-Header"]
Request.Cookies["session"]
[FromBody] object body
[FromQuery] string param
```

## B2. .NET Sink

| Sink类型 | 漏洞 | CWE | 危险函数 |
|----------|------|-----|----------|
| 反序列化 | RCE | 502 | BinaryFormatter, TypeNameHandling |
| SQL执行 | SQL注入 | 89 | SqlCommand, FromSqlRaw |
| 命令执行 | 命令注入 | 78 | Process.Start |
| 文件操作 | 路径遍历 | 22 | File.Open, FileStream |
| HTTP请求 | SSRF | 918 | HttpClient |

## B3. Sink检测命令

## 识别特征

```csharp
// .NET 项目识别
*.csproj, *.sln, *.cs
packages.config, Directory.Build.props

// 文件结构
├── Program.cs / Startup.cs
├── Controllers/
├── Models/
├── Services/
├── wwwroot/
└── appsettings.json
```

---

## 一键检测命令

### 反序列化

```bash
# BinaryFormatter (高危 - 已废弃)
grep -rn "BinaryFormatter\|SoapFormatter\|NetDataContractSerializer\|ObjectStateFormatter" --include="*.cs"

# JSON 反序列化
grep -rn "TypeNameHandling\|JsonSerializerSettings\|TypeNameAssemblyFormat" --include="*.cs"

# XML 反序列化
grep -rn "XmlSerializer\|DataContractSerializer\|XamlReader\.Load" --include="*.cs"

# ViewState (ASP.NET WebForms)
grep -rn "LosFormatter\|ObjectStateFormatter\|ViewState" --include="*.cs" --include="*.aspx"
```

### SQL 注入

```bash
# 原生 SQL
grep -rn "SqlCommand\|ExecuteReader\|ExecuteNonQuery\|ExecuteScalar" --include="*.cs"
grep -rn "FromSqlRaw\|FromSqlInterpolated\|ExecuteSqlRaw" --include="*.cs"

# 动态 SQL 拼接
grep -rn "string\.Format.*SELECT\|\\$\".*SELECT\|\+ \".*WHERE" --include="*.cs"

# Dapper
grep -rn "Query<\|Execute(" --include="*.cs"
```

### 命令执行

```bash
grep -rn "Process\.Start\|ProcessStartInfo\|cmd\.exe\|/bin/bash" --include="*.cs"
grep -rn "PowerShell\|Invoke-Expression" --include="*.cs"
```

### 路径遍历

```bash
grep -rn "Path\.Combine\|File\.Open\|File\.Read\|File\.Write\|FileStream" --include="*.cs"
grep -rn "IFormFile\|SaveAs\|CopyTo" --include="*.cs"
```

### SSRF

```bash
grep -rn "HttpClient\|WebClient\|WebRequest\|HttpWebRequest" --include="*.cs"
grep -rn "GetAsync\|PostAsync\|SendAsync" --include="*.cs"
```

---

## .NET 特定漏洞

### 1. 反序列化 RCE (严重)

```csharp
// 🔴 BinaryFormatter - 极度危险，.NET 5+ 已废弃
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);  // RCE!

// 🔴 TypeNameHandling - Newtonsoft.Json
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // 危险!
};
JsonConvert.DeserializeObject(json, settings);

// 🔴 DataContractSerializer 配置不当
var serializer = new DataContractSerializer(typeof(object));  // 多态危险

// 🔴 XamlReader
XamlReader.Load(stream);  // 可执行任意代码

// 搜索模式
BinaryFormatter|TypeNameHandling\.All|TypeNameHandling\.Auto|TypeNameHandling\.Objects
NetDataContractSerializer|LosFormatter|ObjectStateFormatter|XamlReader\.Load
```

**Gadget Chains**:
```
ysoserial.net 支持的 Gadget:
- TypeConfuseDelegate
- TextFormattingRunProperties
- WindowsIdentity
- ClaimsPrincipal
- PSObject (PowerShell)
- ActivitySurrogateSelector
- ObjectDataProvider
```

### 2. ViewState 反序列化 (ASP.NET WebForms)

```csharp
// 🔴 ViewState 未加密或密钥泄露
<%@ Page EnableViewStateMac="false" %>  // 危险配置

// machineKey 泄露场景
// web.config 中的 machineKey 被泄露后可伪造 ViewState

// 检测命令
grep -rn "machineKey\|validationKey\|decryptionKey" --include="*.config"
grep -rn "EnableViewStateMac\s*=\s*[\"']?false" --include="*.aspx"
```

### 3. SQL 注入

```csharp
// 🔴 字符串拼接
string query = "SELECT * FROM Users WHERE Name = '" + userName + "'";
SqlCommand cmd = new SqlCommand(query, conn);

// 🔴 string.Format
string query = string.Format("SELECT * FROM Users WHERE Id = {0}", id);

// 🔴 插值字符串直接用于 SQL
string query = $"SELECT * FROM Users WHERE Name = '{name}'";

// 🔴 FromSqlRaw 不安全用法
var users = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'");

// 🟢 安全: 参数化查询
string query = "SELECT * FROM Users WHERE Name = @Name";
cmd.Parameters.AddWithValue("@Name", userName);

// 🟢 安全: FromSqlInterpolated (会自动参数化)
var users = context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");

// 搜索高危模式
grep -rn "FromSqlRaw\s*\(\s*\$\|FromSqlRaw\s*\(\s*string\.Format" --include="*.cs"
```

### 4. LDAP 注入

```csharp
// 🔴 危险
string filter = "(uid=" + username + ")";
DirectorySearcher searcher = new DirectorySearcher(filter);

// 🟢 安全: 转义特殊字符
string safeUsername = username.Replace("\\", "\\5c")
                              .Replace("*", "\\2a")
                              .Replace("(", "\\28")
                              .Replace(")", "\\29")
                              .Replace("\0", "\\00");
```

### 5. 命令执行

```csharp
// 🔴 危险
Process.Start("cmd.exe", "/c " + userInput);
Process.Start(userInput);

// 🔴 PowerShell
using (PowerShell ps = PowerShell.Create()) {
    ps.AddScript(userScript);  // RCE!
    ps.Invoke();
}

// 搜索模式
Process\.Start|ProcessStartInfo|cmd\.exe|/bin/bash|PowerShell\.Create
```

### 6. 路径遍历

```csharp
// 🔴 危险
string path = Path.Combine(basePath, userInput);  // ../../../etc/passwd
File.ReadAllText(path);

// 🔴 文件上传
file.SaveAs(Path.Combine(uploadPath, file.FileName));  // FileName 可能包含 ../

// 🟢 安全: 验证路径
string fullPath = Path.GetFullPath(Path.Combine(basePath, userInput));
if (!fullPath.StartsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}

// 🟢 安全: 文件上传
string safeFileName = Path.GetFileName(file.FileName);  // 去除路径
```

### 7. XXE (XML External Entity)

```csharp
// 🔴 危险 (.NET Framework 4.5.2 之前默认不安全)
XmlDocument doc = new XmlDocument();
doc.Load(userInput);  // XXE!

XmlTextReader reader = new XmlTextReader(stream);  // 默认启用 DTD

// 🟢 安全: 禁用 DTD
XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
XmlReader reader = XmlReader.Create(stream, settings);

// 搜索模式
XmlDocument|XmlTextReader|XmlReader\.Create.*DtdProcessing\.Parse
```

### 8. SSRF

```csharp
// 🔴 危险
HttpClient client = new HttpClient();
var response = await client.GetAsync(userUrl);

WebClient wc = new WebClient();
string content = wc.DownloadString(userUrl);

// 检测内网访问
// 127.0.0.1, localhost, 10.x.x.x, 172.16-31.x.x, 192.168.x.x
// 云元数据: 169.254.169.254

// 搜索模式
HttpClient|WebClient|WebRequest|HttpWebRequest.*用户输入
```

### 9. 开放重定向

```csharp
// 🔴 危险
return Redirect(returnUrl);
Response.Redirect(url);

// 🟢 安全: 验证 URL
if (Url.IsLocalUrl(returnUrl)) {
    return Redirect(returnUrl);
}

// 搜索模式
Redirect\(|RedirectToAction.*url|Response\.Redirect
```

### 10. XSS

```csharp
// 🔴 Razor 中使用 @Html.Raw
@Html.Raw(userInput)  // XSS!

// 🔴 JavaScript 中直接输出
<script>var data = '@Model.UserData';</script>

// 🟢 安全: 使用编码
@Html.Encode(userInput)
@System.Web.HttpUtility.JavaScriptStringEncode(data)

// 搜索模式
Html\.Raw|Response\.Write(?!.*Encode)
```

### 11. 不安全的随机数

```csharp
// 🔴 危险: 可预测
Random rng = new Random();
int token = rng.Next();

// 🟢 安全: 密码学安全随机数
using (var rng = RandomNumberGenerator.Create()) {
    byte[] data = new byte[32];
    rng.GetBytes(data);
}

// 搜索模式
new Random\(\)|Random\.Next
```

### 12. 硬编码凭据

```csharp
// 🔴 危险
string connectionString = "Server=db;User=admin;Password=secret123";
string apiKey = "sk-1234567890abcdef";

// 搜索模式
password\s*=\s*[\"'][^\"']+[\"']|apikey\s*=\s*[\"']|secret\s*=\s*[\"']
```

---

## ASP.NET Core 特定漏洞

### 1. 中间件顺序错误

```csharp
// 🔴 错误顺序导致鉴权绕过
var app = builder.Build();
app.MapControllers();  // 先映射路由
app.UseAuthentication();  // 后鉴权 = 绕过!
app.UseAuthorization();

// 🟢 正确顺序
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
```

### 2. CORS 配置不当

```csharp
// 🔴 过宽的 CORS
builder.Services.AddCors(options => {
    options.AddPolicy("any", policy => {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();  // 与 AllowAnyOrigin 冲突!
    });
});

// 🔴 动态 Origin 反射
policy.SetIsOriginAllowed(origin => true);

// 搜索模式
AllowAnyOrigin|SetIsOriginAllowed.*true|AllowCredentials
```

### 3. 授权绕过

```csharp
// 🔴 AllowAnonymous 误用
[AllowAnonymous]  // 允许匿名访问管理接口!
[HttpGet("admin/users")]
public IActionResult GetUsers() { ... }

// 🔴 Minimal API 未授权
app.MapGet("/admin/secrets", () => GetSecrets());  // 无 RequireAuthorization

// 🟢 安全
app.MapGet("/admin/secrets", () => GetSecrets())
   .RequireAuthorization("AdminPolicy");

// 搜索模式
\[AllowAnonymous\]|MapGet\(.*(?!RequireAuthorization)
```

### 4. SignalR 安全

```csharp
// 🔴 Hub 未鉴权
[AllowAnonymous]
public class ChatHub : Hub {
    public async Task SendMessage(string user, string message) { ... }
}

// 🔴 未验证连接用户
public override Task OnConnectedAsync() {
    Groups.AddToGroupAsync(Context.ConnectionId, groupName);  // groupName 可控
}

// 🟢 安全: 使用授权
[Authorize]
public class ChatHub : Hub { ... }

// 搜索模式
: Hub|MapHub|HubConnection
```

### 5. Blazor 安全

```csharp
// 🔴 Blazor Server 组件中的敏感操作
// 客户端可以通过 SignalR 直接调用任何公共方法

[Parameter]
public string UserId { get; set; }  // 客户端可篡改

// 🟢 安全: 服务端验证
var userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

// 🔴 Blazor WASM 中的敏感逻辑
// 所有代码都在客户端运行，可被反编译
```

### 6. 请求伪造保护

```csharp
// 🔴 CSRF 保护缺失
[HttpPost]
[IgnoreAntiforgeryToken]  // 禁用 CSRF 保护
public IActionResult Transfer() { ... }

// 🔴 API 缺少 CSRF
// SPA 调用的 API 需要额外的 CSRF 保护机制

// 搜索模式
IgnoreAntiforgeryToken|ValidateAntiForgeryToken.*=\s*false
```

---

## Entity Framework 安全

### 1. EF Core 注入

```csharp
// 🔴 FromSqlRaw 字符串拼接
var users = context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'")
    .ToList();

// 🔴 ExecuteSqlRaw
context.Database.ExecuteSqlRaw($"DELETE FROM Users WHERE Id = {id}");

// 🟢 安全: 参数化
var users = context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Name = {0}", name)
    .ToList();

// 🟢 安全: FromSqlInterpolated
var users = context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}")
    .ToList();
```

### 2. 敏感数据泄露

```csharp
// 🔴 返回整个实体（包含敏感字段）
return Ok(await context.Users.ToListAsync());

// 🟢 安全: 使用 DTO
return Ok(await context.Users.Select(u => new UserDto {
    Id = u.Id,
    Name = u.Name
    // 不包含 PasswordHash 等敏感字段
}).ToListAsync());
```

---

## 配置安全

### 1. appsettings.json 敏感信息

```json
// 🔴 危险: 敏感信息明文
{
  "ConnectionStrings": {
    "Default": "Server=db;User=admin;Password=secret123"
  },
  "ApiKeys": {
    "Payment": "sk_live_xxx"
  }
}

// 🟢 安全: 使用 Secret Manager 或环境变量
// dotnet user-secrets set "ApiKeys:Payment" "sk_live_xxx"
```

### 2. 调试配置

```csharp
// 🔴 生产环境开启详细错误
if (env.IsDevelopment()) {
    app.UseDeveloperExceptionPage();
} else {
    app.UseDeveloperExceptionPage();  // 错误！生产也开启了
}

// 🔴 Swagger 生产环境暴露
app.UseSwagger();
app.UseSwaggerUI();  // 应该只在开发环境

// 搜索模式
UseDeveloperExceptionPage|UseSwagger
```

---

## 审计清单

```
反序列化:
- [ ] 搜索 BinaryFormatter/TypeNameHandling
- [ ] 检查 ViewState 配置 (WebForms)
- [ ] 验证 JSON 序列化设置

注入类:
- [ ] 搜索 FromSqlRaw 字符串拼接
- [ ] 检查原生 SQL 命令
- [ ] 验证 LDAP 查询构造
- [ ] 搜索 Process.Start

文件操作:
- [ ] 检查 Path.Combine 用法
- [ ] 验证文件上传处理
- [ ] 检查 XXE 防护

认证授权:
- [ ] 验证中间件顺序
- [ ] 检查 AllowAnonymous 使用
- [ ] 验证 SignalR Hub 授权
- [ ] 检查 CORS 配置

配置安全:
- [ ] 检查 appsettings.json 敏感信息
- [ ] 验证生产环境配置
- [ ] 检查 machineKey (WebForms)
```

---

## 审计正则

```regex
# 反序列化
BinaryFormatter|TypeNameHandling\.(All|Auto|Objects)|NetDataContractSerializer
LosFormatter|ObjectStateFormatter|XamlReader\.Load|DataContractSerializer

# SQL 注入
FromSqlRaw\s*\(\s*(\$|string\.Format)|ExecuteSqlRaw\s*\(\s*\$
SqlCommand.*\+|"SELECT.*\+.*"

# 命令执行
Process\.Start|ProcessStartInfo|PowerShell\.Create

# 路径遍历
Path\.Combine.*用户输入|File\.(Read|Write|Open)

# XSS
Html\.Raw|Response\.Write(?!.*Encode)

# 配置问题
AllowAnyOrigin|AllowAnonymous|IgnoreAntiforgeryToken
UseDeveloperExceptionPage
```

---

## 工具推荐

```bash
# Security Code Scan (静态分析)
dotnet add package SecurityCodeScan.VS2019

# .NET 依赖漏洞检查
dotnet list package --vulnerable

# Snyk
snyk test --file=project.csproj
```

---

## 竞态条件 (CWE-362)

### 危险模式

```csharp
// 1. Check-Then-Act (TOCTOU)
// 危险: 检查与操作之间存在竞态窗口
public class VulnerableTransfer
{
    private Dictionary<string, decimal> _balances = new();

    public bool Transfer(string from, string to, decimal amount)
    {
        if (_balances[from] >= amount)  // 检查
        {
            // 竞态窗口
            _balances[from] -= amount;   // 操作
            _balances[to] += amount;
            return true;
        }
        return false;
    }
}

// 安全: 使用锁
public class SafeTransfer
{
    private readonly ConcurrentDictionary<string, decimal> _balances = new();
    private readonly object _lock = new();

    public bool Transfer(string from, string to, decimal amount)
    {
        lock (_lock)
        {
            if (_balances[from] >= amount)
            {
                _balances[from] -= amount;
                _balances[to] += amount;
                return true;
            }
            return false;
        }
    }
}

// 2. 单例双重检查锁定
// 危险: 可能看到部分构造的对象
public class Singleton
{
    private static Singleton _instance;

    public static Singleton Instance
    {
        get
        {
            if (_instance == null)
            {
                lock (typeof(Singleton))
                {
                    if (_instance == null)
                        _instance = new Singleton();
                }
            }
            return _instance;
        }
    }
}

// 安全: 使用 Lazy<T>
public class SafeSingleton
{
    private static readonly Lazy<SafeSingleton> _instance =
        new(() => new SafeSingleton());

    public static SafeSingleton Instance => _instance.Value;
}

// 3. 文件操作竞态
// 危险
public void ProcessFile(string path)
{
    if (File.Exists(path))
    {
        // 竞态窗口: 文件可能被删除或替换
        var content = File.ReadAllText(path);
    }
}

// 安全: 直接尝试，处理异常
public void SafeProcessFile(string path)
{
    try
    {
        var content = File.ReadAllText(path);
    }
    catch (FileNotFoundException)
    {
        // 文件不存在
    }
}
```

### ASP.NET Core 竞态

```csharp
// 危险: 单例服务中的共享状态
public class VulnerableService
{
    private User _currentUser;  // 危险: 所有请求共享

    public void SetUser(User user) => _currentUser = user;
    public void Process() => DoSomething(_currentUser);
}

// 安全: 使用 Scoped 生命周期
services.AddScoped<IScopedService, ScopedService>();

// 或使用 IHttpContextAccessor
public class SafeService
{
    private readonly IHttpContextAccessor _accessor;

    public SafeService(IHttpContextAccessor accessor)
    {
        _accessor = accessor;
    }

    public void Process()
    {
        var user = _accessor.HttpContext?.User;
        DoSomething(user);
    }
}

// 危险: 静态缓存无同步
public static class Cache
{
    private static Dictionary<string, object> _cache = new();

    public static object Get(string key)
    {
        if (!_cache.ContainsKey(key))
        {
            _cache[key] = LoadExpensive(key);  // 竞态
        }
        return _cache[key];
    }
}

// 安全: 使用 ConcurrentDictionary + GetOrAdd
public static class SafeCache
{
    private static readonly ConcurrentDictionary<string, Lazy<object>> _cache = new();

    public static object Get(string key)
    {
        return _cache.GetOrAdd(key, k => new Lazy<object>(() => LoadExpensive(k))).Value;
    }
}
```

### Entity Framework 竞态

```csharp
// 危险: 应用层检查
public async Task CreateUser(string username)
{
    if (!await _context.Users.AnyAsync(u => u.Username == username))
    {
        // 竞态窗口
        _context.Users.Add(new User { Username = username });
        await _context.SaveChangesAsync();
    }
}

// 安全: 数据库唯一约束 + 异常处理
public async Task SafeCreateUser(string username)
{
    try
    {
        _context.Users.Add(new User { Username = username });
        await _context.SaveChangesAsync();
    }
    catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
    {
        throw new UsernameExistsException(username);
    }
}

// 安全: 悲观锁 (使用原生SQL)
public async Task TransferWithLock(int fromId, int toId, decimal amount)
{
    await using var transaction = await _context.Database.BeginTransactionAsync();

    var from = await _context.Accounts
        .FromSqlRaw("SELECT * FROM Accounts WITH (UPDLOCK) WHERE Id = {0}", fromId)
        .FirstAsync();

    var to = await _context.Accounts
        .FromSqlRaw("SELECT * FROM Accounts WITH (UPDLOCK) WHERE Id = {0}", toId)
        .FirstAsync();

    from.Balance -= amount;
    to.Balance += amount;

    await _context.SaveChangesAsync();
    await transaction.CommitAsync();
}

// 安全: 乐观锁 (使用 RowVersion)
public class Account
{
    public int Id { get; set; }
    public decimal Balance { get; set; }

    [Timestamp]
    public byte[] RowVersion { get; set; }  // 乐观锁
}
```

### 检测命令

```bash
# 查找共享可变状态
grep -rn "private static\|private.*=" --include="*.cs" | grep -v "readonly\|const"

# 查找 check-then-act 模式
grep -rn "if.*Exists\|if.*== null" --include="*.cs" -A 3

# 查找非线程安全集合
grep -rn "new Dictionary\|new List\|new HashSet" --include="*.cs" | grep "static"

# 查找双重检查锁定
grep -rn "if.*null.*lock" --include="*.cs"
```

---

## CSRF 防护 (CWE-352)

### ASP.NET Core

```csharp
// Startup.cs - 全局配置
services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// 危险: 缺少验证
[HttpPost]
public IActionResult Delete(int id)
{
    // 无CSRF保护
    _service.Delete(id);
    return Ok();
}

// 安全: 使用 ValidateAntiForgeryToken
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult SafeDelete(int id)
{
    _service.Delete(id);
    return Ok();
}

// 全局过滤器 (推荐)
services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

// API场景: 使用自定义头验证
[HttpPost]
[IgnoreAntiforgeryToken]  // 禁用表单验证
public IActionResult ApiDelete([FromBody] DeleteRequest request)
{
    // 验证自定义头
    if (!Request.Headers.ContainsKey("X-Requested-With"))
    {
        return BadRequest("Missing required header");
    }
    _service.Delete(request.Id);
    return Ok();
}

// Razor Pages 自动保护
@Html.AntiForgeryToken()

// Blazor Server
<EditForm Model="@Model" OnValidSubmit="HandleSubmit">
    <AntiforgeryToken />  <!-- 自动包含 -->
</EditForm>
```

### 检测命令

```bash
# 查找缺少CSRF保护的POST方法
grep -rn "\[HttpPost\]" --include="*.cs" -A 2 | grep -v "ValidateAntiForgeryToken"

# 查找 IgnoreAntiforgeryToken
grep -rn "IgnoreAntiforgeryToken" --include="*.cs"
```

---

## 文件上传安全 (CWE-434)

```csharp
// 危险: 无验证
[HttpPost]
public async Task<IActionResult> Upload(IFormFile file)
{
    var path = Path.Combine(_uploadPath, file.FileName);  // 路径遍历
    await using var stream = new FileStream(path, FileMode.Create);
    await file.CopyToAsync(stream);  // 无类型检查
    return Ok();
}

// 安全: 完整验证
public class SecureUploadService
{
    private readonly string[] _allowedExtensions = { ".jpg", ".jpeg", ".png", ".gif" };
    private readonly string[] _allowedMimeTypes = { "image/jpeg", "image/png", "image/gif" };
    private readonly Dictionary<string, byte[]> _signatures = new()
    {
        { ".jpg", new byte[] { 0xFF, 0xD8, 0xFF } },
        { ".png", new byte[] { 0x89, 0x50, 0x4E, 0x47 } },
        { ".gif", new byte[] { 0x47, 0x49, 0x46 } }
    };
    private const long MaxFileSize = 5 * 1024 * 1024;  // 5MB

    public async Task<string> Upload(IFormFile file)
    {
        // 1. 大小检查
        if (file.Length > MaxFileSize)
            throw new InvalidOperationException("File too large");

        // 2. 扩展名检查
        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!_allowedExtensions.Contains(ext))
            throw new InvalidOperationException("Invalid extension");

        // 3. MIME类型检查
        if (!_allowedMimeTypes.Contains(file.ContentType))
            throw new InvalidOperationException("Invalid content type");

        // 4. 魔数验证
        using var reader = new BinaryReader(file.OpenReadStream());
        var headerBytes = reader.ReadBytes(_signatures[ext].Length);
        if (!headerBytes.SequenceEqual(_signatures[ext]))
            throw new InvalidOperationException("Invalid file signature");

        // 5. 生成安全文件名
        var safeName = $"{Guid.NewGuid()}{ext}";
        var safePath = Path.Combine(_uploadPath, safeName);

        // 6. 确保路径安全
        var fullPath = Path.GetFullPath(safePath);
        if (!fullPath.StartsWith(_uploadPath))
            throw new InvalidOperationException("Path traversal detected");

        // 7. 保存文件
        await using var stream = new FileStream(fullPath, FileMode.Create);
        file.OpenReadStream().Position = 0;
        await file.CopyToAsync(stream);

        return safeName;
    }
}
```

---

## 权限管理 (CWE-269/276)

### 默认权限问题

```csharp
// 危险: 默认允许所有
[ApiController]
public class AdminController : ControllerBase
{
    // 缺少授权，任何人可访问
    [HttpGet("users")]
    public IActionResult GetUsers() => Ok(_userService.GetAll());
}

// 安全: 全局默认拒绝 + 显式授权
// Startup.cs
services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

[Authorize(Roles = "Admin")]
[ApiController]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult GetUsers() => Ok(_userService.GetAll());
}

// 危险: 权限提升
[HttpPost("promote")]
public IActionResult Promote(int userId)
{
    var user = _context.Users.Find(userId);
    user.Role = "Admin";  // 无检查直接提升
    _context.SaveChanges();
    return Ok();
}

// 安全: 检查当前用户权限
[Authorize(Policy = "SuperAdminOnly")]
[HttpPost("promote")]
public IActionResult SafePromote(int userId, [FromBody] PromoteRequest request)
{
    var currentUser = GetCurrentUser();

    // 验证当前用户有权授予目标角色
    if (!CanGrantRole(currentUser, request.TargetRole))
        return Forbid();

    // 验证不能提升到比自己更高的角色
    if (GetRoleLevel(request.TargetRole) >= GetRoleLevel(currentUser.Role))
        return Forbid();

    var user = _context.Users.Find(userId);
    user.Role = request.TargetRole;
    _context.SaveChanges();

    _auditLog.Log($"User {userId} promoted to {request.TargetRole} by {currentUser.Id}");
    return Ok();
}
```

### 基于策略的授权

```csharp
// 定义策略
services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin", "SuperAdmin"));

    options.AddPolicy("ResourceOwner", policy =>
        policy.Requirements.Add(new ResourceOwnerRequirement()));

    options.AddPolicy("MinimumAge", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));
});

// 自定义授权处理器
public class ResourceOwnerHandler : AuthorizationHandler<ResourceOwnerRequirement, Resource>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ResourceOwnerRequirement requirement,
        Resource resource)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (resource.OwnerId == userId)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

// 使用
[HttpDelete("{id}")]
public async Task<IActionResult> Delete(int id)
{
    var resource = await _context.Resources.FindAsync(id);
    var authResult = await _authorizationService.AuthorizeAsync(User, resource, "ResourceOwner");

    if (!authResult.Succeeded)
        return Forbid();

    _context.Resources.Remove(resource);
    await _context.SaveChangesAsync();
    return NoContent();
}
```

### 检测命令

```bash
# 查找缺少授权的控制器
grep -rn "\[ApiController\]" --include="*.cs" -A 5 | grep -v "Authorize"

# 查找 AllowAnonymous
grep -rn "AllowAnonymous" --include="*.cs"

# 查找角色硬编码
grep -rn "Role.*=.*\"Admin\"\|\.Role = " --include="*.cs"
```

---

**版本**: 2.1
**更新日期**: 2026-02-04
**覆盖漏洞类型**: 22+ (含CWE-362/352/434/269/276)
