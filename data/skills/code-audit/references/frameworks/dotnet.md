# ASP.NET Core / Blazor Security Audit Guide

> ASP.NET Core 框架安全审计模块
> 适用于: ASP.NET Core 6/7/8, Blazor Server/WebAssembly, Razor Pages, Minimal APIs

## 识别特征

```csharp
// ASP.NET Core 项目识别
<Project Sdk="Microsoft.NET.Sdk.Web">
using Microsoft.AspNetCore;

// 文件结构
├── Program.cs / Startup.cs
├── appsettings.json
├── Controllers/
├── Pages/ (Razor Pages)
├── Views/ (MVC)
├── Models/
├── Data/ (EF Core DbContext)
└── wwwroot/
```

---

## SQL 注入检测

```csharp
// 危险: EF Core 原始SQL拼接
var users = db.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");  // ❌ Critical

// 危险: Dapper 字符串拼接
connection.Query("SELECT * FROM Users WHERE Id = " + id);  // ❌ Critical
connection.Execute($"DELETE FROM Users WHERE Id = {id}");   // ❌ Critical

// 危险: ADO.NET 原始拼接
var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + input + "'", conn);  // ❌

// 危险: EF Core ExecuteSqlRaw 拼接
db.Database.ExecuteSqlRaw("UPDATE Users SET Name = '" + name + "' WHERE Id = " + id);  // ❌

// 审计正则
FromSqlRaw\s*\(.*\+|ExecuteSqlRaw\s*\(.*\+
connection\.(Query|Execute)\s*\(.*\+|SqlCommand\s*\(.*\+

// 安全: 参数化查询
db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");  // ✓
db.Database.ExecuteSqlInterpolated($"UPDATE Users SET Name = {name}");     // ✓

// Dapper 参数化
connection.Query("SELECT * FROM Users WHERE Id = @Id", new { Id = id });  // ✓

// ADO.NET 参数化
var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @Name", conn);
cmd.Parameters.AddWithValue("@Name", input);  // ✓
```

---

## XSS 检测 (Razor Views)

```html
<!-- 危险: Html.Raw 输出用户输入 -->
@Html.Raw(Model.UserComment)          <!-- ❌ Critical: 直接输出原始HTML -->
@Html.Raw(ViewBag.Message)            <!-- ❌ ViewBag可能含用户输入 -->

<!-- 危险: JavaScript上下文中的未编码输出 -->
<script>var name = '@Model.Name';</script>  <!-- ❌ 可逃逸引号 -->

<!-- 审计正则 -->
Html\.Raw\s*\(|@Html\.Raw|@\(.*Html\.Raw
<script>.*@Model\.|<script>.*@ViewBag\.

<!-- 安全: Razor 默认转义 -->
<p>@Model.UserComment</p>                  <!-- ✓ 自动HTML编码 -->

<!-- 安全: JavaScript上下文 -->
<script>var name = @Json.Serialize(Model.Name);</script>  <!-- ✓ JSON编码 -->
```

---

## CSRF 配置检测

```csharp
// 危险: 全局禁用防伪验证
services.AddControllersWithViews(options =>
{
    // 未添加 AutoValidateAntiforgeryTokenAttribute
});

// 危险: 控制器级别忽略
[IgnoreAntiforgeryToken]  // ❌ 跳过CSRF验证
public IActionResult UpdateProfile(ProfileModel model) { ... }

// 危险: Razor Pages 禁用
@attribute [IgnoreAntiforgeryToken]  // ❌

// 审计正则
\[IgnoreAntiforgeryToken\]|IgnoreAntiforgeryToken
AddControllersWithViews(?!.*AutoValidateAntiforgeryToken)

// 安全: 全局启用
services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());  // ✓
});

// Razor Pages 默认启用; API使用JWT则可禁用CSRF但需确认
```

---

## 授权配置缺陷

```csharp
// 危险: [AllowAnonymous] 覆盖 [Authorize]
[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    [AllowAnonymous]  // ❌ Critical: 覆盖了类级别的Authorize
    public IActionResult SensitiveAction() { ... }
}

// 危险: 缺少授权属性
public class PaymentController : Controller  // ❌ 无[Authorize]
{
    public IActionResult ProcessPayment() { ... }
}

// 危险: Minimal API 遗漏授权
app.MapGet("/admin/users", GetAllUsers);  // ❌ 未添加RequireAuthorization

// 审计正则
\[AllowAnonymous\]|AllowAnonymous
MapGet\(|MapPost\(|MapPut\(|MapDelete\(  // 检查是否有RequireAuthorization

// 安全: Fallback策略 (默认拒绝)
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();  // ✓ 未标注的端点默认需要认证
});

// Minimal API 授权
app.MapGet("/admin/users", GetAllUsers).RequireAuthorization("AdminPolicy");  // ✓
```

---

## 不安全的反序列化

```csharp
// 危险: BinaryFormatter (已弃用，但仍在老代码中)
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);  // ❌ Critical: RCE

// 危险: Newtonsoft TypeNameHandling
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All  // ❌ Critical: 反序列化任意类型
};
JsonConvert.DeserializeObject(json, settings);

// 危险: TypeNameHandling.Auto/Objects 同样可利用
TypeNameHandling = TypeNameHandling.Auto    // ❌
TypeNameHandling = TypeNameHandling.Objects // ❌

// 审计正则
BinaryFormatter|ObjectStateFormatter|SoapFormatter|NetDataContractSerializer
TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)
LosFormatter|XmlSerializer\s*\(.*typeof\s*\(.*GetType

// 安全: 使用 System.Text.Json (默认安全)
var obj = JsonSerializer.Deserialize<MyModel>(json);  // ✓ 无多态类型处理

// 如果必须用 Newtonsoft, 使用 SerializationBinder 白名单
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.Auto,
    SerializationBinder = new KnownTypesBinder(allowedTypes)  // ✓
};
```

---

## 路径遍历 (文件下载)

```csharp
// 危险: 直接拼接文件路径
[HttpGet("download")]
public IActionResult Download(string fileName)
{
    var path = Path.Combine(_uploadDir, fileName);
    return PhysicalFile(path, "application/octet-stream");  // ❌ ../../../etc/passwd
}

// 危险: 未规范化路径
var fullPath = _baseDir + "/" + userInput;  // ❌ 路径遍历
System.IO.File.ReadAllText(fullPath);

// 审计正则
PhysicalFile\s*\(.*\+|Path\.Combine\s*\(.*fileName|File\.(Read|Open|Delete).*\+
SendFileAsync\s*\(.*\+

// 安全: 路径验证
[HttpGet("download")]
public IActionResult Download(string fileName)
{
    if (fileName.Contains("..") || Path.IsPathRooted(fileName))
        return BadRequest();

    var path = Path.Combine(_uploadDir, fileName);
    var fullPath = Path.GetFullPath(path);

    if (!fullPath.StartsWith(Path.GetFullPath(_uploadDir)))  // ✓ 规范化后比对
        return BadRequest();

    return PhysicalFile(fullPath, "application/octet-stream");
}
```

---

## CORS 配置缺陷

```csharp
// 危险: 允许所有来源 + 凭据
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()     // ❌
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();   // ❌ 与AllowAnyOrigin冲突且危险
    });
});

// 危险: 在 Program.cs/Startup.cs 中动态反射 Origin
app.UseCors(policy => policy
    .SetIsOriginAllowed(_ => true)   // ❌ 允许任何来源
    .AllowCredentials());

// 审计正则
AllowAnyOrigin|SetIsOriginAllowed.*true|AllowCredentials

// 安全: 明确白名单
builder.Services.AddCors(options =>
{
    options.AddPolicy("Strict", policy =>
    {
        policy.WithOrigins("https://app.example.com")  // ✓
              .WithMethods("GET", "POST")
              .WithHeaders("Content-Type", "Authorization")
              .AllowCredentials();
    });
});
```

---

## Blazor 安全差异

```csharp
// Blazor Server: 服务端渲染, SignalR连接
// - 敏感数据在服务端, 但 SignalR 消息可能泄露
// - Circuit 劫持: 确保认证检查在每个Hub调用中
// - 防止 JS Interop 注入

// 危险: Blazor Server 中直接访问数据库无权限检查
@code {
    private async Task LoadData()
    {
        data = await _dbContext.SensitiveData.ToListAsync();  // ❌ 无用户权限检查
    }
}

// 危险: MarkupString 等价于 Html.Raw
@((MarkupString)userInput)  // ❌ XSS

// Blazor WebAssembly: 客户端运行
// - 所有C#代码在浏览器中, 可被反编译 → 不要在WASM中存放密钥
// - API调用必须在服务端验证 → 不能仅依赖客户端授权检查
// - 审计: 检查 wwwroot/ 中是否有敏感配置

// 审计正则
MarkupString\)|@\(\(MarkupString\)
NavigationManager\.NavigateTo\s*\(.*\+  // 开放重定向
```

---

## 搜索模式汇总

```regex
# SQL注入
FromSqlRaw\s*\(.*\+|ExecuteSqlRaw\s*\(.*\+|SqlCommand\s*\(.*\+
connection\.(Query|Execute)\s*\(.*\+

# XSS
Html\.Raw\s*\(|MarkupString\)

# CSRF
\[IgnoreAntiforgeryToken\]

# 授权
\[AllowAnonymous\]
MapGet\(|MapPost\(  // 检查Minimal API授权

# 反序列化
BinaryFormatter|TypeNameHandling\.(All|Auto|Objects)

# 路径遍历
PhysicalFile\s*\(.*\+|Path\.Combine\s*\(.*fileName

# CORS
AllowAnyOrigin|SetIsOriginAllowed.*true

# 敏感配置
"ConnectionStrings".*password|appsettings.*Development.*json
```

---

## 快速审计检查清单

```markdown
[ ] 检查 ASP.NET Core 版本和已知CVE
[ ] 搜索 FromSqlRaw/ExecuteSqlRaw 字符串拼接
[ ] 搜索 Dapper Query/Execute 拼接
[ ] 搜索 Html.Raw / MarkupString (XSS)
[ ] 搜索 [IgnoreAntiforgeryToken] (CSRF绕过)
[ ] 搜索 [AllowAnonymous] 在敏感Controller上
[ ] 检查 FallbackPolicy 授权配置
[ ] 搜索 BinaryFormatter / TypeNameHandling (反序列化)
[ ] 检查文件下载端点路径验证
[ ] 搜索 AllowAnyOrigin / SetIsOriginAllowed (CORS)
[ ] 检查 appsettings.json 中硬编码密钥/连接字符串
[ ] 检查 Blazor 中 MarkupString 和 JS Interop
[ ] 验证 Minimal API 端点是否有 RequireAuthorization
[ ] 检查异常处理是否泄露堆栈 (app.UseDeveloperExceptionPage)
```

---

## 最小 PoC 示例
```bash
# SQL 注入 (Dapper/Raw SQL)
curl "http://localhost:5000/api/users?name=admin'OR'1'='1"

# 路径遍历
curl "http://localhost:5000/download?fileName=../../../etc/passwd"

# 开放重定向
curl "http://localhost:5000/redirect?url=https://evil.com"
```

---

## 参考资源

- [Microsoft ASP.NET Core Security Documentation](https://learn.microsoft.com/en-us/aspnet/core/security/)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [Blazor Security Considerations](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/)
