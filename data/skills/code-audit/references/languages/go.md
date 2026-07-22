# Go Security Audit

> Go 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: Go, Gin, Echo, Fiber, net/http, fasthttp, iris, mux, httprouter

---

## 审计方法论

### 双轨并行框架

```
                      Go 代码安全审计
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
│ • IDOR          │ │ • SSRF          │ │                 │
│ • 竞态条件      │ │ • 路径遍历      │ │                 │
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
# Gin框架路由 - 数据修改操作
grep -rn "\.POST\|\.PUT\|\.DELETE\|\.PATCH" --include="*.go"

# Echo框架路由
grep -rn "e\.POST\|e\.PUT\|e\.DELETE" --include="*.go"

# net/http 数据修改
grep -rn "case.*POST\|case.*PUT\|case.*DELETE" --include="*.go"

# 数据访问操作 (带参数)
grep -rn "\.GET.*:\|Param(\|Query(" --include="*.go"

# 批量操作
grep -rn "func.*Export\|func.*Download\|func.*Batch" --include="*.go"

# 资金操作
grep -rn "Transfer\|Payment\|Refund\|Balance" --include="*.go"

# 外部HTTP请求
grep -rn "http\.Get\|http\.Post\|http\.Client" --include="*.go"

# 文件操作
grep -rn "os\.Open\|ioutil\.ReadFile\|os\.Create" --include="*.go"

# 命令执行
grep -rn "exec\.Command\|os\.StartProcess" --include="*.go"
```

### 1.2 输出模板

```markdown
## Go敏感操作清单

| # | 端点/函数 | HTTP方法 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|----------|----------|------|----------|
| 1 | /api/user/:id | DELETE | 数据修改 | handler.go:45 | 高 |
| 2 | /api/user/:id | GET | 数据访问 | handler.go:32 | 中 |
| 3 | /api/transfer | POST | 资金操作 | payment.go:56 | 严重 |
```

---

## A2. 安全控制建模

### 2.1 Go安全控制实现方式

| 控制类型 | Gin | Echo | 通用实现 |
|----------|-----|------|----------|
| **认证控制** | JWT middleware | JWT middleware | 自定义middleware |
| **授权控制** | Casbin, 自定义中间件 | Casbin | RBAC中间件 |
| **资源所有权** | handler中比对 | handler中比对 | `user.ID == resource.OwnerID` |
| **输入验证** | binding, validator | validator | go-playground/validator |
| **并发控制** | GORM锁, 数据库事务 | 事务 | `SELECT ... FOR UPDATE` |
| **审计日志** | 自定义middleware | middleware | zap/logrus |

### 2.2 控制矩阵模板 (Go)

```yaml
敏感操作: DELETE /api/user/:id
位置: handler.go:45
类型: 数据修改

应有控制:
  认证控制:
    要求: 必须登录
    Gin: AuthMiddleware()
    验证: 检查路由组是否应用JWT中间件

  授权控制:
    要求: 管理员或本人
    实现: Casbin或自定义权限检查

  资源所有权:
    要求: 非管理员只能删除自己的数据
    验证: if user.ID != resource.OwnerID { return }
```

---

## A3. 控制存在性验证

### 3.1 数据修改操作验证清单

```markdown
## 控制验证: [端点名称]

| 控制项 | 应有 | 代码实现 | 结果 |
|--------|------|----------|------|
| 认证控制 | 必须 | AuthMiddleware | ✅/❌ |
| 授权控制 | 必须 | Casbin/手动检查 | ✅/❌ |
| 资源所有权 | 必须 | OwnerID比对 | ✅/❌ |
| 输入验证 | 必须 | binding:"required" | ✅/❌ |

### 验证命令
```bash
# 检查路由组中间件
grep -B 10 "\.DELETE\|\.POST" [路由文件] | grep "Use\|middleware"

# 检查资源所有权
grep -A 20 "func.*Delete" [handler文件] | grep "OwnerID\|UserID\|CreatedBy"
```
```

### 3.2 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | Go检测方法 |
|----------|----------|-----|------------|
| 无JWT中间件 | 认证缺失 | CWE-306 | 检查路由组Use() |
| 无Casbin检查 | 授权缺失 | CWE-862 | 检查handler权限判断 |
| 无OwnerID比对 | IDOR | CWE-639 | 检查查询条件 |
| 无FOR UPDATE | 竞态条件 | CWE-362 | 检查资金操作事务 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞
> **工具**: gosec 静态扫描

## B1. Go Source

```go
// net/http
r.URL.Query().Get("name")
r.FormValue("name")
r.Header.Get("X-Header")
r.Cookie("session")

// Gin
c.Query("name")
c.PostForm("name")
c.Param("id")
c.GetHeader("X-Header")
```

## B2. Go Sink

| Sink类型 | 漏洞 | Gosec规则 | 危险函数 |
|----------|------|-----------|----------|
| SQL执行 | SQL注入 | G201/G202 | db.Query(sql), fmt.Sprintf |
| 命令执行 | 命令注入 | G204 | exec.Command("sh", "-c", cmd) |
| 文件操作 | 路径遍历 | G304 | os.Open(userPath) |
| HTTP请求 | SSRF | G107 | http.Get(userURL) |

## B3. Gosec规则及Sink检测

## 识别特征

```go
// Go项目识别
package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

// 文件结构
├── go.mod
├── go.sum
├── main.go
├── cmd/
├── internal/
│   ├── handler/
│   ├── service/
│   └── repository/
├── pkg/
└── config/
```

---

## Gosec 规则参考

> gosec 通过扫描 Go AST 检测安全问题，规则与 CWE 映射

### G1xx - 凭据与敏感信息

| 规则 | 描述 | CWE |
|------|------|-----|
| G101 | 硬编码凭据 (password, secret, token) | CWE-798 |
| G102 | 绑定到所有接口 (0.0.0.0) | CWE-200 |
| G103 | unsafe 包使用审计 | CWE-242 |
| G104 | 未检查的错误返回值 | CWE-703 |
| G106 | ssh.InsecureIgnoreHostKey 使用 | CWE-322 |
| G107 | HTTP请求中的污点URL输入 | CWE-88 |
| G108 | pprof端点自动暴露 (/debug/pprof) | CWE-200 |
| G109 | strconv.Atoi 转 int16/32 整数溢出 | CWE-190 |
| G110 | 解压缩炸弹 DoS | CWE-409 |

### G2xx - 注入类

| 规则 | 描述 | CWE |
|------|------|-----|
| G201 | fmt.Sprintf 构造SQL | CWE-89 |
| G202 | 字符串拼接构造SQL | CWE-89 |
| G203 | HTML模板未转义数据 | CWE-79 |
| G204 | 命令执行审计 | CWE-78 |

### G3xx - 文件与路径

| 规则 | 描述 | CWE |
|------|------|-----|
| G301 | 创建目录权限过大 (>0750) | CWE-276 |
| G302 | chmod权限过大 | CWE-276 |
| G303 | 可预测路径创建临时文件 | CWE-377 |
| G304 | 文件路径污点输入 | CWE-22 |
| G305 | Zip解压路径遍历 (Zip Slip) | CWE-22 |
| G306 | 写文件权限过大 | CWE-276 |

### G4xx - 加密相关

| 规则 | 描述 | CWE |
|------|------|-----|
| G401 | 使用 DES/RC4/MD5 | CWE-326 |
| G402 | 不安全的TLS配置 | CWE-295 |
| G403 | RSA密钥 < 2048位 | CWE-326 |
| G404 | 使用 math/rand (弱随机) | CWE-338 |

### G5xx - 导入黑名单

| 规则 | 描述 |
|------|------|
| G501 | 导入 crypto/md5 |
| G502 | 导入 crypto/des |
| G503 | 导入 crypto/rc4 |
| G504 | 导入 net/http/cgi |

---

## Go特定漏洞

### 1. 命令执行 (G204)

```go
// 危险: 用户输入拼接到shell
cmd := exec.Command("sh", "-c", userInput)  // RCE!
cmd.Run()

// 危险: 动态命令名
cmd := exec.Command(userCmd, userArgs...)  // RCE!

// 危险: 从cookie/header获取命令参数
cookie, _ := r.Cookie("cmd")
exec.Command("sh", "-c", cookie.Value)  // RCE!

// 安全: 固定命令 + 白名单参数
allowedHosts := map[string]bool{"google.com": true}
if allowedHosts[host] {
    cmd := exec.Command("ping", "-c", "1", host)
}

// 搜索模式
exec\.Command|exec\.CommandContext|syscall\.Exec
```

### 2. SQL注入 (G201/G202)

```go
// 危险: fmt.Sprintf拼接 (G201)
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
db.Query(query)  // SQLi!

// 危险: 字符串拼接 (G202)
db.Query("SELECT * FROM users WHERE name = '" + name + "'")

// 危险: ORDER BY/LIMIT动态拼接
query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortColumn)

// GORM原生SQL
db.Raw("SELECT * FROM users WHERE id = " + id)  // 危险!

// Sqlx命名查询
db.NamedQuery("SELECT * FROM users WHERE name = " + name)  // 危险!

// 安全: 参数化查询
db.Query("SELECT * FROM users WHERE id = ?", userID)        // MySQL
db.QueryRow("SELECT * FROM users WHERE id = $1", userID)    // PostgreSQL
db.Raw("SELECT * FROM users WHERE id = ?", id)              // GORM安全用法

// 搜索模式
fmt\.Sprintf.*SELECT|fmt\.Sprintf.*INSERT|fmt\.Sprintf.*UPDATE|fmt\.Sprintf.*DELETE
db\.Query.*\+|db\.Exec.*\+|db\.Raw\(.*\+
```

### 3. 模板注入 (G203)

```go
// 危险: 用户输入作为模板内容
tmpl := template.New("test")
tmpl, _ = tmpl.Parse(userInput)  // SSTI!
tmpl.Execute(w, data)

// 危险: text/template (无自动转义)
import "text/template"  // 比html/template更危险

// 危险: html/template禁用转义
template.HTML(userInput)  // XSS!
template.JS(userInput)    // XSS!
template.CSS(userInput)   // XSS!

// 安全: 固定模板 + 数据分离
tmpl := template.Must(template.ParseFiles("template.html"))
tmpl.Execute(w, safeData)

// 搜索模式
template\.New.*Parse\(|text/template
template\.HTML\(|template\.JS\(|template\.CSS\(
```

### 4. SSRF (G107)

```go
// 危险: 用户可控URL
url := req.FormValue("url")
resp, _ := http.Get(url)  // SSRF!

// 危险: 未验证的重定向跟随
client := &http.Client{}  // 默认跟随重定向
resp, _ := client.Get(userURL)

// 危险: net.Dial可控
conn, _ := net.Dial("tcp", userHost+":"+userPort)

// 安全: 白名单 + 禁止内网地址
func isInternalIP(ip net.IP) bool {
    return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

parsedURL, _ := url.Parse(userURL)
ips, _ := net.LookupIP(parsedURL.Hostname())
for _, ip := range ips {
    if isInternalIP(ip) {
        return errors.New("internal IP not allowed")
    }
}

// 安全: 禁用重定向跟随
client := &http.Client{
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse
    },
}

// 需要防护的协议
// file://, gopher://, dict://, ftp://

// 搜索模式
http\.Get\(|http\.Post\(|http\.Do\(|http\.NewRequest
net\.Dial|net\.DialTimeout|net\.DialTCP
```

### 5. 路径遍历 (G304/G305)

```go
// 危险: filepath.Join不能防止路径遍历!
filePath := filepath.Join("/uploads", userFilename)
// filepath.Join("/uploads", "../../etc/passwd") = "/etc/passwd"

// 危险: Zip解压路径遍历 (Zip Slip) (G305)
func extractZip(zipPath, destDir string) {
    r, _ := zip.OpenReader(zipPath)
    for _, f := range r.File {
        path := filepath.Join(destDir, f.Name)  // 可能逃逸!
        // f.Name 可能是 "../../../etc/cron.d/malicious"
    }
}

// 安全: 验证最终路径在目标目录内
func safeJoin(baseDir, userPath string) (string, error) {
    absBase, _ := filepath.Abs(baseDir)
    targetPath := filepath.Join(absBase, userPath)
    absTarget, _ := filepath.Abs(targetPath)

    if !strings.HasPrefix(absTarget, absBase+string(os.PathSeparator)) {
        return "", errors.New("path traversal detected")
    }
    return absTarget, nil
}

// 搜索模式
filepath\.Join|os\.Open|ioutil\.ReadFile|os\.ReadFile|os\.Create
zip\.OpenReader|archive/zip|archive/tar
```

### 6. 整数溢出 (G109)

```go
// 危险: strconv.Atoi结果转小类型
input := req.FormValue("size")
size, _ := strconv.Atoi(input)
smallSize := int16(size)  // 溢出! 65536 -> 0

// 危险: 乘法溢出导致小分配
count, _ := strconv.Atoi(userInput)
buf := make([]byte, count*elementSize)  // count很大时溢出

// 安全: 边界检查
size, err := strconv.Atoi(input)
if err != nil || size < 0 || size > math.MaxInt16 {
    return errors.New("invalid size")
}

// 搜索模式
strconv\.Atoi.*int16|strconv\.Atoi.*int32
```

### 7. 弱随机数 (G404)

```go
// 危险: math/rand用于安全场景
import "math/rand"
token := rand.Int()  // 可预测!
rand.Seed(time.Now().UnixNano())  // 种子可猜测

// 安全: crypto/rand
import "crypto/rand"
bytes := make([]byte, 32)
rand.Read(bytes)

// 搜索模式
"math/rand"|rand\.Int|rand\.Intn|rand\.Seed
```

### 8. Unsafe包滥用 (G103)

```go
// 危险: unsafe.Pointer转换
ptr := unsafe.Pointer(&data)
uptr := uintptr(ptr)  // GC可能在此期间移动对象
// ... 其他代码 ...
newPtr := unsafe.Pointer(uptr)  // 可能指向无效内存!

// 危险: 与syscall配合
syscall.Syscall(SYS_XXX, uintptr(unsafe.Pointer(&buf)), ...)

// 搜索模式
unsafe\.Pointer|uintptr\(unsafe
```

### 9. Goroutine泄漏

```go
// 危险: 无缓冲channel阻塞
func leak() {
    ch := make(chan int)
    go func() {
        result := doWork()
        ch <- result  // 如果没人接收，永久阻塞!
    }()

    select {
    case <-time.After(time.Second):
        return  // 超时返回，goroutine泄漏
    case r := <-ch:
        return r
    }
}

// 安全: 使用缓冲channel或context取消
func safe(ctx context.Context) {
    ch := make(chan int, 1)  // 缓冲channel
    go func() {
        select {
        case ch <- doWork():
        case <-ctx.Done():
            return
        }
    }()
}

// 搜索模式
make\(chan.*\)|go func\(
```

### 10. pprof暴露 (G108)

```go
// 危险: 导入pprof自动注册路由
import _ "net/http/pprof"  // 自动暴露 /debug/pprof

// 可能泄露:
// /debug/pprof/heap     - 内存信息
// /debug/pprof/goroutine - 协程栈
// /debug/pprof/cmdline  - 命令行参数

// 安全: 单独端口或认证保护
// 不要在生产环境公开pprof端点

// 搜索模式
net/http/pprof|/debug/pprof
```

### 11. SSH不安全配置 (G106)

```go
// 危险: 忽略主机密钥验证
config := &ssh.ClientConfig{
    HostKeyCallback: ssh.InsecureIgnoreHostKey(),  // 中间人攻击!
}

// 安全: 验证主机密钥
config := &ssh.ClientConfig{
    HostKeyCallback: ssh.FixedHostKey(hostKey),
}

// 搜索模式
InsecureIgnoreHostKey
```

### 12. 解压缩炸弹 (G110)

```go
// 危险: 未限制解压大小
gzReader, _ := gzip.NewReader(r.Body)
io.Copy(w, gzReader)  // 1KB压缩 -> 1GB解压 = DoS

// 安全: 限制读取大小
limitReader := io.LimitReader(gzReader, maxSize)
io.Copy(w, limitReader)

// 搜索模式
gzip\.NewReader|zlib\.NewReader|flate\.NewReader
```

### 13. IPv6地址处理

```go
// 危险: IPv6地址端口拼接
addr := fmt.Sprintf("%s:%s", host, port)  // IPv6错误!
// "::1:8080" 解析错误

// 安全: 使用net.JoinHostPort
addr := net.JoinHostPort(host, port)  // "[::1]:8080"

// 搜索模式
fmt\.Sprintf.*%s:%s.*host|fmt\.Sprintf.*%s:%d.*host
```

### 14. 控制字符注入

```go
// 危险: 日志注入
log.Printf("User: %s", userInput)  // 可能注入\r\n伪造日志

// 安全: 使用%q或strconv.Quote
log.Printf("User: %q", userInput)
log.Printf("User: %s", strconv.Quote(userInput))

// 搜索模式
log\.Printf.*%s|fmt\.Printf.*%s
```

### 15. JWT/认证

```go
// 危险: 弱密钥
var jwtKey = []byte("secret")  // 弱!

// 危险: 不验证签名算法
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return jwtKey, nil  // 未验证alg，可能被none算法绕过
})

// 安全: 严格验证算法
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return jwtKey, nil
})

// 搜索模式
jwt\.Parse|jwt\.ParseWithClaims
jwtKey|secretKey|signingKey
```

### 16. CORS配置

```go
// Gin框架 - 危险配置
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"*"},  // 允许所有来源
    AllowCredentials: true,           // 与*同时使用危险!
}))

// 危险: 反射Origin
r.Use(cors.New(cors.Config{
    AllowOriginFunc: func(origin string) bool {
        return true  // 反射任意来源
    },
    AllowCredentials: true,
}))

// 搜索模式
AllowOrigins|AllowAllOrigins|AllowCredentials|AllowOriginFunc
Access-Control-Allow-Origin
```

---

## Go审计清单

```
命令执行 (G204):
- [ ] 搜索 exec.Command / exec.CommandContext
- [ ] 检查用户输入是否进入命令参数
- [ ] 检查shell模式调用 ("sh", "-c", ...)

SQL注入 (G201/G202):
- [ ] 搜索 fmt.Sprintf + SQL关键字
- [ ] 搜索 db.Query/Exec + 字符串拼接
- [ ] 搜索 GORM db.Raw() / Sqlx NamedQuery
- [ ] 验证参数化查询使用

模板注入 (G203):
- [ ] 搜索 template.Parse(用户输入)
- [ ] 区分 text/template 和 html/template
- [ ] 搜索 template.HTML/JS/CSS

SSRF (G107):
- [ ] 搜索 http.Get/Post/Do/NewRequest
- [ ] 搜索 net.Dial/DialTimeout
- [ ] 检查URL白名单验证
- [ ] 检查重定向处理

文件操作 (G304/G305):
- [ ] 搜索 filepath.Join + 用户输入
- [ ] 验证路径遍历防护
- [ ] 检查zip/tar解压安全

整数溢出 (G109):
- [ ] 搜索 strconv.Atoi 转小整数类型
- [ ] 检查乘法/加法溢出

弱随机 (G404):
- [ ] 搜索 math/rand 用于安全场景
- [ ] 验证使用 crypto/rand

认证与授权:
- [ ] 检查JWT密钥强度和算法验证
- [ ] 检查CORS配置
- [ ] 审计中间件鉴权

敏感信息 (G101):
- [ ] 搜索硬编码密码/密钥/token
- [ ] 检查日志是否记录敏感信息
- [ ] 检查pprof端点暴露 (G108)

资源安全:
- [ ] 检查goroutine泄漏
- [ ] 检查解压缩大小限制 (G110)
- [ ] 检查错误处理 (G104)
```

---

## 审计正则

```regex
# 命令执行 (G204)
exec\.Command|exec\.CommandContext|syscall\.Exec

# SQL注入 (G201/G202)
fmt\.Sprintf.*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)
db\.(Query|Exec|Raw)\s*\([^)]*\+
NamedQuery\s*\([^)]*\+

# 模板注入 (G203)
template\.New.*Parse\(|text/template
template\.(HTML|JS|CSS)\s*\(

# SSRF (G107)
http\.(Get|Post|Do|NewRequest)\s*\(
net\.(Dial|DialTimeout|DialTCP)\s*\(

# 路径遍历 (G304/G305)
filepath\.Join|os\.(Open|Create|ReadFile)|ioutil\.ReadFile
zip\.OpenReader|archive/(zip|tar)

# 整数溢出 (G109)
strconv\.Atoi.*int(8|16|32)

# 弱随机 (G404)
"math/rand"|rand\.(Int|Intn|Seed)

# 硬编码凭据 (G101)
(password|passwd|secret|token|apikey|api_key)\s*[:=]\s*["'][^"']+["']

# pprof暴露 (G108)
net/http/pprof|/debug/pprof

# SSH不安全 (G106)
InsecureIgnoreHostKey

# unsafe使用 (G103)
unsafe\.Pointer|uintptr\(unsafe

# 解压缩 (G110)
gzip\.NewReader|zlib\.NewReader|flate\.NewReader
```

---

## 审计工具

```bash
# Gosec - Go安全检查器
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...
gosec -severity medium ./...
gosec -include=G101,G201,G204 ./...
gosec -exclude=G104 ./...
gosec -fmt=json -out=results.json ./...

# 配置G101规则
cat > gosec.json << 'EOF'
{
  "G101": {
    "pattern": "(?i)passwd|pass|password|pwd|secret|private_key|token|apikey",
    "ignore_entropy": false,
    "entropy_threshold": "80.0"
  }
}
EOF
gosec -conf=gosec.json ./...

# 其他工具
go vet ./...                    # 内置静态分析
staticcheck ./...               # 深度检查
golangci-lint run               # 综合lint工具

# CodeQL for Go
# 1. 创建qlpack.yml配置文件
cat > qlpack.yml << 'EOF'
name: your-org/codeql-go-queries
version: 0.0.1
libraryPathDependencies: codeql-go
extractor: go
EOF

# 2. 创建CodeQL数据库
codeql database create ./codeql_database -s /path/to/go/project --language=go

# 3. 运行查询
codeql database analyze ./codeql_database codeql/go-queries --format=sarif-latest --output=results.sarif

# CodeQL Go标准库参考
# https://codeql.github.com/codeql-standard-libraries/go/
```

---

## 最小 PoC 示例
```bash
# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历
curl "http://localhost:8080/download?file=../../etc/passwd"

# 命令注入
curl "http://localhost:8080/ping?host=google.com;id"
```

---

---

## 授权漏洞检测 (Authorization Gap) - v1.7.1

> **核心问题**: 授权漏洞是"代码缺失"，grep 无法检测"应该有但没有"的代码
> **解决方案**: 授权矩阵方法 - 从"应该是什么"出发，而非"存在什么"

### 方法论

```
❌ 旧思路 (被动检测 - 局限性大):
   搜索中间件调用 → 检查是否存在
   问题: 存在中间件不等于正确，可能配置错误或遗漏

✅ 新思路 (主动建模 - 系统性):
   1. 枚举所有敏感操作 (DELETE/PUT handler)
   2. 定义应有的权限 (谁可以操作什么)
   3. 对比实际代码，检测缺失或不一致
```

### Gin 框架授权检测

```bash
# 步骤1: 找到所有敏感路由
grep -rn "\.DELETE\|\.PUT\|\.PATCH" --include="*.go"
grep -rn "func.*Delete\|func.*Update\|func.*Remove" --include="*.go"

# 步骤2: 检查路由组是否有认证中间件
grep -rn "\.Group" --include="*.go" -A 5 | grep -E "AuthMiddleware|JWTAuth|RequireAuth"

# 步骤3: 检查具体handler是否有权限检查
grep -rn "func.*Delete" --include="*.go" -A 20 | grep -E "userID|ownerID|CheckPermission|Authorize"
```

### 漏洞模式

```go
// ❌ 漏洞: delete handler 缺失权限检查
func DeleteFile(c *gin.Context) {
    fileID := c.Param("id")
    // 未检查用户是否有权删除该文件
    db.Delete(&File{}, fileID)
    c.JSON(200, gin.H{"status": "deleted"})
}

// ❌ 漏洞: 有认证但无授权 (水平越权)
func DeleteFile(c *gin.Context) {
    fileID := c.Param("id")
    userID := c.GetInt("userID")  // 从JWT获取用户ID
    // 只验证登录，未验证是否是文件所有者
    db.Delete(&File{}, fileID)  // 可删除他人文件!
    c.JSON(200, gin.H{"status": "deleted"})
}

// ✅ 安全: 认证 + 授权 + 资源所有权验证
func DeleteFile(c *gin.Context) {
    fileID := c.Param("id")
    userID := c.GetInt("userID")

    // 验证资源所有权
    var file File
    if err := db.Where("id = ? AND owner_id = ?", fileID, userID).First(&file).Error; err != nil {
        c.JSON(403, gin.H{"error": "not authorized"})
        return
    }

    db.Delete(&file)
    c.JSON(200, gin.H{"status": "deleted"})
}
```

### Echo 框架授权检测

```bash
# 检查路由定义
grep -rn "\.DELETE\|\.PUT\|\.PATCH" --include="*.go"

# 检查中间件配置
grep -rn "e\.Use\|g\.Use" --include="*.go" -A 2 | grep -E "middleware\.|JWT|Auth"
```

### 漏洞模式 (Echo)

```go
// ❌ 漏洞: 路由组有认证但无细粒度授权
api := e.Group("/api", middleware.JWT([]byte("secret")))
api.DELETE("/users/:id", deleteUser)  // 任何登录用户都可删除任何用户!

// ✅ 安全: 添加权限中间件
api := e.Group("/api", middleware.JWT([]byte("secret")))
admin := api.Group("/admin", AdminOnly)
admin.DELETE("/users/:id", deleteUser)  // 只有管理员可删除
```

### Fiber 框架授权检测

```bash
# 检查路由定义
grep -rn "\.Delete\|\.Put\|\.Patch" --include="*.go"

# 检查中间件
grep -rn "app\.Use\|group\.Use" --include="*.go" -A 2
```

### 授权一致性检测脚本

```bash
#!/bin/bash
# check_auth_consistency_go.sh

echo "=== Go 授权一致性检测 ==="

# 找所有Go文件
GO_FILES=$(find . -name "*.go" -type f)

for gofile in $GO_FILES; do
    # 检查敏感路由
    DELETE_ROUTES=$(grep -n "\.DELETE\|\.Delete" "$gofile" 2>/dev/null)
    PUT_ROUTES=$(grep -n "\.PUT\|\.Put" "$gofile" 2>/dev/null)

    if [ -n "$DELETE_ROUTES" ] || [ -n "$PUT_ROUTES" ]; then
        echo ""
        echo "检查: $gofile"

        # 检查是否有认证中间件
        AUTH_MIDDLEWARE=$(grep -c "AuthMiddleware\|JWTMiddleware\|RequireAuth\|middleware\.JWT" "$gofile")

        if [ "$AUTH_MIDDLEWARE" -eq 0 ]; then
            echo "  ⚠️  文件中有敏感路由但未发现认证中间件"
        fi

        # 检查handler中是否有权限验证
        echo "$DELETE_ROUTES" | while read line; do
            if [ -n "$line" ]; then
                handler=$(echo "$line" | grep -o "[A-Za-z]*Delete[A-Za-z]*\|delete[A-Za-z]*")
                if [ -n "$handler" ]; then
                    # 检查handler实现
                    has_owner_check=$(grep -A 30 "func.*$handler" "$gofile" | grep -c "owner_id\|OwnerID\|user_id.*=\|UserID.*=")
                    if [ "$has_owner_check" -eq 0 ]; then
                        echo "  ⚠️  $handler: 可能缺少资源所有权验证"
                    fi
                fi
            fi
        done
    fi
done
```

### 间接SSRF检测 (配置驱动)

```go
// ❌ 漏洞: 配置驱动的间接SSRF
type Config struct {
    APIBaseURL string `yaml:"api_base_url"`
}

func FetchData(cfg *Config, endpoint string) ([]byte, error) {
    url := cfg.APIBaseURL + endpoint  // 间接SSRF
    resp, err := http.Get(url)
    // ...
}

// 检测命令
grep -rn "viper\.Get.*URL\|viper\.Get.*Host\|config\.\w*URL" --include="*.go"
grep -rn "os\.Getenv.*URL\|os\.Getenv.*HOST" --include="*.go"
grep -rn "fmt\.Sprintf.*%s.*http\|fmt\.Sprintf.*http.*%s" --include="*.go"
```

### 审计清单 (授权专项)

```
授权矩阵建模:
- [ ] 列出所有敏感路由 (DELETE/PUT/PATCH)
- [ ] 定义每个路由的预期权限
- [ ] 检查实际中间件配置是否匹配预期

Gin/Echo/Fiber 专项:
- [ ] 检查路由组的中间件配置
- [ ] 验证 DELETE 路由是否有认证中间件
- [ ] 检查 handler 中的资源所有权验证

水平越权防护:
- [ ] 验证所有资源操作都检查 owner_id/user_id
- [ ] 检查数据库查询是否包含用户过滤条件
- [ ] 验证批量操作的权限检查

中间件配置:
- [ ] 检查中间件顺序 (认证 → 授权)
- [ ] 验证 JWT 密钥强度
- [ ] 检查 CORS 配置

间接注入:
- [ ] 检查 viper/config 中的 URL 配置
- [ ] 追踪环境变量中的可控值
- [ ] 验证 fmt.Sprintf 构造的URL
```

---

## CSRF 安全 (CWE-352)

### 危险模式

```go
// 🔴 Gin - 无 CSRF 保护
r := gin.Default()
r.POST("/api/transfer", func(c *gin.Context) {
    // 状态变更操作无 CSRF 保护
    var req TransferRequest
    c.BindJSON(&req)
    transfer(req.To, req.Amount)
})
```

### 安全配置

```go
// Gin + gorilla/csrf
import (
    "github.com/gorilla/csrf"
    adapter "github.com/gwatts/gin-adapter"
)

func main() {
    r := gin.Default()

    // CSRF 中间件
    csrfMiddleware := csrf.Protect(
        []byte("32-byte-long-auth-key-here!!!!!"),
        csrf.Secure(true),  // HTTPS only
        csrf.HttpOnly(true),
    )

    r.Use(adapter.Wrap(csrfMiddleware))

    r.GET("/form", func(c *gin.Context) {
        token := csrf.Token(c.Request)
        c.HTML(200, "form.html", gin.H{"csrf": token})
    })

    r.POST("/api/transfer", func(c *gin.Context) {
        // CSRF token 自动验证
        var req TransferRequest
        c.BindJSON(&req)
        transfer(req.To, req.Amount)
    })
}

// Echo + middleware
import "github.com/labstack/echo/v4/middleware"

e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
    TokenLookup: "header:X-CSRF-Token",
    CookieName:  "_csrf",
    CookieSecure: true,
}))
```

### 检测命令

```bash
# 查找 POST/PUT/DELETE 路由
rg -n '\.(POST|PUT|DELETE|PATCH)\(' --glob "*.go"

# 查找缺少 CSRF 中间件的项目
rg -n "csrf|CSRF" --glob "*.go" || echo "No CSRF protection found"
```

---

## 文件上传安全 (CWE-434)

### 危险模式

```go
// 🔴 无验证的文件上传
func uploadHandler(c *gin.Context) {
    file, _ := c.FormFile("file")
    c.SaveUploadedFile(file, "/uploads/"+file.Filename)  // 路径遍历 + 任意类型
}
```

### 安全配置

```go
import (
    "path/filepath"
    "strings"
    "github.com/h2non/filetype"
)

var allowedTypes = map[string]bool{
    "image/jpeg": true,
    "image/png":  true,
    "image/gif":  true,
}

const maxFileSize = 5 * 1024 * 1024  // 5MB

func uploadHandler(c *gin.Context) {
    file, header, err := c.Request.FormFile("file")
    if err != nil {
        c.JSON(400, gin.H{"error": "No file"})
        return
    }
    defer file.Close()

    // 1. 大小限制
    if header.Size > maxFileSize {
        c.JSON(400, gin.H{"error": "File too large"})
        return
    }

    // 2. 读取文件头判断真实类型
    head := make([]byte, 261)
    file.Read(head)
    file.Seek(0, 0)

    kind, _ := filetype.Match(head)
    if !allowedTypes[kind.MIME.Value] {
        c.JSON(400, gin.H{"error": "Invalid file type"})
        return
    }

    // 3. 安全文件名
    ext := filepath.Ext(header.Filename)
    if !isAllowedExt(ext) {
        c.JSON(400, gin.H{"error": "Invalid extension"})
        return
    }
    safeName := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)

    // 4. 安全路径
    uploadDir := "/uploads"
    dst := filepath.Join(uploadDir, safeName)
    if !strings.HasPrefix(filepath.Clean(dst), uploadDir) {
        c.JSON(400, gin.H{"error": "Invalid path"})
        return
    }

    out, _ := os.Create(dst)
    defer out.Close()
    io.Copy(out, file)

    c.JSON(200, gin.H{"filename": safeName})
}

func isAllowedExt(ext string) bool {
    allowed := []string{".jpg", ".jpeg", ".png", ".gif"}
    ext = strings.ToLower(ext)
    for _, a := range allowed {
        if ext == a {
            return true
        }
    }
    return false
}
```

### 检测命令

```bash
# 查找文件上传
rg -n "FormFile|SaveUploadedFile|MultipartForm" --glob "*.go"

# 查找缺少验证的上传
rg -A10 "FormFile" --glob "*.go" | grep -v "filetype\|MIME\|extension"
```

---

## 参考资源

- [gosec GitHub](https://github.com/securego/gosec)
- [Go安全最佳实践](https://go.dev/doc/security)
- [OWASP Go安全指南](https://owasp.org/www-project-web-security-testing-guide/)
