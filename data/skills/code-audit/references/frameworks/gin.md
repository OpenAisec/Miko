# Gin Security Audit

> Gin 框架安全审计模块
> 适用于: Gin, Gin-GORM, Gin-JWT

---

## 识别特征

```go
// Gin 项目识别
import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.Run()
}

// 常见目录结构
├── cmd/
│   └── main.go
├── internal/
│   ├── handler/     # 控制器
│   ├── service/     # 业务逻辑
│   ├── model/       # 数据模型
│   └── middleware/  # 中间件
├── pkg/             # 公共包
├── config/          # 配置
└── go.mod
```

---

## Critical 漏洞

### 1. SQL 注入

```go
import (
    "github.com/gin-gonic/gin"
    "gorm.io/gorm"
)

// 危险: Raw 拼接
func GetUser(c *gin.Context) {
    id := c.Param("id")
    var user User
    db.Raw("SELECT * FROM users WHERE id = " + id).Scan(&user)
    c.JSON(200, user)
}

// 危险: Where 字符串拼接
func SearchUsers(c *gin.Context) {
    name := c.Query("name")
    var users []User
    db.Where("name LIKE '%" + name + "%'").Find(&users)
    c.JSON(200, users)
}

// 危险: Order 注入
func ListUsers(c *gin.Context) {
    order := c.Query("order")  // 用户控制排序
    var users []User
    db.Order(order).Find(&users)  // ORDER BY 注入
    c.JSON(200, users)
}
// payload: ?order=id; DROP TABLE users;--

// 安全: 参数化查询
func GetUser(c *gin.Context) {
    id := c.Param("id")
    var user User
    db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&user)
    c.JSON(200, user)
}

// 安全: ORM 方法
func SearchUsers(c *gin.Context) {
    name := c.Query("name")
    var users []User
    db.Where("name LIKE ?", "%"+name+"%").Find(&users)
    c.JSON(200, users)
}

// 安全: Order 白名单
var allowedOrders = map[string]bool{
    "id":         true,
    "created_at": true,
    "name":       true,
}

func ListUsers(c *gin.Context) {
    order := c.DefaultQuery("order", "id")
    if !allowedOrders[order] {
        order = "id"
    }
    var users []User
    db.Order(order).Find(&users)
    c.JSON(200, users)
}
```

### 2. 命令注入

```go
import "os/exec"

// 危险: shell 执行
func RunCommand(c *gin.Context) {
    cmd := c.Query("cmd")
    out, _ := exec.Command("sh", "-c", cmd).Output()
    c.String(200, string(out))
}

// 危险: 参数拼接
func Ping(c *gin.Context) {
    host := c.Query("host")
    cmd := exec.Command("sh", "-c", "ping -c 4 "+host)
    out, _ := cmd.Output()
    c.String(200, string(out))
}
// payload: ?host=127.0.0.1;id

// 安全: 直接执行，无 shell
func Ping(c *gin.Context) {
    host := c.Query("host")
    // 验证 host 格式
    if !isValidHost(host) {
        c.String(400, "Invalid host")
        return
    }
    cmd := exec.Command("ping", "-c", "4", host)
    out, _ := cmd.Output()
    c.String(200, string(out))
}
```

### 3. 路径遍历

```go
// 危险: 直接拼接路径
func DownloadFile(c *gin.Context) {
    filename := c.Query("file")
    c.File("/uploads/" + filename)
}
// payload: ?file=../../../etc/passwd

// 安全: 路径验证
func DownloadFile(c *gin.Context) {
    filename := c.Query("file")

    // 清理路径
    cleanName := filepath.Clean(filename)

    // 防止目录遍历
    if strings.Contains(cleanName, "..") {
        c.String(400, "Invalid filename")
        return
    }

    fullPath := filepath.Join("/uploads", cleanName)

    // 验证在允许目录内
    if !strings.HasPrefix(fullPath, "/uploads/") {
        c.String(403, "Access denied")
        return
    }

    c.File(fullPath)
}
```

---

## High 漏洞

### 4. SSRF

```go
import "net/http"

// 危险: 未验证 URL
func FetchURL(c *gin.Context) {
    url := c.Query("url")
    resp, _ := http.Get(url)
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    c.String(200, string(body))
}
// payload: ?url=http://169.254.169.254/latest/meta-data/

// 安全: URL 白名单
var allowedHosts = map[string]bool{
    "api.example.com": true,
}

func FetchURL(c *gin.Context) {
    rawURL := c.Query("url")

    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        c.String(400, "Invalid URL")
        return
    }

    if !allowedHosts[parsedURL.Host] {
        c.String(403, "Host not allowed")
        return
    }

    // 检查内网 IP
    if isPrivateIP(parsedURL.Host) {
        c.String(403, "Private IP not allowed")
        return
    }

    resp, _ := http.Get(rawURL)
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    c.String(200, string(body))
}
```

### 5. 身份认证绕过

```go
// 危险: JWT 密钥硬编码
var jwtSecret = []byte("secret")

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        token, _ := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
            return jwtSecret, nil
        })
        // ...
    }
}

// 危险: 未验证签名算法
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token, _ := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
            // 未检查算法!
            return jwtSecret, nil
        })
        // ...
    }
}
// 攻击: 修改 alg 为 none

// 安全: 验证算法 + 环境变量密钥
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
            // 验证签名算法
            if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            c.AbortWithStatus(401)
            return
        }

        c.Next()
    }
}
```

### 6. 越权访问 (IDOR)

```go
// 危险: 未验证资源所有权
func GetOrder(c *gin.Context) {
    orderID := c.Param("id")
    var order Order
    db.First(&order, orderID)
    c.JSON(200, order)  // 任何人可访问任何订单
}

// 安全: 验证所有权
func GetOrder(c *gin.Context) {
    orderID := c.Param("id")
    userID := c.GetInt("user_id")  // 从 JWT 获取

    var order Order
    result := db.Where("id = ? AND user_id = ?", orderID, userID).First(&order)
    if result.Error != nil {
        c.JSON(404, gin.H{"error": "Order not found"})
        return
    }
    c.JSON(200, order)
}
```

---

## Medium 漏洞

### 7. XSS

```go
// 危险: 直接输出 HTML
func Hello(c *gin.Context) {
    name := c.Query("name")
    c.Writer.Write([]byte("<h1>Hello " + name + "</h1>"))
}

// 危险: template.HTML 不转义
func Hello(c *gin.Context) {
    name := c.Query("name")
    c.HTML(200, "hello.tmpl", gin.H{
        "name": template.HTML(name),  // 不转义!
    })
}

// 安全: 使用模板自动转义
func Hello(c *gin.Context) {
    name := c.Query("name")
    c.HTML(200, "hello.tmpl", gin.H{
        "name": name,  // 自动转义
    })
}
```

### 8. CORS 配置错误

```go
import "github.com/gin-contrib/cors"

// 危险: 允许所有来源
r.Use(cors.Default())

// 更危险: 允许凭证 + 所有来源
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"*"},
    AllowCredentials: true,  // 危险组合!
}))

// 安全: 指定允许的来源
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://example.com"},
    AllowMethods:     []string{"GET", "POST"},
    AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
    AllowCredentials: true,
    MaxAge:           12 * time.Hour,
}))
```

### 9. 信任代理头

```go
// 危险: 默认信任所有代理头
r := gin.Default()
// 默认会读取 X-Forwarded-For

// 可能导致 IP 欺骗
func GetClientIP(c *gin.Context) {
    ip := c.ClientIP()  // 可能被伪造
    // ...
}

// 安全: 配置信任的代理
r.SetTrustedProxies([]string{"192.168.1.0/24", "10.0.0.0/8"})

// 或禁用代理头
r.SetTrustedProxies(nil)
```

### 10. 参数绑定漏洞

```go
// 危险: 自动绑定所有字段
type User struct {
    ID       uint   `json:"id"`
    Name     string `json:"name"`
    IsAdmin  bool   `json:"is_admin"`
}

func CreateUser(c *gin.Context) {
    var user User
    c.BindJSON(&user)  // 用户可设置 is_admin=true
    db.Create(&user)
}

// 安全: 使用 DTO
type CreateUserDTO struct {
    Name string `json:"name" binding:"required"`
}

func CreateUser(c *gin.Context) {
    var dto CreateUserDTO
    if err := c.ShouldBindJSON(&dto); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    user := User{Name: dto.Name, IsAdmin: false}
    db.Create(&user)
}
```

---

## Gin 中间件安全

### 速率限制

```go
import "github.com/ulule/limiter/v3/drivers/middleware/gin"

// 危险: 无速率限制
r.POST("/login", loginHandler)

// 安全: 添加速率限制
store := memory.NewStore()
rate := limiter.Rate{
    Period: 1 * time.Minute,
    Limit:  10,
}
middleware := mgin.NewMiddleware(limiter.New(store, rate))
r.POST("/login", middleware, loginHandler)
```

### 日志安全

```go
// 危险: 记录敏感信息
func Login(c *gin.Context) {
    password := c.PostForm("password")
    log.Printf("Login attempt with password: %s", password)  // 不要!
}

// 安全: 脱敏日志
func Login(c *gin.Context) {
    username := c.PostForm("username")
    log.Printf("Login attempt for user: %s", username)
}
```

### 错误处理

```go
// 危险: 暴露内部错误
func GetUser(c *gin.Context) {
    var user User
    if err := db.First(&user).Error; err != nil {
        c.JSON(500, gin.H{"error": err.Error()})  // 暴露数据库信息
        return
    }
    c.JSON(200, user)
}

// 安全: 通用错误消息
func GetUser(c *gin.Context) {
    var user User
    if err := db.First(&user).Error; err != nil {
        log.Printf("Database error: %v", err)  // 内部日志
        c.JSON(500, gin.H{"error": "Internal server error"})
        return
    }
    c.JSON(200, user)
}
```

---

## 检测命令

```bash
# SQL 注入
grep -rn "\.Raw\|\.Where\|\.Order" --include="*.go" | grep -E '"\s*\+|\+\s*"'

# 命令执行
grep -rn "exec\.Command" --include="*.go"

# 路径操作
grep -rn "c\.File\|filepath\.Join" --include="*.go"

# JWT 密钥
grep -rn "jwt\|secret\|Secret" --include="*.go"

# CORS 配置
grep -rn "cors\." --include="*.go"

# 绑定操作
grep -rn "c\.Bind\|c\.ShouldBind" --include="*.go"

# 静态分析
gosec ./...
staticcheck ./...
```

---

## 审计清单

```
[ ] 检查 SQL 查询是否使用参数化
[ ] 检查命令执行是否有注入风险
[ ] 检查文件操作是否有路径遍历
[ ] 检查 HTTP 请求是否有 SSRF
[ ] 检查 JWT 配置 (密钥、算法)
[ ] 检查 IDOR 漏洞
[ ] 检查 XSS 防护
[ ] 检查 CORS 配置
[ ] 检查代理头信任配置
[ ] 检查参数绑定是否安全
[ ] 检查速率限制
[ ] 检查错误处理
[ ] 运行 gosec 静态分析
```

---

## 最小 PoC 示例
```bash
# SQL 注入
curl "http://localhost:8080/users?id=1' OR '1'='1"

# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历
curl "http://localhost:8080/download?file=../../etc/passwd"
```

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
