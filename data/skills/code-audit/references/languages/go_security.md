# Go Security Deep Dive

> Go 语言安全审计深度模块
> 覆盖: 并发安全、unsafe 包、cgo、Web 框架

---

## Overview

Go 虽然内存安全，但仍存在独特的安全挑战：并发竞态条件、unsafe 包滥用、cgo 边界问题、以及 Web 框架特定漏洞。

---

## 并发安全 (Race Conditions)

### 1. Data Race 检测

```go
// 危险: 并发读写 map
var cache = make(map[string]string)

func GetCache(key string) string {
    return cache[key]  // 并发读
}

func SetCache(key, value string) {
    cache[key] = value  // 并发写 - DATA RACE!
}

// 安全: 使用 sync.RWMutex
var (
    cache = make(map[string]string)
    mu    sync.RWMutex
)

func GetCache(key string) string {
    mu.RLock()
    defer mu.RUnlock()
    return cache[key]
}

func SetCache(key, value string) {
    mu.Lock()
    defer mu.Unlock()
    cache[key] = value
}

// 或使用 sync.Map
var cache sync.Map

func GetCache(key string) (string, bool) {
    v, ok := cache.Load(key)
    if !ok {
        return "", false
    }
    return v.(string), true
}
```

### 2. Channel 竞态

```go
// 危险: channel 关闭后发送
func worker(ch chan int) {
    for i := 0; i < 10; i++ {
        ch <- i
    }
    close(ch)  // 关闭
}

func main() {
    ch := make(chan int)
    go worker(ch)

    // 另一个 goroutine 可能在关闭后发送
    go func() {
        ch <- 100  // panic: send on closed channel
    }()
}

// 安全: 使用 sync.Once 或 context
var closeOnce sync.Once

func safeClose(ch chan int) {
    closeOnce.Do(func() {
        close(ch)
    })
}
```

### 3. Read-Modify-Write 竞态

```go
// 危险: 非原子计数
var counter int

func increment() {
    counter++  // 非原子操作: 读取 → 加1 → 写入
}

// 安全: 使用 atomic
var counter int64

func increment() {
    atomic.AddInt64(&counter, 1)
}

// 安全: 使用 mutex
var (
    counter int
    mu      sync.Mutex
)

func increment() {
    mu.Lock()
    counter++
    mu.Unlock()
}
```

### 4. 检查-使用竞态 (TOCTOU)

```go
// 危险: 检查后使用
func processFile(path string) error {
    // 检查文件是否存在
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return err
    }

    // 竞态窗口: 文件可能在检查后被删除或替换

    return os.Remove(path)  // 使用
}

// 安全: 直接操作，处理错误
func processFile(path string) error {
    err := os.Remove(path)
    if os.IsNotExist(err) {
        return nil  // 或返回错误
    }
    return err
}
```

### 5. Race Detector

```bash
# 编译时启用竞态检测
go build -race ./...

# 测试时检测
go test -race ./...

# 运行时检测
go run -race main.go
```

---

## unsafe 包安全

### 1. 常见危险用法

```go
import "unsafe"

// 危险: 任意内存访问
func readMemory(addr uintptr, size int) []byte {
    // 可能导致段错误或信息泄露
    return (*[1 << 30]byte)(unsafe.Pointer(addr))[:size]
}

// 危险: 类型转换绕过
func bypassTypeSystem(i int) *string {
    // 将 int 指针强转为 string 指针 - 未定义行为
    return (*string)(unsafe.Pointer(&i))
}

// 危险: 修改不可变数据
func modifyString(s string) {
    // 字符串在 Go 中是不可变的
    // 通过 unsafe 修改可能导致崩溃
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    data := (*[1 << 30]byte)(unsafe.Pointer(sh.Data))[:sh.Len]
    data[0] = 'X'  // 危险!
}
```

### 2. 检测规则

```regex
# unsafe 包使用
import\s+"unsafe"
unsafe\.Pointer
unsafe\.Sizeof
unsafe\.Offsetof
unsafe\.Alignof

# 危险的 uintptr 转换
uintptr\(unsafe\.Pointer
\(\*[^)]+\)\(unsafe\.Pointer
```

### 3. 安全替代

```go
// 使用 encoding/binary 替代 unsafe 类型转换
import "encoding/binary"

func intToBytes(i int32) []byte {
    buf := make([]byte, 4)
    binary.LittleEndian.PutUint32(buf, uint32(i))
    return buf
}

// 使用 reflect 替代 unsafe 内存操作
import "reflect"

func getFieldByName(obj interface{}, name string) interface{} {
    v := reflect.ValueOf(obj)
    f := v.FieldByName(name)
    return f.Interface()
}
```

---

## cgo 安全

### 1. 内存安全问题

```go
/*
#include <stdlib.h>
#include <string.h>

void vulnerable_copy(char* dst, char* src, int len) {
    memcpy(dst, src, len);  // 可能越界
}
*/
import "C"
import "unsafe"

// 危险: 缓冲区溢出
func copyData(dst, src []byte) {
    C.vulnerable_copy(
        (*C.char)(unsafe.Pointer(&dst[0])),
        (*C.char)(unsafe.Pointer(&src[0])),
        C.int(len(src)),  // 如果 src > dst，溢出
    )
}

// 危险: 悬挂指针
func dangling() *C.char {
    s := "hello"
    cs := C.CString(s)
    // 忘记 C.free(unsafe.Pointer(cs))
    return cs  // 返回后 Go 字符串可能被回收
}

// 安全: 正确管理内存
func safeCopy(dst, src []byte) {
    if len(src) > len(dst) {
        src = src[:len(dst)]
    }
    copy(dst, src)  // 使用 Go 内置 copy
}

func safeString() string {
    cs := C.some_c_function()
    defer C.free(unsafe.Pointer(cs))
    return C.GoString(cs)  // 复制到 Go 内存
}
```

### 2. 检测规则

```regex
# cgo 使用
import\s+"C"
/\*.*#include.*\*/
C\.[A-Za-z]+\(

# 危险的 cgo 模式
C\.CString\([^)]+\)(?!.*C\.free)
C\.malloc\(
unsafe\.Pointer.*C\.
```

---

## 命令注入

### 1. 危险模式

```go
import "os/exec"

// 危险: shell 执行用户输入
func runCommand(userInput string) error {
    cmd := exec.Command("sh", "-c", userInput)
    return cmd.Run()
}

// 危险: 字符串拼接
func runCommand(filename string) error {
    cmd := exec.Command("sh", "-c", "cat "+filename)
    return cmd.Run()
}

// 安全: 直接执行，无 shell
func runCommand(filename string) error {
    cmd := exec.Command("cat", filename)
    return cmd.Run()
}

// 更安全: 使用内置函数
func readFile(filename string) ([]byte, error) {
    // 验证路径
    cleanPath := filepath.Clean(filename)
    if !filepath.IsAbs(cleanPath) {
        cleanPath = filepath.Join(baseDir, cleanPath)
    }
    return os.ReadFile(cleanPath)
}
```

### 2. 检测规则

```regex
# 危险的命令执行
exec\.Command\s*\(\s*"(sh|bash|cmd)"\s*,\s*"-c"
exec\.Command.*\+\s*[a-zA-Z]
exec\.CommandContext.*\+

# syscall 执行
syscall\.Exec\s*\(
syscall\.ForkExec\s*\(
```

---

## SQL 注入

### 1. 危险模式

```go
import "database/sql"

// 危险: 字符串拼接
func getUser(db *sql.DB, id string) (*User, error) {
    query := "SELECT * FROM users WHERE id = " + id
    row := db.QueryRow(query)
    // ...
}

// 危险: fmt.Sprintf
func getUser(db *sql.DB, id string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
    row := db.QueryRow(query)
    // ...
}

// 安全: 参数化查询
func getUser(db *sql.DB, id string) (*User, error) {
    query := "SELECT * FROM users WHERE id = $1"
    row := db.QueryRow(query, id)
    // ...
}
```

### 2. GORM 特定

```go
import "gorm.io/gorm"

// 危险: Raw 拼接
func search(db *gorm.DB, name string) []User {
    var users []User
    db.Raw("SELECT * FROM users WHERE name = '" + name + "'").Scan(&users)
    return users
}

// 危险: Where 字符串
func search(db *gorm.DB, name string) []User {
    var users []User
    db.Where("name = '" + name + "'").Find(&users)
    return users
}

// 安全: 参数化
func search(db *gorm.DB, name string) []User {
    var users []User
    db.Where("name = ?", name).Find(&users)
    return users
}

// 安全: 结构体条件
func search(db *gorm.DB, name string) []User {
    var users []User
    db.Where(&User{Name: name}).Find(&users)
    return users
}
```

### 3. 检测规则

```regex
# 字符串拼接 SQL
(Query|Exec|QueryRow)\s*\([^?]*\+
(Query|Exec|QueryRow)\s*\(.*fmt\.Sprintf

# GORM 危险模式
\.Raw\s*\([^?]*\+
\.Where\s*\("[^"]*'\s*\+
\.Order\s*\([^)]*\+
```

---

## 路径遍历

### 1. 危险模式

```go
// 危险: 直接拼接路径
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    data, _ := os.ReadFile("/data/" + filename)
    w.Write(data)
}
// payload: ?file=../../../etc/passwd

// 安全: 路径清理和验证
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")

    // 清理路径
    cleanPath := filepath.Clean(filename)

    // 确保在允许的目录内
    fullPath := filepath.Join("/data", cleanPath)
    if !strings.HasPrefix(fullPath, "/data/") {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    data, err := os.ReadFile(fullPath)
    if err != nil {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }
    w.Write(data)
}
```

### 2. Zip Slip

```go
import "archive/zip"

// 危险: 解压时未验证路径
func unzip(src, dest string) error {
    r, _ := zip.OpenReader(src)
    defer r.Close()

    for _, f := range r.File {
        // 危险: f.Name 可能包含 ../
        path := filepath.Join(dest, f.Name)

        rc, _ := f.Open()
        outFile, _ := os.Create(path)  // 可能写入任意位置
        io.Copy(outFile, rc)
        // ...
    }
    return nil
}

// 安全: 验证解压路径
func unzip(src, dest string) error {
    r, _ := zip.OpenReader(src)
    defer r.Close()

    dest = filepath.Clean(dest) + string(os.PathSeparator)

    for _, f := range r.File {
        path := filepath.Join(dest, f.Name)

        // 验证路径在目标目录内
        if !strings.HasPrefix(path, dest) {
            return fmt.Errorf("illegal file path: %s", f.Name)
        }

        // ... 继续解压
    }
    return nil
}
```

---

## SSRF

```go
import "net/http"

// 危险: 未验证 URL
func fetchURL(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, _ := http.Get(url)
    io.Copy(w, resp.Body)
}
// payload: ?url=http://169.254.169.254/latest/meta-data/

// 安全: URL 白名单验证
var allowedHosts = map[string]bool{
    "api.example.com": true,
    "cdn.example.com": true,
}

func fetchURL(w http.ResponseWriter, r *http.Request) {
    rawURL := r.URL.Query().Get("url")

    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        http.Error(w, "Invalid URL", http.StatusBadRequest)
        return
    }

    // 检查协议
    if parsedURL.Scheme != "https" {
        http.Error(w, "Only HTTPS allowed", http.StatusBadRequest)
        return
    }

    // 检查主机白名单
    if !allowedHosts[parsedURL.Host] {
        http.Error(w, "Host not allowed", http.StatusBadRequest)
        return
    }

    // 检查内网 IP
    ips, _ := net.LookupIP(parsedURL.Hostname())
    for _, ip := range ips {
        if isPrivateIP(ip) {
            http.Error(w, "Private IP not allowed", http.StatusBadRequest)
            return
        }
    }

    resp, _ := http.Get(rawURL)
    io.Copy(w, resp.Body)
}

func isPrivateIP(ip net.IP) bool {
    private := []string{
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    }
    for _, cidr := range private {
        _, subnet, _ := net.ParseCIDR(cidr)
        if subnet.Contains(ip) {
            return true
        }
    }
    return false
}
```

---

## Web 框架特定漏洞

### Gin

```go
import "github.com/gin-gonic/gin"

// 危险: 信任代理头
r := gin.Default()
// 默认信任所有代理头，可能导致 IP 欺骗

// 安全: 配置信任代理
r.SetTrustedProxies([]string{"192.168.1.0/24"})

// 危险: 模板注入
r.GET("/hello", func(c *gin.Context) {
    name := c.Query("name")
    c.HTML(http.StatusOK, "index.tmpl", gin.H{
        "content": template.HTML(name),  // 未转义
    })
})
```

### Echo

```go
import "github.com/labstack/echo/v4"

// 危险: 绑定攻击
type User struct {
    Name  string `json:"name"`
    Admin bool   `json:"admin"`
}

e.POST("/user", func(c echo.Context) error {
    u := new(User)
    c.Bind(u)  // 用户可设置 Admin=true
    // ...
})

// 安全: 使用 DTO
type CreateUserDTO struct {
    Name string `json:"name"`
}
```

---

## 检测命令

```bash
# 竞态检测
go build -race ./...
go test -race ./...

# unsafe 使用
grep -rn "unsafe\." --include="*.go"

# cgo 使用
grep -rn 'import "C"' --include="*.go"

# SQL 注入
grep -rn "Query\|Exec\|QueryRow" --include="*.go" | grep "+"

# 命令执行
grep -rn "exec\.Command" --include="*.go"

# 路径操作
grep -rn "filepath\.Join\|os\.Open\|os\.ReadFile" --include="*.go"

# 静态分析工具
gosec ./...
staticcheck ./...
```

---

## 审计清单

```
[ ] 运行 go build -race 检测数据竞态
[ ] 搜索 unsafe 包使用，验证必要性
[ ] 检查 cgo 代码的内存管理
[ ] 检查 SQL 查询是否使用参数化
[ ] 检查命令执行是否有 shell 注入风险
[ ] 检查文件操作是否有路径遍历
[ ] 检查 HTTP 请求是否有 SSRF 风险
[ ] 检查 Web 框架配置 (信任代理、绑定等)
[ ] 运行 gosec 静态分析
[ ] 检查并发原语使用是否正确
```

---

## 最小 PoC 示例
```bash
# -race 并发检测
go test -race ./...

# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历
curl "http://localhost:8080/download?file=../../etc/passwd"
```

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
