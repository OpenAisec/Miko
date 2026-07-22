# 输入验证安全审计 (CWE-20)

> 覆盖 OWASP A03 | 输入验证不当 | 类型混淆 | 边界检查 | 格式验证
>
> 适用全语言通用规则

---

## 目录

1. [CWE-20 概述](#1-cwe-20-概述)
2. [输入验证缺失模式](#2-输入验证缺失模式)
3. [类型验证](#3-类型验证)
4. [边界检查](#4-边界检查)
5. [格式验证](#5-格式验证)
6. [多语言检测规则](#6-多语言检测规则)
7. [安全验证最佳实践](#7-安全验证最佳实践)

---

## 1. CWE-20 概述

### 1.1 风险定义

**CWE-20: 输入验证不当** 是所有注入类漏洞的根源，位列 CWE Top 25 第6位。

| 风险 | 说明 |
|------|------|
| **直接影响** | SQL注入、XSS、命令注入、路径遍历 |
| **间接影响** | 业务逻辑绕过、DoS、数据污染 |
| **CVSS** | 取决于下游漏洞，可达 9.8 |

### 1.2 验证层次

```
┌─────────────────────────────────────────────┐
│  客户端验证 (UX, 不可信)                      │
├─────────────────────────────────────────────┤
│  API网关/WAF验证 (边界防护, 粗粒度)           │
├─────────────────────────────────────────────┤
│  应用层验证 (核心, 必须)                      │  ← 审计重点
│  - 类型验证                                  │
│  - 边界检查                                  │
│  - 格式验证                                  │
│  - 业务规则验证                              │
├─────────────────────────────────────────────┤
│  数据层验证 (兜底, 约束)                      │
└─────────────────────────────────────────────┘
```

---

## 2. 输入验证缺失模式

### 2.1 直接使用未验证输入

```java
// 🔴 Java - 直接使用请求参数
@GetMapping("/search")
public List<Product> search(@RequestParam String keyword) {
    return productRepository.findByNameContaining(keyword);  // 无长度/字符限制
}

// 🔴 直接用于文件操作
@GetMapping("/download")
public void download(@RequestParam String filename, HttpServletResponse response) {
    File file = new File("/uploads/" + filename);  // 路径遍历
    // ...
}
```

```python
# 🔴 Python - 无验证的参数
@app.get("/users/{user_id}")
async def get_user(user_id):  # 类型未指定
    return await User.get(id=int(user_id))  # int() 可能抛异常

# 🔴 直接拼接
@app.get("/files")
async def get_file(path: str):  # 无格式验证
    return FileResponse(f"/data/{path}")
```

```javascript
// 🔴 Node.js - 无验证
app.get('/api/data', (req, res) => {
    const { page, limit } = req.query;  // 类型未验证
    const offset = page * limit;  // NaN 风险
    // ...
});

// 🔴 直接使用
app.post('/api/execute', (req, res) => {
    const { command } = req.body;  // 无白名单
    exec(command);  // 命令注入
});
```

```go
// 🔴 Go - 类型转换无错误处理
func handler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    num, _ := strconv.Atoi(id)  // 🔴 忽略错误
    // ...
}
```

### 2.2 验证绕过

```java
// 🔴 仅客户端验证
// 前端: if (age < 0 || age > 150) return false;
// 后端无验证，攻击者可直接发请求绕过

// 🔴 黑名单验证 (可绕过)
public boolean isValidFilename(String filename) {
    String[] blacklist = {"..", "/", "\\"};
    for (String bad : blacklist) {
        if (filename.contains(bad)) return false;
    }
    return true;  // 🔴 可用 URL 编码绕过: %2e%2e%2f
}

// 🔴 正则过于宽松
Pattern.matches("[a-zA-Z0-9]+", input);  // 🔴 允许空字符串
Pattern.matches(".*@.*\\..*", email);    // 🔴 匹配 @.
```

---

## 3. 类型验证

### 3.1 数值类型

```java
// 🔴 整数溢出
public void transfer(long amount) {
    if (amount <= 0) throw new IllegalArgumentException();
    account.balance -= amount;  // 🔴 未检查上限，可能溢出
}

// 🟢 安全: 完整边界检查
public void transfer(long amount) {
    if (amount <= 0 || amount > MAX_TRANSFER_AMOUNT) {
        throw new IllegalArgumentException("Invalid amount");
    }
    if (account.balance < amount) {
        throw new InsufficientFundsException();
    }
    account.balance -= amount;
}
```

```python
# 🔴 类型混淆
def calculate_discount(price, discount):
    return price * (1 - discount)  # discount 可能是字符串 "0.5"

# 🟢 安全: 类型强制
def calculate_discount(price: Decimal, discount: Decimal) -> Decimal:
    if not (0 <= discount <= 1):
        raise ValueError("Discount must be between 0 and 1")
    return price * (Decimal('1') - discount)
```

```javascript
// 🔴 JavaScript 类型陷阱
function processAge(age) {
    if (age > 0) {  // "10" > 0 为 true (字符串比较)
        return age + 1;  // "10" + 1 = "101"
    }
}

// 🟢 安全: 类型转换和验证
function processAge(age) {
    const numAge = Number(age);
    if (!Number.isInteger(numAge) || numAge < 0 || numAge > 150) {
        throw new Error('Invalid age');
    }
    return numAge + 1;
}
```

### 3.2 字符串类型

```java
// 🔴 空字符串/null 未处理
public User findUser(String username) {
    return userRepository.findByUsername(username);  // null/空串未检查
}

// 🟢 安全
public User findUser(String username) {
    if (username == null || username.isBlank()) {
        throw new IllegalArgumentException("Username required");
    }
    if (username.length() > 50) {
        throw new IllegalArgumentException("Username too long");
    }
    return userRepository.findByUsername(username.trim());
}
```

### 3.3 数组/集合类型

```java
// 🔴 数组索引未验证
public String getItem(String[] items, int index) {
    return items[index];  // ArrayIndexOutOfBoundsException
}

// 🔴 批量操作无限制
@PostMapping("/batch-delete")
public void batchDelete(@RequestBody List<Long> ids) {
    itemRepository.deleteAllByIdIn(ids);  // 🔴 无数量限制，可 DoS
}

// 🟢 安全
@PostMapping("/batch-delete")
public void batchDelete(@RequestBody @Size(max = 100) List<Long> ids) {
    if (ids == null || ids.isEmpty()) {
        throw new IllegalArgumentException("IDs required");
    }
    itemRepository.deleteAllByIdIn(ids);
}
```

---

## 4. 边界检查

### 4.1 数值边界

```java
// 🔴 分页参数无边界
@GetMapping("/list")
public Page<Item> list(@RequestParam int page, @RequestParam int size) {
    return itemRepository.findAll(PageRequest.of(page, size));  // size=1000000 -> OOM
}

// 🟢 安全
@GetMapping("/list")
public Page<Item> list(
    @RequestParam @Min(0) int page,
    @RequestParam @Min(1) @Max(100) int size) {
    return itemRepository.findAll(PageRequest.of(page, Math.min(size, 100)));
}
```

```python
# 🔴 金额边界
async def create_order(amount: float):
    order = Order(amount=amount)  # 负数? 超大数?

# 🟢 安全
async def create_order(amount: Decimal):
    if amount <= 0:
        raise ValueError("Amount must be positive")
    if amount > Decimal('1000000'):
        raise ValueError("Amount exceeds limit")
    order = Order(amount=amount)
```

### 4.2 长度边界

```java
// 🔴 字符串长度无限制
@PostMapping("/comment")
public void addComment(@RequestBody String content) {
    commentRepository.save(new Comment(content));  // 10MB 内容?
}

// 🟢 安全
@PostMapping("/comment")
public void addComment(@RequestBody @Size(min = 1, max = 5000) String content) {
    commentRepository.save(new Comment(content.trim()));
}
```

### 4.3 时间边界

```java
// 🔴 日期范围无限制
@GetMapping("/report")
public Report getReport(@RequestParam LocalDate start, @RequestParam LocalDate end) {
    return reportService.generate(start, end);  // 10年范围 -> 超时
}

// 🟢 安全
@GetMapping("/report")
public Report getReport(@RequestParam LocalDate start, @RequestParam LocalDate end) {
    if (start.isAfter(end)) {
        throw new IllegalArgumentException("Invalid date range");
    }
    if (ChronoUnit.DAYS.between(start, end) > 365) {
        throw new IllegalArgumentException("Range exceeds 1 year");
    }
    return reportService.generate(start, end);
}
```

---

## 5. 格式验证

### 5.1 邮箱格式

```java
// 🔴 弱正则
Pattern.matches(".*@.*", email);  // 匹配 "@"

// 🔴 过于复杂的正则 (ReDoS 风险)
Pattern.matches("^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$", email);

// 🟢 安全: 使用验证库
import org.apache.commons.validator.routines.EmailValidator;
EmailValidator.getInstance().isValid(email);

// 或 Bean Validation
@Email
private String email;
```

### 5.2 URL 格式

```java
// 🔴 仅检查前缀
if (url.startsWith("http://") || url.startsWith("https://")) {
    fetch(url);  // 可能是 http://internal-server
}

// 🟢 安全: URL 解析 + 白名单
try {
    URL parsed = new URL(url);
    if (!ALLOWED_HOSTS.contains(parsed.getHost())) {
        throw new SecurityException("Host not allowed");
    }
    if (!"https".equals(parsed.getProtocol())) {
        throw new SecurityException("HTTPS required");
    }
    fetch(url);
} catch (MalformedURLException e) {
    throw new IllegalArgumentException("Invalid URL");
}
```

### 5.3 文件名格式

```java
// 🔴 允许路径分隔符
public void saveFile(String filename, byte[] content) {
    Files.write(Paths.get("/uploads/" + filename), content);  // ../../../etc/passwd
}

// 🟢 安全
public void saveFile(String filename, byte[] content) {
    // 只允许字母数字和点
    if (!filename.matches("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$")) {
        throw new IllegalArgumentException("Invalid filename");
    }
    // 不允许特殊扩展名
    String ext = FilenameUtils.getExtension(filename).toLowerCase();
    if (DANGEROUS_EXTENSIONS.contains(ext)) {
        throw new SecurityException("File type not allowed");
    }
    Path path = Paths.get("/uploads").resolve(filename).normalize();
    if (!path.startsWith("/uploads")) {
        throw new SecurityException("Path traversal detected");
    }
    Files.write(path, content);
}
```

### 5.4 JSON 格式

```java
// 🔴 深度嵌套 DoS
ObjectMapper mapper = new ObjectMapper();
JsonNode node = mapper.readTree(jsonInput);  // {"a":{"a":{"a":...}}} 1000层

// 🟢 安全: 限制深度
ObjectMapper mapper = new ObjectMapper();
mapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
mapper.getFactory().setStreamReadConstraints(
    StreamReadConstraints.builder()
        .maxNestingDepth(50)
        .maxStringLength(10_000_000)
        .build()
);
```

---

## 6. 多语言检测规则

### 6.1 检测命令

```bash
# 查找无验证的参数使用
# Java
rg -n "@RequestParam\s+\w+\s+\w+[^@]" --glob "*.java" | grep -v "@Valid\|@NotNull\|@Size\|@Min\|@Max"

# Python/FastAPI
rg -n "def.*\(.*:.*\):" --glob "*.py" | grep -v "Annotated\|Query\|Path\|Body"

# Node.js
rg -n "req\.(body|query|params)\." --glob "*.{js,ts}" | grep -v "validate\|sanitize\|joi\|zod"

# Go
rg -n "r\.URL\.Query\(\)|r\.FormValue\(" --glob "*.go"

# 查找可能的边界问题
rg -n "parseInt|parseFloat|Number\(|int\(|float\(|strconv\.Atoi" --glob "*.{js,ts,py,go}"

# 查找未处理的错误
rg -n ", _\s*:?=|, err\s*:?=.*\n\s*[^if]" --glob "*.go"
```

### 6.2 框架验证注解/装饰器

| 语言/框架 | 验证方式 | 示例 |
|-----------|----------|------|
| Java/Spring | Bean Validation | `@Valid @NotNull @Size @Min @Max @Pattern @Email` |
| Python/Pydantic | 类型注解 | `Field(min_length=1, max_length=100)` |
| Python/FastAPI | Query/Path | `Query(min_length=1, regex="^[a-z]+$")` |
| Node.js/Joi | Schema | `Joi.string().min(1).max(100).email()` |
| Node.js/Zod | Schema | `z.string().min(1).max(100).email()` |
| Go/validator | Struct tags | `` `validate:"required,min=1,max=100,email"` `` |
| .NET | DataAnnotations | `[Required] [StringLength(100)] [Range(0,100)]` |
| Ruby/Rails | ActiveModel | `validates :name, presence: true, length: { maximum: 100 }` |

---

## 7. 安全验证最佳实践

### 7.1 验证策略

```
1. 白名单优于黑名单
2. 服务端验证是必须的，客户端验证是可选的
3. 验证后立即使用，避免 TOCTOU
4. 使用成熟的验证库，避免自己实现
5. 记录验证失败日志（但不记录敏感数据）
```

### 7.2 通用验证清单

```markdown
## 输入验证审计清单

### 类型验证
- [ ] 数值参数是否指定类型
- [ ] 字符串参数是否有长度限制
- [ ] 数组参数是否有大小限制
- [ ] 日期参数是否有格式和范围限制

### 边界检查
- [ ] 数值是否有最小/最大值限制
- [ ] 分页参数是否有上限
- [ ] 批量操作是否有数量限制

### 格式验证
- [ ] 邮箱/URL/手机号是否使用标准验证
- [ ] 文件名是否过滤路径字符
- [ ] 自定义格式是否有正则验证

### 业务验证
- [ ] 状态转换是否验证前置条件
- [ ] 金额计算是否验证精度和范围
- [ ] 引用关系是否验证存在性
```

### 7.3 框架配置示例

```java
// Spring Boot 全局验证配置
@Configuration
public class ValidationConfig {
    @Bean
    public Validator validator() {
        ValidatorFactory factory = Validation.byDefaultProvider()
            .configure()
            .messageInterpolator(new ParameterMessageInterpolator())
            .buildValidatorFactory();
        return factory.getValidator();
    }
}

// Controller 使用
@PostMapping("/users")
public User createUser(@Valid @RequestBody UserRequest request) {
    return userService.create(request);
}
```

```python
# FastAPI/Pydantic 验证
from pydantic import BaseModel, Field, validator

class UserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: EmailStr
    age: int = Field(ge=0, le=150)

    @validator('username')
    def username_not_reserved(cls, v):
        if v.lower() in ['admin', 'root', 'system']:
            raise ValueError('Reserved username')
        return v
```

```typescript
// NestJS/class-validator
import { IsEmail, IsInt, IsString, Length, Min, Max } from 'class-validator';

class CreateUserDto {
    @IsString()
    @Length(3, 50)
    @Matches(/^[a-zA-Z0-9_]+$/)
    username: string;

    @IsEmail()
    email: string;

    @IsInt()
    @Min(0)
    @Max(150)
    age: number;
}
```
