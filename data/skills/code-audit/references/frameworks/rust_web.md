# Rust Web Framework Security Audit Guide

> Rust Web 框架安全审计模块
> 适用于: Actix-web 4.x, Axum 0.7+, Rocket 0.5+, sqlx, diesel, sea-orm

## 识别特征

```toml
# Cargo.toml 识别
[dependencies]
actix-web = "4"
axum = "0.7"
rocket = "0.5"
sqlx = { version = "0.7", features = ["postgres"] }
diesel = { version = "2.1", features = ["postgres"] }

# 项目结构 (典型)
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── handlers/ (或 routes/)
│   ├── models/
│   ├── db/
│   └── middleware/
└── migrations/
```

---

## SQL 注入检测

```rust
// 危险: sqlx::query 原始字符串拼接
let q = format!("SELECT * FROM users WHERE name = '{}'", name);
sqlx::query(&q).fetch_all(&pool).await;  // ❌ Critical

// 危险: sqlx::query_as 拼接
let sql = format!("SELECT * FROM orders WHERE status = '{}' ORDER BY {}", status, sort);
sqlx::query_as::<_, Order>(&sql).fetch_all(&pool).await;  // ❌

// 危险: diesel raw_sql
diesel::sql_query(format!("SELECT * FROM users WHERE id = {}", id))
    .load::<User>(&mut conn);  // ❌

// 危险: sea-orm raw query
let stmt = Statement::from_string(
    DbBackend::Postgres,
    format!("SELECT * FROM users WHERE name = '{}'", input)  // ❌
);

// 审计正则 (Rust)
format!\s*\(.*SELECT|format!\s*\(.*INSERT|format!\s*\(.*UPDATE|format!\s*\(.*DELETE
sql_query\s*\(format!|query\s*\(&format!|query_as.*&format!

// 安全: sqlx 绑定参数
sqlx::query("SELECT * FROM users WHERE name = $1")
    .bind(&name)
    .fetch_all(&pool).await;  // ✓

// 安全: sqlx 宏 (编译时验证)
sqlx::query!("SELECT * FROM users WHERE name = $1", name)
    .fetch_all(&pool).await;  // ✓ 编译时类型检查

// 安全: diesel 查询构建器
users::table.filter(users::name.eq(&name)).load::<User>(&mut conn);  // ✓
```

---

## 路径遍历 (文件服务)

```rust
// 危险: Actix NamedFile 直接拼接
async fn download(path: web::Path<String>) -> actix_files::NamedFile {
    let filepath = format!("./uploads/{}", path.into_inner());
    NamedFile::open(filepath).unwrap()  // ❌ ../../../etc/passwd
}

// 危险: Axum 文件读取
async fn read_file(Path(name): Path<String>) -> impl IntoResponse {
    let content = tokio::fs::read_to_string(format!("./data/{}", name)).await;  // ❌
    content.unwrap_or_default()
}

// 危险: Rocket 文件路径
#[get("/files/<path>")]
async fn files(path: &str) -> Option<NamedFile> {
    NamedFile::open(format!("static/{}", path)).await.ok()  // ❌
}

// 审计正则
NamedFile::open\s*\(format!|read_to_string\s*\(format!.*\{
tokio::fs::(read|write).*format!|std::fs::(read|write).*format!

// 安全: 路径验证
async fn download(path: web::Path<String>) -> Result<NamedFile, Error> {
    let name = path.into_inner();
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(actix_web::error::ErrorBadRequest("invalid path"));
    }
    let filepath = PathBuf::from("./uploads").join(&name);
    let canonical = filepath.canonicalize()?;
    if !canonical.starts_with(std::fs::canonicalize("./uploads")?) {  // ✓
        return Err(actix_web::error::ErrorForbidden("forbidden"));
    }
    Ok(NamedFile::open(canonical)?)
}

// Actix ServeDir 安全 (tower-http)
// ServeDir 默认防止路径遍历, 但检查自定义处理
```

---

## SSRF 检测

```rust
// 危险: reqwest 请求用户控制的URL
async fn fetch(url: web::Query<FetchParams>) -> impl Responder {
    let resp = reqwest::get(&url.target).await.unwrap();  // ❌ SSRF
    resp.text().await.unwrap()
}

// 危险: hyper 客户端
let uri: Uri = user_input.parse().unwrap();
let resp = hyper_client.get(uri).await;  // ❌

// 审计正则
reqwest::(get|Client).*params|reqwest::get\s*\(&|\.get\s*\(&.*user
hyper::Uri.*parse\s*\(.*input|Client::new.*\.get\s*\(

// 安全: URL白名单 + 内网IP检查
use std::net::IpAddr;
use url::Url;

fn validate_url(input: &str) -> Result<Url, &'static str> {
    let url = Url::parse(input).map_err(|_| "invalid url")?;
    if url.scheme() != "https" { return Err("only https"); }

    let host = url.host_str().ok_or("no host")?;
    // DNS解析后检查IP
    let addr: IpAddr = host.parse()
        .or_else(|_| resolve_host(host))
        .map_err(|_| "resolve failed")?;

    if addr.is_loopback() || addr.is_private() || addr.is_link_local() {
        return Err("internal ip blocked");  // ✓
    }
    Ok(url)
}
```

---

## Unsafe 块和 FFI 边界

```rust
// 审计重点: unsafe 块
unsafe {
    let ptr = user_data.as_ptr();
    std::ptr::read(ptr.offset(offset as isize))  // ❌ 边界未检查
}

// 危险: FFI 调用无验证
extern "C" {
    fn external_process(data: *const u8, len: usize);
}
unsafe { external_process(input.as_ptr(), input.len()); }  // ❌ 信任外部数据

// 危险: transmute 类型转换
let value: u64 = unsafe { std::mem::transmute(user_bytes) };  // ❌

// 审计正则
unsafe\s*\{|std::mem::transmute|std::ptr::(read|write)|from_raw_parts
extern\s+"C"|#\[no_mangle\]

// 审计策略: 所有 unsafe 块需人工审查
// 1. 检查边界验证
// 2. 检查空指针处理
// 3. 检查 FFI 输入验证
// 4. 检查 lifetime 正确性
```

---

## 竞态条件 (共享状态)

```rust
// 危险: Arc<Mutex> 中的 TOCTOU
async fn transfer(state: web::Data<Arc<Mutex<BankState>>>, req: TransferReq) {
    let mut s = state.lock().unwrap();
    if s.balance >= req.amount {
        drop(s);  // ❌ 释放锁后再操作
        // 其他线程可能在此修改balance
        let mut s = state.lock().unwrap();
        s.balance -= req.amount;  // ❌ TOCTOU竞态
    }
}

// 危险: RwLock 读锁升级为写锁之间的竞态
let balance = state.read().unwrap().balance;  // 读
// 间隙: 其他线程可能修改
if balance >= amount {
    state.write().unwrap().balance -= amount;  // ❌ 竞态
}

// 审计正则
Arc::new\s*\(Mutex::new|Arc::new\s*\(RwLock::new
\.lock\(\).*drop\s*\(|\.read\(\).*\.write\(\)

// 安全: 在锁持有期间完成所有操作
async fn transfer(state: web::Data<Arc<Mutex<BankState>>>, req: TransferReq) {
    let mut s = state.lock().unwrap();
    if s.balance >= req.amount {
        s.balance -= req.amount;  // ✓ 锁未释放, 原子操作
    }
}

// 或使用 tokio::sync::Mutex 用于 async
let mut guard = state.lock().await;  // ✓ 异步锁
```

---

## JWT 处理 (jsonwebtoken crate)

```rust
// 危险: 不验证算法
let token_data = decode::<Claims>(
    &token,
    &DecodingKey::from_secret(secret),
    &Validation::default()  // ⚠️ 默认允许多种算法
)?;

// 危险: 关闭过期验证
let mut validation = Validation::new(Algorithm::HS256);
validation.validate_exp = false;  // ❌ 不验证过期

// 危险: 弱密钥
let key = DecodingKey::from_secret(b"secret");  // ❌ 弱密钥

// 审计正则
validate_exp\s*=\s*false|validate_aud\s*=\s*false
from_secret\s*\(b"[^"]{1,16}"\)|DecodingKey.*"secret"

// 安全: 严格验证
let mut validation = Validation::new(Algorithm::HS256);  // ✓ 明确算法
validation.set_audience(&["my-app"]);                    // ✓ 验证audience
validation.set_issuer(&["auth-server"]);                 // ✓ 验证issuer
// validate_exp 默认 true                                // ✓

let key = DecodingKey::from_secret(std::env::var("JWT_SECRET")?.as_bytes());  // ✓
let token_data = decode::<Claims>(&token, &key, &validation)?;
```

---

## CORS 配置

```rust
// 危险: Actix CORS 宽泛配置
use actix_cors::Cors;
Cors::permissive()                    // ❌ 允许所有
Cors::default()
    .allow_any_origin()               // ❌
    .allow_any_method()
    .supports_credentials()           // ❌ 与any_origin冲突

// 审计正则
Cors::permissive|allow_any_origin|allowed_origin\(".*\*"\)

// 安全:
Cors::default()
    .allowed_origin("https://app.example.com")  // ✓
    .allowed_methods(vec!["GET", "POST"])
    .allowed_headers(vec!["Authorization", "Content-Type"])
    .supports_credentials()
    .max_age(3600)
```

---

## 输入验证 (Extractor 缺失)

```rust
// 危险: 未验证的请求体
async fn create_user(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    // ❌ 使用通用 Value, 无类型/范围验证
    let name = body["name"].as_str().unwrap();
}

// 安全: 类型化提取器 + validator
#[derive(Deserialize, Validate)]
struct CreateUser {
    #[validate(length(min = 1, max = 100))]
    name: String,
    #[validate(email)]
    email: String,
}

async fn create_user(
    ValidatedJson(body): ValidatedJson<CreateUser>  // ✓ 自动验证
) -> impl IntoResponse { ... }

// 审计正则
Json\(.*\):\s*Json<serde_json::Value>|Json<Value>
Path\(.*\):\s*Path<String>  // 路径参数无验证
```

---

## 搜索模式汇总

```regex
# SQL注入
format!\s*\(.*SELECT|format!\s*\(.*INSERT|sql_query\s*\(format!

# 路径遍历
NamedFile::open\s*\(format!|tokio::fs::read.*format!

# SSRF
reqwest::(get|Client).*params|hyper::Uri.*parse.*input

# Unsafe
unsafe\s*\{|transmute|from_raw_parts

# 竞态
\.lock\(\).*drop|\.read\(\).*\.write\(\)

# JWT
validate_exp.*false|from_secret.*b"[^"]{1,16}"

# CORS
Cors::permissive|allow_any_origin

# 输入验证
Json<serde_json::Value>|Json<Value>
```

---

## 快速审计检查清单

```markdown
[ ] 检查 Cargo.toml 依赖版本 (cargo audit)
[ ] 搜索 format! 含 SQL 关键字 (SQL注入)
[ ] 搜索 NamedFile::open/tokio::fs::read 路径拼接 (路径遍历)
[ ] 搜索 reqwest/hyper 用户控制URL (SSRF)
[ ] 审查所有 unsafe 块 (内存安全)
[ ] 搜索 Arc<Mutex>/RwLock 检查竞态条件
[ ] 搜索 jsonwebtoken 配置 (JWT安全)
[ ] 搜索 Cors::permissive / allow_any_origin (CORS)
[ ] 搜索 Json<Value> 无类型化输入 (验证缺失)
[ ] 检查 .env / dotenv 中硬编码密钥
[ ] 搜索 unwrap()/expect() 在请求处理中 (DoS/panic)
[ ] 检查 tower-http/actix-middleware 安全头配置
```

---

## 最小 PoC 示例
```bash
# SQL 注入 (format! 拼接)
curl "http://localhost:8080/users?name=admin'OR'1'='1"

# 路径遍历
curl "http://localhost:8080/files/../../../etc/passwd"

# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
```

---

## Rust 特有安全优势与陷阱

```markdown
优势:
- 内存安全 (无 buffer overflow / use-after-free) — 在safe Rust中
- 类型系统防止大量逻辑错误
- sqlx 编译时查询检查

陷阱:
- unsafe 块打破所有安全保证
- unwrap()/panic 在 handler 中导致 DoS
- format! SQL 拼接仍然是注入向量
- 共享状态竞态 (逻辑竞态, 非内存竞态)
- FFI 边界无 Rust 安全保证
```

---

## 参考资源

- [Rust Secure Coding Guidelines](https://anssi-fr.github.io/rust-guide/)
- [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
- [RustSec Advisory Database](https://rustsec.org/advisories/)
- [OWASP Rust Security](https://cheatsheetseries.owasp.org/cheatsheets/Rust_Cheat_Sheet.html)
