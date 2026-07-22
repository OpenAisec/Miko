# Web 逆向参考手册

> 本文档包含 Web 逆向的详细加密分析代码和安全测试脚本，作为主文件的补充参考。

## 一、加密库指纹识别

先确定用了哪个加密库，再针对性分析。

```bash
# 在 JS bundle 中搜索加密库特征
curl -s https://example.com/static/js/app.js | grep -oiE \
  '(CryptoJS|JSEncrypt|jsencrypt|forge|crypto-js|aes|des|tripledes|rsa|sm2|sm4|gm|biginteger|bn\.js|elliptic|tweetnacl|sjcl)' \
  | sort | uniq -c | sort -rn
```

| 特征关键词 | 加密库 | 典型用途 |
|-----------|--------|---------|
| `JSEncrypt`, `setPublicKey`, `encrypt()` | jsencrypt | RSA 前端加密密码 |
| `CryptoJS.AES`, `CryptoJS.DES`, `CryptoJS.MD5` | crypto-js | 对称加密/哈希 |
| `forge.cipher`, `forge.random`, `forge.pki` | node-forge | RSA/AES/证书 |
| `sm2`, `sm3`, `sm4`, `gmCrypt` | sm-crypto/gm-crypto | 国密算法 |
| `nacl`, `tweetnacl`, `box`, `secretbox` | TweetNaCl | Ed25519/X25519 加密 |
| `sjcl.encrypt`, `sjcl.decrypt` | Stanford JS Crypto | AES-GCM |
| `BigInteger`, `bignum` | jsbn | RSA 大数运算 |
| `aes-ecb`, `aes-cbc`, `aes-gcm`, `aes-ctr` | Web Crypto API / 手动实现 | 浏览器原生加密 |
| `SubtleCrypto`, `crypto.subtle` | Web Crypto API | 现代浏览器原生 |
| `wasm`, `Module._malloc`, `ccall` | C/C++ 编译的 WASM 加密 | 高强度混淆 |

## 二、常见加密算法逆向

### RSA 加密（密码传输最常见）

```javascript
// 特征：公钥加密，私钥解密。前端通常只用公钥加密密码。
// 搜索关键词：setPublicKey, JSEncrypt, RSA, publicKey, encrypt

// 方法 1：Hook JSEncrypt 实例
const origEncrypt = JSEncrypt.prototype.encrypt;
JSEncrypt.prototype.encrypt = function(str) {
  console.log('[RSA] 公钥:', this.getPublicKey());
  console.log('[RSA] 明文:', str);
  const result = origEncrypt.call(this, str);
  console.log('[RSA] 密文:', result);
  return result;
};

// 方法 2：直接拦截表单提交
document.querySelector('form').addEventListener('submit', function(e) {
  const passwordField = this.querySelector('input[type="password"]');
  console.log('密码字段名:', passwordField.name);
  console.log('密码字段值:', passwordField.value);  // 加密前的明文
});
```

**Python 复现：**
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

def rsa_encrypt(plaintext: str, public_key_pem: str) -> str:
    """复现前端 JSEncrypt 的 RSA 加密"""
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

# 公钥通常从页面 JS 或接口获取
pub_key = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...
-----END PUBLIC KEY-----"""
encrypted_pwd = rsa_encrypt("mypassword123", pub_key)
```

### AES 加密（参数加密/响应解密）

```javascript
// Hook CryptoJS.AES.encrypt
const origAESEncrypt = CryptoJS.AES.encrypt;
CryptoJS.AES.encrypt = function(message, key, cfg) {
  console.log('[AES] 明文:', typeof message === 'string' ? message : message.toString());
  console.log('[AES] 密钥:', typeof key === 'string' ? key : key.toString());
  console.log('[AES] IV:', cfg?.iv?.toString());
  console.log('[AES] 模式:', cfg?.mode?.toString());
  console.log('[AES] 填充:', cfg?.padding?.toString());
  const result = origAESEncrypt.call(this, message, key, cfg);
  console.log('[AES] 密文:', result.toString());
  return result;
};

// Hook CryptoJS.AES.decrypt（用于响应解密）
const origAESDecrypt = CryptoJS.AES.decrypt;
CryptoJS.AES.decrypt = function(ciphertext, key, cfg) {
  console.log('[AES-Decrypt] 密文:', typeof ciphertext === 'string' ? ciphertext : ciphertext.toString());
  console.log('[AES-Decrypt] 密钥:', typeof key === 'string' ? key : key.toString());
  const result = origAESDecrypt.call(this, ciphertext, key, cfg);
  console.log('[AES-Decrypt] 明文:', result.toString(CryptoJS.enc.Utf8));
  return result;
};
```

**Python 复现：**
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_cbc_encrypt(plaintext: str, key: str, iv: str) -> str:
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    return base64.b64encode(cipher.encrypt(padded)).decode('utf-8')

def aes_cbc_decrypt(ciphertext_b64: str, key: str, iv: str) -> str:
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    decrypted = cipher.decrypt(base64.b64decode(ciphertext_b64))
    return unpad(decrypted, AES.block_size).decode('utf-8')

def aes_ecb_encrypt(plaintext: str, key: str) -> str:
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    return base64.b64encode(cipher.encrypt(padded)).decode('utf-8')
```

### SM2/SM4 国密算法

```javascript
// Hook SM2 加密
const origSM2 = sm2.doEncrypt;
sm2.doEncrypt = function(msg, publicKey, cipherMode) {
  console.log('[SM2] 明文:', msg);
  console.log('[SM2] 公钥:', publicKey);
  console.log('[SM2] 模式:', cipherMode);
  const result = origSM2.call(this, msg, publicKey, cipherMode);
  console.log('[SM2] 密文:', result);
  return result;
};

// Hook SM4 加密
const origSM4 = sm4.encrypt;
sm4.encrypt = function(msg, key) {
  console.log('[SM4] 明文:', msg);
  console.log('[SM4] 密钥:', key);
  const result = origSM4.call(this, msg, key);
  console.log('[SM4] 密文:', result);
  return result;
};
```

**Python 复现：**
```python
# pip install gmssl
from gmssl import sm2, sm4
import base64

def sm2_encrypt(plaintext: str, public_key: str) -> str:
    crypt = sm2.CryptSM2(public_key=public_key, private_key='')
    encrypted = crypt.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def sm4_ecb_encrypt(plaintext: str, key: str) -> str:
    crypt = sm4.CryptSM4()
    crypt.set_key(key.encode('utf-8'), sm4.SM4_ENCRYPT)
    encrypted = crypt.crypt_ecb(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def sm4_cbc_encrypt(plaintext: str, key: str, iv: str) -> str:
    crypt = sm4.CryptSM4()
    crypt.set_key(key.encode('utf-8'), sm4.SM4_ENCRYPT)
    encrypted = crypt.crypt_cbc(iv.encode('utf-8'), plaintext.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')
```

### DES/3DES 加密

```python
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad
import base64

def des_ecb_encrypt(plaintext: str, key: str) -> str:
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'), DES.block_size)
    return base64.b64encode(cipher.encrypt(padded)).decode('utf-8')

def triple_des_cbc_encrypt(plaintext: str, key: str, iv: str) -> str:
    cipher = DES3.new(key.encode('utf-8'), DES3.MODE_CBC, iv.encode('utf-8'))
    padded = pad(plaintext.encode('utf-8'), DES3.block_size)
    return base64.b64encode(cipher.encrypt(padded)).decode('utf-8')
```

## 三、签名机制逆向

### Hook 签名函数

```javascript
// 通用 Hook：拦截所有 MD5/SHA 调用
const origMD5 = CryptoJS.MD5;
CryptoJS.MD5 = function(msg) {
  const result = origMD5.call(this, msg);
  console.log('[MD5] 输入:', msg.toString());
  console.log('[MD5] 输出:', result.toString());
  return result;
};

const origSHA256 = CryptoJS.SHA256;
CryptoJS.SHA256 = function(msg) {
  const result = origSHA256.call(this, msg);
  console.log('[SHA256] 输入:', msg.toString());
  console.log('[SHA256] 输出:', result.toString());
  return result;
};

const origHmacSHA256 = CryptoJS.HmacSHA256;
CryptoJS.HmacSHA256 = function(msg, key) {
  const result = origHmacSHA256.call(this, msg, key);
  console.log('[HMAC-SHA256] 消息:', msg.toString());
  console.log('[HMAC-SHA256] 密钥:', key.toString());
  console.log('[HMAC-SHA256] 结果:', result.toString());
  return result;
};
```

**Python 复现：**
```python
import hashlib, hmac, time

def md5_sign(params: dict, secret: str) -> str:
    sorted_str = '&'.join(f'{k}={v}' for k, v in sorted(params.items()))
    return hashlib.md5(f'{sorted_str}&secret={secret}'.encode()).hexdigest()

def hmac_sha256_sign(message: str, secret: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

def timestamp_nonce_sign(params: dict, app_secret: str) -> str:
    ts = str(int(time.time() * 1000))
    nonce = 'random_string_here'
    sorted_params = '&'.join(f'{k}={v}' for k, v in sorted(params.items()))
    return hashlib.sha256(f'{ts}{nonce}{sorted_params}{app_secret}'.encode()).hexdigest()
```

## 四、响应数据解密

```javascript
// 拦截 XMLHttpRequest 响应
const origOpen = XMLHttpRequest.prototype.open;
const origSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open = function(method, url, ...args) {
  this._url = url;
  return origOpen.call(this, method, url, ...args);
};
XMLHttpRequest.prototype.send = function(body) {
  this.addEventListener('load', function() {
    if (this.responseText && this.responseText.length > 100) {
      console.log('[Response]', this._url, this.responseText.substring(0, 200));
    }
  });
  return origSend.call(this, body);
};

// 拦截 fetch 响应
const origFetch = window.fetch;
window.fetch = function(...args) {
  return origFetch.apply(this, args).then(response => {
    response.clone().text().then(body => {
      console.log('[Fetch]', args[0], body.substring(0, 200));
    });
    return response;
  });
};
```

## 五、WASM/字节码加密

```javascript
// Hook WASM 导出函数
const origInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = function(buffer, imports) {
  console.log('[WASM] 加载模块，大小:', buffer.byteLength);
  return origInstantiate.call(this, buffer, imports).then(result => {
    const exports = result.instance.exports;
    console.log('[WASM] 导出函数:', Object.keys(exports));
    for (const [name, fn] of Object.entries(exports)) {
      if (typeof fn === 'function') {
        const origFn = fn;
        exports[name] = function(...args) {
          console.log(`[WASM.${name}] 入参:`, args);
          const result = origFn.apply(this, args);
          console.log(`[WASM.${name}] 返回:`, result);
          return result;
        };
      }
    }
    return result;
  });
};
// 下载 .wasm 文件后用 wasm-decompile / Ghidra 静态分析
```

## 六、JS 混淆还原

```bash
# synchrony - javascript-obfuscator 专用
npm install -g synchrony
synchrony deobfuscate input.js -o output.js

# webcrack - webpack + obfuscator 还原
npm install -g webcrack
webcrack input.js -o output_dir

# de4js - 在线反混淆器: https://lelinhtinh.github.io/de4js/
# JStillery - 常量折叠 + 死代码消除
```

**动态调试技巧：**
1. Sources 面板 → 搜索 `encrypt` / `sign` / `hash`
2. 在匹配函数第一行打断点
3. 触发登录/请求 → 断点命中 → 查看调用栈
4. 沿调用栈向上找到密钥、IV 等参数来源

## 七、密钥提取技巧

```javascript
// 1. 硬编码在 JS 中（最常见）
// 搜索 Base64 字符串
curl -s https://example.com/static/js/app.js | \
  grep -oP '["'"'"'][A-Za-z0-9+/=]{16,}["'"'"']' | sort -u

// 2. 从页面 HTML 中提取
document.querySelectorAll('[data-key], [data-token], [data-secret], [name="csrf"]')

// 3. 从接口响应获取（首次加载时后端下发密钥/公钥）

// 4. 从 Cookie 中获取
document.cookie.split(';').forEach(c => console.log(c.trim()))
```

## 八、授权安全测试

### 认证安全测试

```bash
# 暴力破解防护检测
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://target.com/api/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"testuser","password":"wrong'$i'"}')
  echo "尝试 $i: HTTP $STATUS"
done

# 用户名枚举检测
curl -s -X POST https://target.com/api/login \
  -d '{"username":"admin","password":"wrong"}' | jq '.message'
curl -s -X POST https://target.com/api/login \
  -d '{"username":"nonexistent","password":"wrong"}' | jq '.message'
# 如果 message 不同 → 存在用户名枚举漏洞
```

### Session 安全测试

```bash
# Session 固定攻击测试
BEFORE=$(curl -sI https://target.com/login | grep -i 'set-cookie' | grep -oP 'session=\K[^;]+')
curl -s -c cookies.txt -X POST https://target.com/login \
  -d "username=test&password=test" > /dev/null
AFTER=$(curl -sI -b cookies.txt https://target.com/dashboard | grep -i 'set-cookie' | grep -oP 'session=\K[^;]+')
echo "登录前: $BEFORE  登录后: $AFTER"
# 如果相同 → Session 固定漏洞

# Cookie 安全属性检查
curl -sI https://target.com/login | grep -i 'set-cookie'
# 检查：HttpOnly, Secure, SameSite
```

### 授权绕过测试

```bash
# 水平越权
curl -s https://target.com/api/users/123 -H 'Authorization: Bearer <user_A_token>' | jq '.data'
# 换成其他用户 ID → 能返回数据 → 水平越权

# 垂直越权
curl -s https://target.com/api/admin/users -H 'Authorization: Bearer <normal_user_token>' | jq '.data'

# JWT alg=none 攻击
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

### 密码存储审计

```bash
# 密码重置流程检查
curl -s -X POST https://target.com/api/forgot-password \
  -d '{"email":"test@example.com"}' | jq '.message'
curl -s -X POST https://target.com/api/forgot-password \
  -d '{"email":"nonexistent@example.com"}' | jq '.message'
# 响应不同 → 邮箱枚举漏洞
```

### 安全测试报告模板

```markdown
## 安全测试报告

### 测试信息
- 目标：example.com
- 授权方：[公司名]
- 测试时间：YYYY-MM-DD ~ YYYY-MM-DD
- 测试范围：登录认证、用户管理、数据接口

### 发现的漏洞

#### [高危] 用户名枚举
- **端点：** POST /api/login
- **描述：** 不同用户名返回不同错误信息
- **修复建议：** 统一返回"用户名或密码错误"

#### [中危] Session 固定
- **描述：** 登录前后 Session ID 未变化
- **修复建议：** 登录成功后重新生成 Session ID
```

### 安全测试工具

| 工具 | 用途 | 适用场景 |
|------|------|---------|
| **Burp Suite** | 代理抓包 + 漏洞扫描 | 全流程渗透测试 |
| **sqlmap** | SQL 注入检测 | 参数化测试 |
| **nuclei** | 模板化漏洞扫描 | 批量已知漏洞检测 |
| **nikto** | Web 服务器扫描 | 配置错误检测 |
| **OWASP ZAP** | 开源代理 + 扫描器 | 替代 Burp 的免费方案 |
| **hydra** | 暴力破解 | 登录接口强度测试 |
| **jwt_tool** | JWT 安全测试 | JWT 伪造/混淆攻击 |

## 九、加密分析工具

| 工具 | 用途 | 命令/入口 |
|------|------|----------|
| **synchrony** | javascript-obfuscator 反混淆 | `synchrony deobfuscate input.js -o out.js` |
| **webcrack** | webpack + obfuscator 还原 | `webcrack input.js -o dir` |
| **de4js** | 在线 JS 反混淆器 | 网页工具 |
| **CyberChef** | 编码/解码/加解密瑞士军刀 | 网页工具 / 本地 |
| **jwt.io** | JWT 在线解码调试 | 网页工具 |
| **hashcat** | 哈希破解 | `hashcat -m 0 hash.txt wordlist` |
| **openssl** | 证书/密钥/加密命令行 | `openssl enc -aes-256-cbc -in plain -out enc` |
| **wasm-decompile** | WASM 反编译 | `wasm-decompile module.wasm` |
