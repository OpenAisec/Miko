# Cryptography Security Audit

> 密码学安全审计模块
> 覆盖: 加密算法、密钥管理、TLS/SSL、哈希函数

---

## Overview

密码学错误是导致数据泄露的主要原因之一。本模块覆盖常见的密码学漏洞：弱算法、不安全模式、密钥管理不当、随机数问题。

---

## 弱加密算法

### 1. 已淘汰的算法

```python
# 危险: DES (56-bit 密钥)
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)

# 危险: 3DES (被 NIST 废弃)
from Crypto.Cipher import DES3

# 危险: RC4 (多个漏洞)
from Crypto.Cipher import ARC4

# 危险: Blowfish (过时)
from Crypto.Cipher import Blowfish

# 安全: AES-256
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
```

```java
// 危险: DES
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

// 危险: RC4
Cipher cipher = Cipher.getInstance("RC4");

// 安全: AES-256-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

### 2. 检测命令

```bash
# Python
grep -rn "DES\|DES3\|ARC4\|RC4\|Blowfish\|RC2" --include="*.py"

# Java
grep -rn "DES/\|RC4\|RC2\|Blowfish" --include="*.java"

# 通用
grep -rn "MD5\|SHA1\|SHA-1" --include="*.py" --include="*.java" --include="*.js"
```

---

## 不安全的加密模式

### 1. ECB 模式

```python
# 危险: ECB 模式 (相同明文产生相同密文，可分析模式)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

# 攻击: 相同的块产生相同的密文
# 经典例子: ECB 企鹅图像

# 安全: 使用 GCM (带认证的加密)
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# 或 CBC (需要 HMAC 认证)
cipher = AES.new(key, AES.MODE_CBC, iv)
```

### 2. IV 重用

```python
# 危险: 固定 IV
IV = b'0' * 16  # 硬编码 IV
cipher = AES.new(key, AES.MODE_CBC, IV)

# 危险: 可预测 IV
iv = str(int(time.time())).encode().ljust(16, b'\x00')

# 安全: 随机 IV
from Crypto.Random import get_random_bytes
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
# 将 IV 与密文一起存储
ciphertext = iv + cipher.encrypt(padded_data)

# GCM 模式自动生成 nonce
cipher = AES.new(key, AES.MODE_GCM)
nonce = cipher.nonce
```

### 3. Padding Oracle

```python
# 危险: 暴露填充错误
def decrypt(ciphertext):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except ValueError as e:
        # 暴露了是填充错误还是其他错误!
        if "Padding" in str(e):
            raise PaddingError()  # 可被利用
        raise

# 安全: 使用认证加密 (GCM) 或统一错误
def decrypt(ciphertext):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception:
        raise DecryptionError("Decryption failed")  # 统一错误
```

### 4. 检测命令

```bash
# ECB 模式
grep -rn "MODE_ECB\|ECB/\|/ECB/" --include="*.py" --include="*.java"

# 固定 IV
grep -rn "iv\s*=.*b['\"]0\|IV\s*=.*\\\\x00" --include="*.py"
grep -rn "new IvParameterSpec.*new byte\[16\]" --include="*.java"
```

---

## 弱哈希函数

### 1. 密码存储

```python
# 危险: MD5/SHA1 存储密码
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha1(password.encode()).hexdigest()

# 危险: 无盐哈希
password_hash = hashlib.sha256(password.encode()).hexdigest()

# 安全: bcrypt (自动加盐，自适应)
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# 安全: Argon2 (推荐)
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)

# 安全: scrypt
import hashlib
password_hash = hashlib.scrypt(
    password.encode(),
    salt=os.urandom(16),
    n=2**14, r=8, p=1
)
```

### 2. 数据完整性

```python
# 危险: MD5 完整性检查 (碰撞攻击)
file_hash = hashlib.md5(file_content).hexdigest()

# 安全: SHA-256+
file_hash = hashlib.sha256(file_content).hexdigest()

# 更安全: HMAC (带密钥)
import hmac
mac = hmac.new(secret_key, file_content, 'sha256').hexdigest()
```

### 3. 检测命令

```bash
# 弱哈希用于密码
grep -rn "md5\|sha1\|MD5\|SHA1" --include="*.py" --include="*.java" | grep -i "password"

# 无盐哈希
grep -rn "hashlib\.(md5|sha)\|MessageDigest\.getInstance" --include="*.py" --include="*.java"
```

---

## 密钥管理

### 1. 硬编码密钥

```python
# 危险: 硬编码
SECRET_KEY = "my_secret_key_123"
API_KEY = "sk-xxxx"
DB_PASSWORD = "password123"

# 危险: 源码中的密钥
AES_KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

# 安全: 环境变量
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY not set")

# 安全: 密钥管理服务
# AWS KMS
import boto3
kms = boto3.client('kms')
response = kms.decrypt(CiphertextBlob=encrypted_key)
key = response['Plaintext']

# HashiCorp Vault
import hvac
client = hvac.Client(url='https://vault.example.com')
secret = client.secrets.kv.read_secret_version(path='myapp/config')
key = secret['data']['data']['encryption_key']
```

### 2. 弱密钥生成

```python
# 危险: 可预测的随机数
import random
key = ''.join(random.choices('abcdef0123456789', k=32))

# 危险: 时间种子
random.seed(int(time.time()))
key = random.randbytes(32)

# 安全: 密码学安全的随机数
import secrets
key = secrets.token_bytes(32)

# Python 3.6+
from Crypto.Random import get_random_bytes
key = get_random_bytes(32)

# Java
SecureRandom random = new SecureRandom();
byte[] key = new byte[32];
random.nextBytes(key);
```

### 3. 密钥派生

```python
# 危险: 直接使用密码作为密钥
password = "user_password"
key = password.encode().ljust(32, b'\x00')  # 弱!

# 安全: PBKDF2
from Crypto.Protocol.KDF import PBKDF2
key = PBKDF2(password, salt, dkLen=32, count=600000)

# 安全: Argon2
from argon2.low_level import hash_secret_raw, Type
key = hash_secret_raw(
    password.encode(),
    salt,
    time_cost=2,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID
)
```

### 4. 检测命令

```bash
# 硬编码密钥
grep -rn "SECRET_KEY\s*=\s*['\"]" --include="*.py"
grep -rn "api[_-]?key\s*[:=]\s*['\"]" --include="*.py" --include="*.js"
grep -rn "password\s*[:=]\s*['\"]" --include="*.py" --include="*.yaml" --include="*.json"

# 弱随机数
grep -rn "random\.\|Random\(" --include="*.py" --include="*.java" | grep -v "SecureRandom\|secrets\."

# 直接用密码作密钥
grep -rn "password.*ljust\|password.*encode.*key" --include="*.py"
```

---

## TLS/SSL 配置

### 1. 证书验证

```python
# 危险: 禁用证书验证
import requests
requests.get(url, verify=False)

import urllib3
urllib3.disable_warnings()

# 危险: 信任所有证书
import ssl
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# 安全: 默认验证
requests.get(url)  # verify=True 是默认

# 安全: 证书 Pinning
requests.get(url, verify='/path/to/cert.pem')
```

```java
// 危险: 信任所有证书
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
};

// 安全: 使用默认 TrustManager
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, null, new SecureRandom());
```

### 2. TLS 版本

```python
# 危险: 允许旧版本 TLS
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # 可能允许 TLS 1.0

# 安全: 强制 TLS 1.2+
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
```

```java
// 危险: 允许 SSLv3, TLS 1.0
SSLContext.getInstance("SSL");

// 安全: TLS 1.2+
SSLContext context = SSLContext.getInstance("TLSv1.2");
```

### 3. 弱密码套件

```python
# 危险: 弱密码套件
context.set_ciphers('ALL')
context.set_ciphers('DEFAULT')

# 安全: 强密码套件
context.set_ciphers('ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20')
```

### 4. 检测命令

```bash
# 证书验证禁用
grep -rn "verify\s*=\s*False\|CERT_NONE\|check_hostname.*False" --include="*.py"
grep -rn "trustAllCerts\|TrustAllCertificates\|ALLOW_ALL" --include="*.java"

# 旧版 TLS
grep -rn "SSLv3\|TLSv1_0\|PROTOCOL_SSLv" --include="*.py" --include="*.java"

# 弱密码套件
grep -rn "set_ciphers.*ALL\|set_ciphers.*DEFAULT" --include="*.py"
```

---

## JWT 安全

### 1. 弱签名

```python
# 危险: 弱密钥
SECRET = "secret"

# 危险: 允许 none 算法
jwt.decode(token, options={"verify_signature": False})

# 危险: 不验证算法
def verify(token):
    return jwt.decode(token, SECRET, algorithms=jwt.algorithms.get_default_algorithms())

# 安全: 强密钥 + 明确算法
import secrets
SECRET = secrets.token_hex(32)

def verify(token):
    return jwt.decode(
        token,
        SECRET,
        algorithms=["HS256"],  # 明确指定
        options={"require": ["exp", "iat", "sub"]}
    )
```

### 2. RS256/HS256 混淆

```python
# 攻击: 将 RS256 改为 HS256，用公钥作为 HMAC 密钥
# 公钥通常是公开的

# 安全: 严格验证算法
def verify(token):
    header = jwt.get_unverified_header(token)

    if header['alg'] == 'RS256':
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
    elif header['alg'] == 'HS256':
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    else:
        raise ValueError("Unsupported algorithm")
```

---

## 审计清单

```
[ ] 检查是否使用弱加密算法 (DES, RC4, Blowfish)
[ ] 检查是否使用 ECB 模式
[ ] 检查 IV/Nonce 是否正确生成 (随机、不重用)
[ ] 检查是否使用认证加密 (GCM, ChaCha20-Poly1305)
[ ] 检查密码存储 (bcrypt, Argon2, scrypt)
[ ] 检查是否使用弱哈希 (MD5, SHA1) 于敏感场景
[ ] 检查密钥是否硬编码
[ ] 检查随机数生成是否安全
[ ] 检查密钥派生函数
[ ] 检查 TLS 证书验证
[ ] 检查 TLS 版本 (>=1.2)
[ ] 检查密码套件配置
[ ] 检查 JWT 配置 (算法、密钥强度)
```

---

## 最小 PoC 示例
```bash
# 检测 AES-ECB
rg -n "AES/ECB" --glob "*.{java,kt}"

# 检测弱哈希
rg -n "MD5|SHA1" --glob "*.{java,py,go,js,ts,cs,php}"

# TLS 过时协议探测
curl -Iv --tlsv1.0 https://api.example.com

# JWT 弱算法/混淆
rg -n "Algorithm\\.none|HS256|RS256" --glob "*.{java,js,ts,py,cs}"
```

## 安全配置示例
```java
// Spring Security PasswordEncoder
@Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(12); }

// Java TLS 配置
SSLContext ctx = SSLContext.getInstance("TLSv1.2");
```

```js
// Node jsonwebtoken
jwt.verify(token, secret, { algorithms: ["HS256"], audience: "api", issuer: "auth" });
```

```go
// Go tls.Config
&tls.Config{
  MinVersion: tls.VersionTLS12,
  CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
}
```

---

## 参考资源

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-327: Use of Broken Crypto](https://cwe.mitre.org/data/definitions/327.html)
- [Cryptography Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
