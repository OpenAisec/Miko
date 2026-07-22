---
name: reverse-engineering
category: binary
description: Reverse engineering workflow for web, desktop binaries, mobile apps, network protocols, encryption, signatures, and dynamic analysis.
---
# 逆向工程

## 概述

逆向工程是从外部观察推断内部实现的过程。四个目标领域共享同一核心哲学：

**从可见到隐藏、从静态到动态、从简单到复杂。**

通用工作流：`目标识别 → 表面分析 → 深入分析 → 机制还原 → 复现`

不要上来就深入细节——先理解你面对的是什么，再选择合适的工具和方法。

## 何时使用

- **Web**：开发爬虫、提取 API、竞品技术分析、复现网站功能
- **二进制**：软件安全审计（授权）、恶意软件分析、互操作性开发
- **移动端**：App 安全审计、SDK 行为分析、第三方库审查
- **协议**：IoT 设备逆向、自定义协议还原、API 文档补全

**不适用：** 未授权的渗透测试、窃取商业数据、绕过付费墙、制作盗版软件。

> **法律提示：** 逆向工程必须在合法授权范围内进行。中国适用《网络安全法》《数据安全法》《计算机软件保护条例》。仅在拥有书面授权、CTF 比赛、Bug Bounty 计划或自有系统安全审计时进行。

## 通用基础

### 常见加密速查

不管逆向什么目标，加密是共性问题。以下是最常见的算法和 Python 复现一行式：

```python
import hashlib, hmac, base64
from Crypto.Cipher import AES, DES, DES3, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# --- 哈希 ---
hashlib.md5(b'text').hexdigest()
hashlib.sha256(b'text').hexdigest()
hmac.new(b'key', b'msg', hashlib.sha256).hexdigest()

# --- AES ---
aes = AES.new(b'16bytekey123456', AES.MODE_CBC, b'16byteiv12345678')
base64.b64encode(aes.encrypt(pad(b'plaintext', 16))).decode()  # 加密
unpad(AES.new(b'16bytekey123456', AES.MODE_CBC, b'16byteiv12345678').decrypt(base64.b64decode('密文')), 16).decode()  # 解密
# AES-ECB 无 IV: AES.new(key, AES.MODE_ECB)

# --- RSA ---
key = RSA.import_key(open('pub.pem').read())
base64.b64encode(PKCS1_v1_5.new(key).encrypt(b'plaintext')).decode()

# --- 国密 SM2/SM4 (pip install gmssl) ---
from gmssl import sm2, sm4
# SM2: sm2.CryptSM2(public_key=pub, private_key='').encrypt(plain)
# SM4: sm4.CryptSM4().set_key(key, sm4.SM4_ENCRYPT); crypt.crypt_ecb(plain)

# --- 编码检测 ---
# Base64 特征：A-Za-z0-9+/=，长度 4 的倍数
# Hex 特征：0-9a-f，长度偶数
# URL 编码：%XX 格式
```

### 调试基础

**断点策略：**

| 类型 | 适用场景 | 工具 |
|------|---------|------|
| 软件断点 | 代码级调试，函数入口 | x64dbg/GDB/LLDB |
| 条件断点 | 只在特定条件触发 | 所有调试器 |
| 硬件断点 | 反调试绕过、内存访问 | x64dbg/GDB (`watch`) |
| 内存断点 | 监控内存区域读写执行 | x64dbg/Cheat Engine |
| 日志断点 | 不暂停，只记录值 | x64dbg/WinDbg |

**调用栈阅读：**
```
关键原则：从下往上读（最下面是调用起点，最上面是当前执行点）
关注：函数名、参数值、返回地址、栈上的局部变量
```

**内存布局（x86/x64）：**
```
高地址  ┌─────────────┐
        │    Stack     │ ← 局部变量、函数参数（向下增长）
        ├─────────────┤
        │     ↓  ↑    │
        ├─────────────┤
        │    Heap      │ ← malloc/new 分配（向上增长）
        ├─────────────┤
        │    .bss      │ ← 未初始化全局变量
        ├─────────────┤
        │    .data     │ ← 已初始化全局变量
        ├─────────────┤
        │    .text     │ ← 代码段（只读、可执行）
低地址  └─────────────┘
```

### 逆向方法论

**静态 vs 动态分析选择：**

| 场景 | 推荐方法 | 原因 |
|------|---------|------|
| 代码逻辑清晰 | 静态分析 | 直接阅读伪代码更高效 |
| 有反调试/混淆 | 动态分析 | 运行时绕过比静态还原更快 |
| 加密算法还原 | 动态 + Hook | 直接拦截输入输出 |
| 漏洞发现 | 静态为主 | 需要全面审查代码路径 |
| 协议分析 | 动态抓包 | 运行时数据最真实 |

**发现记录模板：**
```markdown
## 逆向发现 #N
- **目标：** [文件/接口/协议]
- **方法：** [静态分析/动态调试/Hook/抓包]
- **发现：** [具体功能、算法、密钥、接口]
- **证据：** [截图/日志/代码片段]
- **复现：** [如何验证这个发现]
- **置信度：** [高/中/低]
```

## 第一部分：Web 逆向

### 1.1 技术指纹识别

**快速检测：**
```bash
# HTTP 头
curl -sI https://example.com | grep -iE "server|x-powered-by|x-framework|set-cookie"

# HTML 特征（前 100 行）
curl -s https://example.com | head -100
# 寻找：meta generator、script src、注释中的框架标识

# JS bundle 框架水印
curl -s https://example.com | grep -oP 'src="[^"]*\.js"' | head -5
curl -s https://example.com/static/js/main.js | grep -oE '(React|Vue|Angular|Next|Nuxt|Svelte)' | sort -u
```

**常见指纹表：**

| 特征 | 技术 | 特征 | 技术 |
|------|------|------|------|
| `__NEXT_DATA__` | Next.js | `__nuxt` / `__NUXT__` | Nuxt.js |
| `data-reactroot` | React | `ng-version` | Angular |
| `__vue__` / `data-v-` | Vue.js | `vite` 相关路径 | Vite |
| `Set-Cookie: PHPSESSID` | PHP | `Set-Cookie: JSESSIONID` | Java |
| `Set-Cookie: csrftoken` | Django | `/wp-content/` | WordPress |
| `X-Powered-By: Express` | Node.js | `.wxml/.wxss` | 微信小程序 |

### 1.2 前端架构分析

**SPA 路由提取：**
```javascript
// Vue Router
JSON.stringify(
  document.querySelector('#app').__vue_app__
    ?.config.globalProperties?.$router?.options?.routes
    ?.map(r => ({ path: r.path, children: r.children?.map(c => c.path) })),
  null, 2
)

// Next.js — 从 _buildManifest.js 获取页面路由
fetch('/_next/static/' + document.querySelector('script[src*="_buildManifest"]')
  ?.src.match(/_next\/static\/([^/]+)/)?.[1] + '/_buildManifest.js')
  .then(r => r.text()).then(console.log)
```

**构建产物分析：**
```bash
# 查找 source map（可能泄露完整源码）
curl -s https://example.com/static/js/main.js.map -o main.map
npx source-map-explorer main.map

# 提取路由和 API 端点
curl -s https://example.com/static/js/main.js | \
  grep -oP '"/(api|auth|admin|dashboard|user|login|register)[^"]*"' | sort -u
```

### 1.3 网络流量捕获

**DevTools 操作流程：**
1. Network 面板 → 勾选 "Preserve log"
2. 清空记录 → 执行目标操作（登录、搜索、翻页等）
3. 按类型筛选：XHR/Fetch 为主
4. 检查每个请求：URL、Headers、Body、Response、Status Code

**curl 复现模板：**
```bash
# 从 DevTools 右键 → Copy as cURL 获取完整命令
# 精简为最小参数后复现
curl -X POST 'https://example.com/api/v1/search' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"keyword":"test","page":1}' | jq '.data'
```

**批量端点发现：**
```bash
curl -s https://example.com/static/js/app.js | \
  grep -oP '["`]/api/[^"`\s]+["`]' | tr -d '"' | sort -u
```

### 1.4 认证逆向

**认证机制识别：**
```
Set-Cookie: sessionid=xxx  → Cookie-based
响应体 {token, refresh_token} → JWT-based
302 重定向到第三方 → OAuth/SSO
```

**登录流程追踪：**
```
1. Network 面板 → 输入账号密码 → 点击登录
2. 找到 POST 请求（通常 /login, /auth, /api/auth）
3. 分析请求体：{username, password, captcha?, csrf_token?}
4. 分析响应：Set-Cookie / token / redirect
5. 追踪后续请求如何携带凭证（Cookie / Authorization Header）
```

**JWT 解码：**
```bash
echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx" | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

**Token 提取：**
```javascript
// localStorage / sessionStorage
Object.keys(localStorage).forEach(k =>
  console.log(k, '=', localStorage[k].substring(0, 50))
);
```

### 1.5 加密速查表

| 加密库 | 特征关键词 | 典型用途 | 详细参考 |
|--------|-----------|---------|---------|
| JSEncrypt | `setPublicKey`, `encrypt()` | RSA 加密密码 | → references/web-re.md |
| CryptoJS.AES | `CryptoJS.AES`, `aes-encrypt` | 参数加密/响应解密 | → references/web-re.md |
| sm-crypto | `sm2`, `sm4`, `gmCrypt` | 国密算法 | → references/web-re.md |
| forge | `forge.cipher`, `forge.pki` | RSA/AES/证书 | → references/web-re.md |
| Web Crypto | `SubtleCrypto`, `crypto.subtle` | 浏览器原生加密 | → references/web-re.md |
| WASM 加密 | `wasm`, `Module._malloc` | 高强度混淆 | → references/web-re.md |

**签名机制 4 种模式：**
```
模式 1: sign = MD5(key1=val1&key2=val2&secret=xxx)     # 参数排序 + 密钥
模式 2: sign = HMAC-SHA256(secret, timestamp+nonce+body) # HMAC
模式 3: sign = SHA256(ts + nonce + sorted_params + secret) # 时间戳+随机数
模式 4: sign = Base64(HMAC-SHA256(secret, method+path+body_hash)) # 请求体哈希
```

> **详细加密逆向**（JS Hook 代码、WASM 分析、JS 反混淆、密钥提取技巧）→ **references/web-re.md**

### 1.6 数据流文档化

**端点文档模板：**
```markdown
### POST /api/v1/login
- 用途：用户登录
- 参数：{ username: string, password: string }
- 认证：无
- 响应：{ code: 0, data: { token: string, expires_in: int } }
- 注意：密码经 RSA 加密（见 login.js 中的 encrypt 函数）
```

**Python 复现模板：**
```python
import requests

class SiteClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...',
            'Accept': 'application/json',
        })

    def login(self, username, password):
        resp = self.session.post(f'{self.base_url}/api/login', json={
            'username': username, 'password': password,
        })
        data = resp.json()
        if data.get('code') == 0:
            self.session.headers['Authorization'] = f"Bearer {data['data']['token']}"
        return data

    def get_users(self, page=1, size=20):
        return self.session.get(f'{self.base_url}/api/users',
            params={'page': page, 'size': size}).json()
```

> **详细安全测试**（认证测试、越权检测、漏洞报告模板）→ **references/web-re.md**
## 第二部分：二进制逆向

### 2.1 文件识别

```bash
# 快速识别文件类型
file target.exe                    # 通用识别
binwalk target.exe                 # 嵌入文件检测

# Detect It Easy (DIE) — GUI 工具，识别编译器、壳、加密库
# PEiD — PE 文件查壳（经典工具）
```

| 文件类型 | 平台 | 特征 | 分析工具 |
|---------|------|------|---------|
| PE (.exe/.dll) | Windows | `MZ` 魔数 | IDA, x64dbg, dnSpy |
| ELF (.so/可执行) | Linux | `ELF` 魔数 | IDA, GDB, Ghidra |
| Mach-O | macOS | `FEEDFACE/F` | Hopper, LLDB |
| .NET DLL | 跨平台 | IL 元数据 | dnSpy, ILSpy |
| .class/.jar | 跨平台 | `CAFEBABE` | jadx, CFR |
| .dex | Android | `dex\n035` | jadx, apktool |

### 2.2 静态分析

**IDA Pro 核心操作：**
```
F5 → 伪代码    X → 交叉引用    N → 重命名    G → 跳转地址
; → 注释       Y → 修改类型    Space → 图形/文本切换
```

**IDA Python 常用：**
```python
# 搜索关键字符串
for s in idautils.Strings():
    if "encrypt" in str(s).lower():
        print(f"0x{s.ea:x}: {s}")

# 枚举感兴趣函数
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if "crypt" in name.lower() or "key" in name.lower():
        print(f"0x{ea:x}: {name}")
```

**Ghidra 工作流：**
1. Import → Auto-Analysis → Search Strings → Decompile
2. 右键函数 → Decompile 查看伪代码
3. Window → Defined Strings 定位密钥/URL

**常见模式识别：**
```asm
; 函数序言 (x86)
push ebp; mov ebp, esp; sub esp, 0x40
; 虚函数调用 (C++)
mov ecx, [this]; mov eax, [ecx]; call [eax+0x10]
; switch 跳转表
cmp eax, 5; ja default; jmp [table + eax*4]
```

### 2.3 动态分析

**x64dbg 核心操作：**

| 快捷键 | 功能 | 快捷键 | 功能 |
|--------|------|--------|------|
| F2 | 断点 | F7 | 步入 |
| F8 | 步过 | F9 | 运行 |
| Ctrl+F9 | 运行到返回 | Ctrl+G | 跳转地址 |
| Space | 修改汇编指令 | | |

**GDB 常用命令：**
```bash
gdb ./target
b main              # 设断点
r                   # 运行
ni / si             # 步过/步入
x/20x $rsp          # 查看栈
info registers      # 寄存器
disassemble main    # 反汇编
set $eax = 0        # 修改寄存器
```

**脱壳通用方法：**
```
ESP 定律: F8 到 OEP 附近 → ESP 变化后设硬件断点 → F9 到 OEP
单步跟踪: F7/F8 逐步跟踪，遇向上跳转用 F4 跳过循环
内存断点: .text 段设执行断点，脱壳完成后触发到 OEP
```

**常见壳：**
| 壳 | 特征 | 脱壳方法 |
|----|------|---------|
| UPX | `UPX0`/`UPX1` 段 | `upx -d` 或手动 |
| VMProtect | 虚拟化保护 | 单步跟踪 + devirtualization |
| Themida | 强壳 + 虚拟机 | 内存断点 + 长期跟踪 |

### 2.4 DLL 注入与 Hook

**注入方式：**

| 方式 | 原理 | 适用场景 |
|------|------|---------|
| CreateRemoteThread | 远程线程调 LoadLibrary | 最通用 |
| SetWindowsHookEx | 消息钩子 | GUI 程序 |
| AppInit_DLLs | 注册表自动加载 | 系统级 |
| Process Hollowing | 替换进程内存 | 高级隐藏 |

**Hook 类型对比：**

| 类型 | 原理 | 难度 | 适用场景 |
|------|------|------|---------|
| **Inline Hook** | 修改函数入口指令（5字节 JMP） | 中 | 任意函数 |
| **IAT Hook** | 修改导入表函数指针 | 低 | 导入的 API |
| **EAT Hook** | 修改导出表函数指针 | 低 | 导出的函数 |
| **VMT Hook** | 修改虚函数表指针 | 低 | C++ 虚函数 |
| **异常 Hook** | 利用异常处理机制 | 高 | 无修改检测场景 |

**Inline Hook 原理：**
```
原函数入口:                    Hook 后:
push ebp                      jmp hook_handler    ← 替换前 5 字节
mov ebp, esp                  ... (原指令)
sub esp, 0x40                 jmp original + 5    ← 跳回
...
```

**VMT Hook 原理（C++ 虚函数）：**
```
对象内存: [vtable_ptr] → [vtable] → [func0, func1, func2...]
替换 vtable 中的函数指针 → 指向 Hook 函数
适用于: COM 接口、C++ 多态类、游戏引擎对象
```

> **完整 DLL 注入 C 代码、MinHook、VMT/EAT/异常 Hook 代码** → **references/binary-re.md**

### 2.5 内存分析

**Cheat Engine 标准流程：**
```
1. 精确值扫描: 知道值(如血量=100) → 首次扫描 → 值变化 → 再次扫描 → 缩小范围
2. 模糊扫描: 不知道值 → 记录当前值 → 值变化 → "增加了/减少了" → 逐步缩小
3. AOB 特征码: 跨版本兼容 → 搜索字节模式 → 通配符 ?? 匹配变化字节
```

**指针链与基址定位：**
```
动态地址 → [指针1] → [指针2] → [基址+偏移] = 静态地址
基址 = 模块加载地址（不变）, 偏移 = 相对位移
多级指针: 基址 + offset1 → + offset2 → + offset3 = 目标地址
```

**AOB 特征码扫描（跨版本兼容）：**
```python
# 特征码: 55 8B EC 83 E4 F8 ?? ?? ?? 53 56 8B F1
# ?? = 通配符，匹配任意字节
# 找到特征码地址 + 偏移 = 目标函数/数据地址
```

> **完整 CE 流程、指针链追踪代码、AOB 扫描 Python 实现** → **references/binary-re.md**

### 2.5 .NET/Java 特化

**.NET 逆向：**
```
dnSpy: 打开 DLL → 浏览类结构 → 右键 Edit Method → Debug Attach
de4dot: 自动去除 .NET 混淆 → de4dot obfuscated.exe -o clean.exe
Harmony: 运行时补丁 → [HarmonyPatch] 标记 + Prefix/Postfix 方法
```

**Java 逆向：**
```
jadx-gui: 打开 .jar/.apk → 反编译为 Java 源码
CFR: java -jar cfr.jar target.class --outputdir output/
Java Agent: -javaagent:agent.jar 启动时注入字节码修改
```

> **完整 IDA 脚本、x64dbg 脚本、DLL 注入代码、.NET/Java 工作流** → **references/binary-re.md**

## 第三部分：移动端逆向

### 3.1 APK 分析

**APK 结构：**
```
app.apk
├── AndroidManifest.xml   # 清单（二进制 XML）
├── classes.dex           # DEX 字节码
├── lib/                  # Native SO（arm64-v8a/armeabi-v7a）
├── res/                  # 资源
└── assets/               # 原始资源
```

**反编译工具链：**
```
jadx-gui app.apk          → Java 源码分析（推荐首选）
apktool d app.apk -o out/ → Smali + 资源（可编辑重打包）
```

**关键搜索：**
```
"https://"     → API 端点    "AES"/"RSA" → 加密算法
"api_key"      → API 密钥    "SharedPreferences" → 本地存储
```

### 3.2 Smali 编辑

```smali
# 寄存器: v0-vN=本地, p0-pN=参数 (非静态 p0=this)

# 强制返回 true
const/4 v0, 0x1
return v0

# 方法调用
invoke-virtual {v0, v1}, Lcom/example/Foo;->bar(I)V
const-string v0, "Hello"
move-result-object v0
```

**重打包流程：**
```
apktool d → 编辑 smali → apktool b → zipalign → apksigner → adb install
```

### 3.3 Frida 动态插桩

**安装与启动：**
```bash
pip install frida-tools objection
# 检查设备架构
adb shell getprop ro.product.cpu.abilist
# 推送并启动 frida-server
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
# 绕过检测：改名或移到 /dev
# adb shell "mv /data/local/tmp/frida-server /data/local/tmp/fs-$(date +%s)"
```

**Hook Java（Android）：**
```javascript
Java.perform(function() {
    var Cls = Java.use("com.example.App");
    Cls.encrypt.overload('java.lang.String').implementation = function(input) {
        console.log("[*] encrypt input=" + input);
        var result = this.encrypt(input);
        console.log("[*] encrypt output=" + result);
        return result;
    };
    Cls.isRooted.implementation = function() { return false; };
});
```

**Hook Native：**
```javascript
Interceptor.attach(Module.findExportByName("libnative.so", "encrypt"), {
    onEnter(args) { console.log("[*] arg0=" + args[0].readUtf8String()); },
    onLeave(retval) { console.log("[*] ret=" + retval.readUtf8String()); }
});
```

**CLI 命令：**
```bash
frida -U -f com.app -l script.js --no-pause   # spawn 模式
frida -U com.app -l script.js                   # 附加模式
frida-trace -U -f com.app -j "*!*encrypt*"      # Java 方法追踪
frida-trace -U -f com.app -i "encrypt"           # Native 函数追踪
frida-discover -U -f com.app                     # 自动发现未知函数
frida-ps -Ua                                     # 列出已安装应用
```

**Stalker（指令级跟踪）：** 对目标函数做逐指令跟踪，适用于分析混淆后的加密逻辑。

**Objection 快速操作：**
```bash
objection -g com.app explore
android root disable       # 绕过 root 检测
android sslpinning disable # 绕过 SSL 锁定
android hooking list classes
android hooking watch class com.example.App
```

### 3.4 Xposed 框架

```java
// Xposed 模块核心
public class HookMain implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("com.target")) return;
        XposedHelpers.findAndHookMethod("com.target.App", lpparam.classLoader,
            "isRooted", new XC_MethodHook() {
                protected void afterHookedMethod(MethodHookParam param) {
                    param.setResult(false);  // 修改返回值
                }
            });
    }
}
```

**Frida vs Xposed：** Frida 适合动态快速分析，Xposed 适合长期持久使用。

### 3.5 游戏引擎逆向

| 引擎 | 特征 | 逆向方法 |
|------|------|---------|
| Unity Mono | Assembly-CSharp.dll | dnSpy 直接反编译 |
| Unity IL2CPP | libil2cpp.so + global-metadata.dat | Il2CppDumper → dump.cs + dummyDll |
| Unreal Engine | libUE4.so | GNames/GObjects dump → SDK 生成 |
| Cocos2d-x | libcocos2dcpp.so | Lua 提取 + Frida hook lua engine |

**IL2CPP 工作流：**
```
Il2CppDumper libil2cpp.so global-metadata.dat output/
→ dump.cs (类/方法定义) + script.json (地址映射)
→ Frida hook: Module.findBaseAddress("libil2cpp.so").add(RVA)
```

### 3.6 反检测绕过

**检测分类体系（通用）：**

| 检测类型 | 方法 | 绕过思路 |
|---------|------|---------|
| **签名校名** | 扫描已知工具特征码 | 改名/加壳/混淆 |
| **内存完整性** | 校验代码段/数据段 CRC | Hook 校验函数 |
| **进程检测** | 扫描可疑进程/模块 | 隐藏进程/改名 |
| **驱动检测** | 检测未签名/可疑驱动 | 使用签名驱动 |
| **调试器检测** | IsDebuggerPresent/ptrace/时间检测 | Patch/绕过 |
| **Hook 检测** | 检测函数入口被修改 | 使用无痕 Hook |
| **代码完整性** | 校验代码段 Hash | Hook 校验返回值 |
| **行为分析** | 分析操作模式（云端） | 模拟人类行为 |

**Android 反检测方案：**

| 检测类型 | 方案 |
|---------|------|
| Root 检测 | Magisk DenyList / Shamiko / KernelSU / Frida 脚本 |
| SSL 锁定 | Frida 脚本 / JustTrustMe / ReFlutter (Flutter) |
| 签名校验 | CorePatch / 手动 patch smali |
| 模拟器检测 | 修改 `ro.product.model` 等 prop |
| Play Integrity | Play Integrity Fix 模块 |
| Frida 检测 | Gadget / 改名 frida-server / 反检测脚本 |
| 调试检测 | Frida hook `ptrace` / Xposed 绕过 |

> **反外挂系统分析（BattlEye/EAC/Vanguard/VAC 详情）** → game-hacking skill `references/anti-cheat.md`

### 3.7 Android 脱壳

加固壳会将原始 DEX 加密，运行时才解密加载到内存。需要在运行时 dump。

| 工具 | 原理 | Root 要求 | 适用加固 |
|------|------|----------|---------|
| **FART** | ART 虚拟机 dump（修改 ROM） | 需要 Root | 通杀大多数壳 |
| **BlackDex** | 免 Root 脱壳（利用虚拟化） | 无需 Root | 常见加固 |
| **Frida dump** | Hook ClassLoader dump DEX | 需要 Root | 通用 |
| **Youpk** | 基于 ART 的 DEX dump | 需要刷入 | 强壳 |

**Frida dump DEX：**
```javascript
Java.perform(function() {
    var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
    PathClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
        var cls = this.loadClass(name);
        if (name.indexOf("com.target") !== -1) {
            // 触发 dump：遍历 DEX 文件并写出
            console.log("[*] Loaded class: " + name);
        }
        return cls;
    };
});
```

### 3.8 网络抓包（免代理方案）

传统代理抓包在 SSL Pinning 场景下无效。以下是免代理方案：

| 工具 | 原理 | Root | 特点 |
|------|------|------|------|
| **R0capture** | Frida 绕 SSL 直接抓明文 | 需要 | 免代理，抓 SSL 明文 |
| **PCAPdroid** | VPN 模式抓包 | 不需要 | Android 端 App |
| **HttpCanary** | VPN 模式 HTTP 抓包 | 不需要 | 图形化 |
| **tcpdump** | 底层抓包 | 需要 | `adb shell tcpdump -i any -w /sdcard/cap.pcap` |

**R0capture 使用：**
```bash
frida -U -f com.target.app -l r0capture.js --no-pause
# 输出 pcap 文件，用 Wireshark 打开
```

### 3.9 ADB 高级用法

```bash
# App 信息
adb shell dumpsys package com.target.app       # 完整包信息
adb shell dumpsys activity com.target.app       # Activity 信息
adb shell dumpsys meminfo com.target.app        # 内存使用

# 启动组件
adb shell am start -n com.target.app/.LoginActivity
adb shell am start -a android.intent.action.VIEW -d "https://example.com"

# Package Manager
adb shell pm list packages -3                   # 第三方应用
adb shell pm path com.target.app                # APK 路径
adb shell pm dump com.target.app | grep -A5 "permissions"

# Content Provider 查询
adb shell content query --uri content://com.target.app/provider

# 数据备份（需应用允许）
adb backup -f backup.ab com.target.app
# 解包: java -jar abe.jar unpack backup.ab backup.tar
```

### 3.10 drozer 安全测试

```bash
# 连接设备
adb forward tcp:31415 tcp:31415
drozer console connect

# 信息收集
run app.package.info -a com.target.app          # 包详情
run app.package.attacksurface com.target.app    # 攻击面
run app.package.debuggable com.target.app       # 可调试应用列表

# Content Provider 测试
run scanner.provider.finduris -a com.target.app # 发现可访问 URI
run app.provider.query content://com.target.app/users  # 查询数据

# Activity / Service / Receiver
run app.activity.info -a com.target.app
run app.activity.start --component com.target.app com.target.app.DebugActivity
run app.service.info -a com.target.app
run app.broadcast.info -a com.target.app
```

### 3.11 Root 方案对比

| 方案 | 原理 | Android 版本 | 特点 |
|------|------|-------------|------|
| **Magisk** | Systemless 修改 boot | 6.0-15 | 主流，Zygisk 模块，Hide 功能 |
| **KernelSU** | 内核级 Root | 11+ | 更隐蔽，内核模块 |
| **APatch** | 内核补丁 | 11+ | 类似 KernelSU，不同实现 |

**Magisk 隐藏链路：** Magisk → Zygisk 启用 → DenyList 勾选目标 App → 安装 Shamiko 模块

**Play Integrity Fix：** Magisk 模块，通过注入 Google Play 服务伪造设备完整性认证，通过 Play Integrity API 检测。

### 3.12 APK 分析工具补充

| 工具 | 用途 | 命令/入口 |
|------|------|----------|
| **APKiD** | 识别壳/混淆器/编译器 | `apkid target.apk` |
| **MobSF** | 自动化安全分析平台 | `docker run -p 8000:8000 opensecurity/mobsf` |
| **Quark-Engine** | Android 恶意行为分析 | Python 库，量化恶意评分 |
| **APK Analyzer** | Android Studio 内置 | Build → Analyze APK |

```bash
# APKiD 识别
pip install apkid
apkid target.apk
# 输出: packer/compiler/obfuscator 信息

# MobSF 自动化分析
# 上传 APK → 自动生成安全报告（权限、API调用、硬编码密钥等）
```

### 3.13 SO 文件分析

Native SO 是 Android 逆向的重要目标（加密、签名校验常在 SO 中）。

```bash
# 基本信息
file libtarget.so                           # 架构识别
readelf -h libtarget.so                     # ELF 头
readelf -s libtarget.so | grep -i encrypt   # 符号表搜索
readelf -d libtarget.so                     # 动态依赖

# 导出函数（JNI 注册）
readelf -s libtarget.so | grep Java_        # JNI 函数
readelf -s libtarget.so | grep -E "(encrypt|decrypt|sign|verify|key)"
```

**IDA 分析 Android SO：**
```
1. 打开 SO → 选择 ARM/ARM64 架构
2. 搜索字符串: "encrypt", "key", "secret", "JNI"
3. 搜索 JNI_OnLoad → 通常有动态注册和反调试
4. 关注 RegisterNatives 调用 → 动态注册的 native 方法
5. F5 伪代码 → 分析加密逻辑
```

**JNI 函数识别：**
```
静态注册: Java_com_example_App_encrypt → 直接搜索函数名
动态注册: JNI_OnLoad 中 RegisterNatives → 搜索 RegisterNatives 调用
```

### 3.14 SSL Pinning 绕过（完整方案）

| App 类型 | 绕过方案 |
|---------|---------|
| 标准 Java/OkHttp | Frida SSL 脚本 / LSPosed JustTrustMe |
| Network Security Config | APK 重打包修改 res/xml/network_security_config.xml |
| Flutter | ReFlutter 修改 libflutter.so |
| 自定义 SSL | 逆向 SO 中的 SSL 验证函数并 Hook |

> **完整 Frida 脚本、Xposed 模板、IL2CppDumper 流程、脱壳脚本** → **references/mobile-re.md**

## 第四部分：协议与接口逆向

### 4.1 流量捕获

| 协议 | 工具 | 方法 |
|------|------|------|
| HTTP/HTTPS | mitmproxy / Burp Suite | 代理拦截 + SSL 绕过 |
| WebSocket | DevTools / mitmproxy | WS 面板 / addon 脚本 |
| TCP/UDP | Wireshark / tcpdump | 抓包过滤器 |
| BLE | nRF Sniffer + Wireshark | GATT 服务分析 |
| USB | USBPcap + Wireshark | 设备通信分析 |

**mitmproxy 脚本：**
```python
from mitmproxy import http, ctx
class LogAddon:
    def request(self, flow: http.HTTPFlow):
        ctx.log.info(f"[REQ] {flow.request.method} {flow.request.url}")
    def response(self, flow: http.HTTPFlow):
        ctx.log.info(f"[RSP] {flow.response.status_code}")
```

### 4.2 协议结构分析

**识别模式：**
```
┌──────────┬──────────┬──────────────────────┐
│  Header  │  Length  │     Payload          │
│ (固定)    │ (变长)    │  (Length 指定)        │
└──────────┴──────────┴──────────────────────┘

长度字段: 固定长度 / TLV / 分隔符 / 长度前缀
字节序: 大端(网络标准) / 小端(x86)
```

**Python struct 解析：**
```python
import struct
msg_type, msg_len = struct.unpack('>HH', data[:4])  # 大端 2x16位
payload = data[4:4+msg_len]
```

### 4.3 序列化格式逆向

| 格式 | 识别特征 | 解码工具 |
|------|---------|---------|
| Protobuf | `0x0a` 开头，varint 编码 | `protoc --decode_raw` / blackboxprotobuf |
| MessagePack | `0xc0-0xdf` 前缀 | msgpack Python 库 |
| Thrift | `0x80` 开头 | Thrift IDL |
| CBOR | major type 前 3 bit | cbor2 Python 库 |

**Protobuf 逆向（无需 .proto）：**
```python
import blackboxprotobuf
data = open('sample.bin', 'rb').read()
message, typedef = blackboxprotobuf.decode_message(data)
```

**gRPC 反射：**
```bash
grpcurl -plaintext localhost:50051 list              # 列出服务
grpcurl -plaintext localhost:50051 describe pkg.Svc  # 描述服务
```

### 4.4 协议重放

```python
from scapy.all import *
pkt = IP(dst="10.0.0.1") / TCP(dport=8080) / Raw(load=b"\x01\x00\x05hello")
resp = sr1(pkt)
```

### 4.5 协议文档化

**字段表模板：**
```markdown
| 偏移 | 长度 | 类型 | 字段名 | 说明 |
|------|------|------|--------|------|
| 0x00 | 2 | uint16 BE | msg_type | 消息类型 |
| 0x02 | 2 | uint16 BE | msg_len | 数据长度 |
```

> **Wireshark 过滤器、Scapy 示例、Protobuf 详解、Lua dissector 模板** → **references/protocol-re.md**
## 统一工具速查表

### 静态分析

| 工具 | 用途 | 适用领域 |
|------|------|---------|
| **IDA Pro** | 反汇编、伪代码、脚本 | 二进制 |
| **Ghidra** | 免费反编译器（NSA 出品） | 二进制 |
| **Binary Ninja** | 现代化逆向工具，API 友好 | 二进制 |
| **dnSpy** | .NET 反编译/调试/编辑 | .NET / Unity Mono |
| **jadx-gui** | Java/Android 反编译 | APK / Java |
| **apktool** | APK 反编译/重打包 | APK |
| **class-dump** | ObjC 头文件提取 | iOS |
| **DIE (Detect It Easy)** | 编译器/壳识别 | 二进制 |
| **Il2CppDumper** | Unity IL2CPP 命令导出 | Unity IL2CPP |
| **synchrony** | JS 反混淆 | Web |
| **webcrack** | Webpack + obfuscator 还原 | Web |

### 动态分析

| 工具 | 用途 | 适用领域 |
|------|------|---------|
| **x64dbg** | Windows 调试器 | 二进制 |
| **WinDbg** | Windows 内核/用户态调试 | 二进制 |
| **GDB** | Linux 调试器 | 二进制 |
| **Frida** | 动态插桩（Java/Native/ObjC） | 移动端 / 二进制 |
| **Xposed/LSPosed** | Android 框架级 Hook | 移动端 |
| **Cycript** | iOS 运行时探索 | iOS |
| **Objection** | 快速移动安全评估 | 移动端 |
| **Cheat Engine** | 内存扫描/修改 | 二进制 |
| **Process Monitor** | 系统调用监控 | 二进制 |

### 网络分析

| 工具 | 用途 | 适用领域 |
|------|------|---------|
| **Wireshark** | 全协议抓包分析 | 协议 |
| **mitmproxy** | HTTP(S) 代理 + 脚本 | Web / 协议 |
| **Burp Suite** | Web 渗透测试套件 | Web |
| **tcpdump** | 命令行抓包 | 协议 |
| **Scapy** | 包构造/重放/Fuzzing | 协议 |

### Web 分析

| 工具 | 用途 |
|------|------|
| **Chrome DevTools** | F12 网络/元素/控制台 |
| **curl** | HTTP 请求复现 |
| **jq** | JSON 格式化过滤 |
| **whatweb / wappalyzer** | 技术栈识别 |
| **ffuf** | 目录/参数 Fuzz |

### 加密/编码

| 工具 | 用途 |
|------|------|
| **CyberChef** | 编码/解码/加解密瑞士军刀 |
| **jwt.io** | JWT 解码调试 |
| **hashcat** | 哈希破解 |
| **openssl** | 证书/加密命令行 |
| **protoc** | Protobuf 编解码 |

### 移动安全测试

| 工具 | 用途 | 参考 |
|------|------|------|
| **OWASP MASTG** | 移动安全测试权威指南 | mas.owasp.org/MASTG |
| **drozer** | Android 攻击面分析 | drozer console connect |
| **MobSF** | 自动化安全分析平台 | docker run opensecurity/mobsf |
| **APKiD** | APK 壳/混淆器识别 | apkid target.apk |
| **Quark-Engine** | Android 恶意行为分析 | Python 库 |

### 安全测试（Web）

| 工具 | 用途 |
|------|------|
| **sqlmap** | SQL 注入检测 |
| **nuclei** | 模板化漏洞扫描 |
| **nikto** | Web 服务器扫描 |
| **hydra** | 暴力破解 |
| **jwt_tool** | JWT 安全测试 |

## 常见错误

### Web 逆向

| 错误 | 正确做法 |
|------|---------|
| 跳过指纹直接抓包 | 先识别技术栈，再决定分析策略 |
| 只看一个请求下结论 | 按时间线分析所有请求，理解依赖关系 |
| curl 复现失败不查 JS | 检查参数是否被前端加密/签名/编码 |
| 硬编码 Token | 实现登录流程，自动获取刷新 |
| 忽略速率限制 | 探测限流阈值，加合理延迟 |
| 只 Hook 一层加密 | Network 面板对比 Hook 密文与实际请求体 |

### 二进制逆向

| 错误 | 正确做法 |
|------|---------|
| 未脱壳直接分析 | 先 DIE/PEiD 查壳，脱壳后再静态分析 |
| 硬编码地址计算 | 注意 ASLR，使用相对偏移（基址+RVA） |
| 混淆 32/64 位 | `file` 命令确认，选择对应分析工具 |
| 忽略调用约定 | x86: cdecl/stdcall/fastcall，x64: Microsoft/System V |

### 移动端逆向

| 错误 | 正确做法 |
|------|---------|
| 未检查混淆直接分析 | ProGuard/R8 会混淆类名方法名，先用 jadx 搜索字符串定位 |
| 忘记 SSL 锁定 | 抓包前先 Frida `sslpinning disable` 或 Xposed JustTrustMe |
| IL2CPP/Mono 混淆 | `libil2cpp.so` 存在 = IL2CPP，`Assembly-CSharp.dll` 存在 = Mono |
| 重打包未禁用签名验证 | CorePatch 或 patch smali 中的签名校验 |

### 协议逆向

| 错误 | 正确做法 |
|------|---------|
| 假设明文传输 | 用熵分析检测加密，检查是否有长度字段编码 |
| 忽略字节序 | 发送已知值（如 0x12345678）观察字节排列 |
| 混淆序列化格式 | protobuf 开头 0x0a，msgpack 前缀 0xc0-0xdf |
| 忽略压缩 | 有些协议先压缩后加密，解密后还需 zlib/gzip 解压 |

## 速查表

| 领域 | 关键活动 | 主要产出 |
|------|---------|---------|
| **Web** | 指纹、抓包、认证逆向、加密还原 | API 文档 + 自动化脚本 |
| **二进制** | 静态分析、动态调试、Hook | 功能逻辑文档 + 补丁/Hook 代码 |
| **移动端** | APK/IPA 分析、Frida Hook、引擎逆向 | 关键逻辑还原 + 绕过方案 |
| **协议** | 抓包、结构分析、格式还原 | 协议文档 + 复现代码 |
