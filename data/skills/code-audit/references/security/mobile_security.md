# Mobile Security Audit Guide

> Android/iOS 移动应用安全审计规则库
>
> 覆盖 OWASP Mobile Top 10 (2024) | 客户端安全 | 数据存储 | 网络通信 | 逆向防护

---

## 目录

1. [OWASP Mobile Top 10 速查](#1-owasp-mobile-top-10-速查)
2. [Android 安全审计](#2-android-安全审计)
3. [iOS 安全审计](#3-ios-安全审计)
4. [通用移动安全问题](#4-通用移动安全问题)
5. [安全配置检查清单](#5-安全配置检查清单)
6. [审计工具与命令](#6-审计工具与命令)

---

## 1. OWASP Mobile Top 10 速查

### 2024 版本映射

| 排名 | 风险类型 | Android 关键点 | iOS 关键点 |
|------|----------|----------------|------------|
| M1 | 不当凭证使用 | Keystore 误用、硬编码密钥 | Keychain 配置错误 |
| M2 | 供应链安全 | 恶意 SDK、依赖投毒 | 第三方框架风险 |
| M3 | 不安全认证/授权 | Intent 劫持、导出组件 | URL Scheme 劫持 |
| M4 | 输入/输出验证不足 | WebView XSS、SQL 注入 | WKWebView 注入 |
| M5 | 不安全通信 | 证书校验绕过、明文传输 | ATS 配置不当 |
| M6 | 隐私控制不足 | 日志泄露、剪贴板 | 后台截图、Pasteboard |
| M7 | 二进制保护不足 | 无混淆、调试开启 | 越狱检测绕过 |
| M8 | 安全配置错误 | debuggable=true | 不安全的 Entitlements |
| M9 | 不安全数据存储 | SharedPreferences 明文 | NSUserDefaults 敏感数据 |
| M10 | 密码学使用不当 | ECB 模式、弱随机数 | CommonCrypto 误用 |

---

## 2. Android 安全审计

### 2.1 组件导出漏洞 (M3)

#### 检测模式
```xml
<!-- AndroidManifest.xml 危险配置 -->
<activity android:exported="true" android:name=".SensitiveActivity"/>
<service android:exported="true" android:name=".PaymentService"/>
<receiver android:exported="true" android:name=".SmsReceiver"/>
<provider android:exported="true" android:name=".UserDataProvider"/>
```

#### 快速检测命令
```bash
# 查找导出组件
grep -rn "exported=\"true\"" --include="AndroidManifest.xml"

# 查找隐式导出 (intent-filter 导致自动导出)
grep -A5 "<intent-filter>" --include="AndroidManifest.xml" | grep -B5 "android:name"
```

#### 漏洞利用场景
```java
// 攻击者 App 调用导出 Activity
Intent intent = new Intent();
intent.setComponent(new ComponentName(
    "com.victim.app",
    "com.victim.app.admin.ResetPasswordActivity"
));
intent.putExtra("new_password", "hacked123");
startActivity(intent);
```

#### 安全修复
```xml
<!-- 方案1: 禁用导出 -->
<activity android:exported="false" android:name=".SensitiveActivity"/>

<!-- 方案2: 自定义权限保护 -->
<permission android:name="com.app.ADMIN_PERMISSION"
            android:protectionLevel="signature"/>
<activity android:exported="true"
          android:permission="com.app.ADMIN_PERMISSION"/>
```

### 2.2 Intent 注入/重定向

#### 危险模式
```java
// 漏洞: 直接使用外部 Intent
Intent forward = getIntent().getParcelableExtra("next_intent");
startActivity(forward);  // 可被劫持到任意 Activity

// 漏洞: Intent URI 解析
String uri = getIntent().getStringExtra("uri");
Intent parsed = Intent.parseUri(uri, 0);  // intent:// scheme 注入
startActivity(parsed);
```

#### 安全修复
```java
// 白名单验证
Intent forward = getIntent().getParcelableExtra("next_intent");
if (forward != null) {
    ComponentName component = forward.getComponent();
    if (component != null &&
        component.getPackageName().equals(getPackageName())) {
        startActivity(forward);
    }
}

// Intent URI 安全解析
Intent parsed = Intent.parseUri(uri, Intent.URI_INTENT_SCHEME);
parsed.addCategory(Intent.CATEGORY_BROWSABLE);
parsed.setComponent(null);
parsed.setSelector(null);
```

### 2.3 WebView 安全问题 (M4)

#### 高危配置检测
```java
// XSS 风险
webView.getSettings().setJavaScriptEnabled(true);

// 本地文件访问风险
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowFileAccessFromFileURLs(true);  // API < 16
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);

// JavaScript 接口注入风险 (API < 17)
webView.addJavascriptInterface(new WebAppInterface(), "Android");
```

#### 快速检测
```bash
# JavaScript 启用
grep -rn "setJavaScriptEnabled(true)" --include="*.java" --include="*.kt"

# 文件访问
grep -rn "setAllowFileAccess\|setAllowUniversalAccess" --include="*.java"

# JS 接口
grep -rn "addJavascriptInterface" --include="*.java" --include="*.kt"
```

#### JavaScript 接口漏洞 (API < 17)
```java
// 漏洞: 未使用 @JavascriptInterface 注解 (API < 17)
class WebAppInterface {
    public void showToast(String msg) { /* ... */ }
}

// 攻击 Payload (通过反射执行任意命令)
<script>
function execute(cmd) {
    return Android.getClass().forName('java.lang.Runtime')
        .getMethod('getRuntime', null).invoke(null, null)
        .exec(cmd);
}
execute('id');
</script>
```

#### 安全配置
```java
// API 17+ 使用 @JavascriptInterface
public class SafeWebAppInterface {
    @JavascriptInterface
    public void allowedMethod(String data) {
        // 输入验证
    }
}

// 禁用危险设置
WebSettings settings = webView.getSettings();
settings.setAllowFileAccess(false);
settings.setAllowContentAccess(false);
if (Build.VERSION.SDK_INT >= 16) {
    settings.setAllowFileAccessFromFileURLs(false);
    settings.setAllowUniversalAccessFromFileURLs(false);
}

// URL 白名单
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        Uri uri = Uri.parse(url);
        if (!"example.com".equals(uri.getHost())) {
            return true;  // 阻止加载
        }
        return false;
    }
});
```

### 2.4 数据存储安全 (M9)

#### 危险存储检测
```java
// SharedPreferences 明文存储
SharedPreferences prefs = getSharedPreferences("user", MODE_WORLD_READABLE);
prefs.edit().putString("password", password).apply();

// SQLite 明文存储
db.execSQL("INSERT INTO users (password) VALUES ('" + password + "')");

// 外部存储 (任何 App 可读)
File file = new File(Environment.getExternalStorageDirectory(), "token.txt");
FileOutputStream fos = new FileOutputStream(file);
fos.write(token.getBytes());
```

#### 快速检测
```bash
# SharedPreferences 危险模式
grep -rn "MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE" --include="*.java"

# 外部存储
grep -rn "getExternalStorageDirectory\|getExternalFilesDir" --include="*.java"

# 明文密码存储
grep -rn "putString.*password\|putString.*token\|putString.*key" --include="*.java"
```

#### 安全存储方案
```java
// EncryptedSharedPreferences (Jetpack Security)
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);

// Android Keystore 存储密钥
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
```

### 2.5 网络安全配置 (M5)

#### 危险配置检测
```xml
<!-- network_security_config.xml -->
<!-- 允许明文流量 -->
<base-config cleartextTrafficPermitted="true"/>

<!-- 信任用户证书 (可被中间人) -->
<trust-anchors>
    <certificates src="user"/>
</trust-anchors>

<!-- 禁用证书固定 -->
<domain-config>
    <domain includeSubdomains="true">example.com</domain>
    <pin-set>
        <!-- 空或过期的 pin -->
    </pin-set>
</domain-config>
```

#### 代码层证书校验绕过
```java
// 漏洞: 信任所有证书
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
};

// 漏洞: 禁用主机名验证
HostnameVerifier allHostsValid = (hostname, session) -> true;
```

#### 快速检测
```bash
# 信任所有证书
grep -rn "checkServerTrusted\|TrustManager\[\]" --include="*.java" | grep -v "throw"

# 主机名验证绕过
grep -rn "HostnameVerifier\|ALLOW_ALL_HOSTNAME" --include="*.java"

# 明文流量
grep -rn "cleartextTrafficPermitted=\"true\"" --include="*.xml"
```

#### 安全配置
```xml
<!-- network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>

    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-01-01">
            <pin digest="SHA-256">base64_encoded_pin_1</pin>
            <pin digest="SHA-256">base64_encoded_pin_2</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### 2.6 Root 检测绕过

#### 常见检测方法
```java
// 文件检测
private boolean checkRootFiles() {
    String[] paths = {"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su"};
    for (String path : paths) {
        if (new File(path).exists()) return true;
    }
    return false;
}

// 命令执行检测
private boolean checkSuCommand() {
    try {
        Runtime.getRuntime().exec("su");
        return true;
    } catch (Exception e) {
        return false;
    }
}

// Build 属性检测
private boolean checkBuildTags() {
    return Build.TAGS != null && Build.TAGS.contains("test-keys");
}
```

#### 绕过技术 (Frida)
```javascript
// Frida hook 绕过 Root 检测
Java.perform(function() {
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1 || path.indexOf("Superuser") !== -1) {
            return false;
        }
        return this.exists();
    };
});
```

### 2.7 日志信息泄露 (M6)

#### 危险模式
```java
// 敏感信息日志
Log.d("Auth", "Password: " + password);
Log.i("Payment", "Card: " + cardNumber);
Log.e("API", "Token: " + accessToken);

// BuildConfig.DEBUG 检查缺失
Log.d(TAG, "Debug info: " + sensitiveData);
```

#### 快速检测
```bash
# 日志敏感信息
grep -rn "Log\.[dievw].*password\|Log\.[dievw].*token\|Log\.[dievw].*key" --include="*.java"

# 未检查 DEBUG
grep -rn "Log\." --include="*.java" | grep -v "BuildConfig.DEBUG"
```

#### 安全实践
```java
// 使用 Timber 并在 Release 禁用
if (BuildConfig.DEBUG) {
    Timber.plant(new Timber.DebugTree());
}

// ProGuard 移除日志
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}
```

### 2.8 Clipboard 数据泄露

```java
// 漏洞: 复制敏感数据到剪贴板
ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
ClipData clip = ClipData.newPlainText("password", password);
clipboard.setPrimaryClip(clip);

// 漏洞: 读取剪贴板 (其他 App 可读)
ClipData clipData = clipboard.getPrimaryClip();
```

---

## 3. iOS 安全审计

### 3.1 Keychain 安全 (M1, M9)

#### 危险配置
```swift
// 漏洞: 不安全的 Keychain 可访问性
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,  // 始终可访问
    kSecValueData as String: password
]

// 漏洞: 未设置访问控制
SecItemAdd(query as CFDictionary, nil)
```

#### 安全配置
```swift
// 安全: 使用生物认证保护
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.userPresence, .biometryCurrentSet],
    nil
)

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessControl as String: access!,
    kSecValueData as String: password
]
```

#### Keychain 可访问性级别
| 级别 | 风险 | 说明 |
|------|------|------|
| `kSecAttrAccessibleAlways` | 高危 | 设备锁定时可访问 |
| `kSecAttrAccessibleAfterFirstUnlock` | 中危 | 重启后首次解锁即可访问 |
| `kSecAttrAccessibleWhenUnlocked` | 较安全 | 仅解锁时可访问 |
| `*ThisDeviceOnly` | 更安全 | 不会备份到 iCloud |

### 3.2 URL Scheme 劫持 (M3)

#### 危险配置
```xml
<!-- Info.plist -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>  <!-- 可被恶意 App 注册 -->
        </array>
    </dict>
</array>
```

#### 漏洞代码
```swift
// 漏洞: 未验证 URL 来源
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    let token = url.queryParameters["token"]
    authenticateUser(with: token)  // 攻击者可伪造 URL
    return true
}
```

#### 安全修复
```swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    // 验证来源 App
    guard let sourceApp = options[.sourceApplication] as? String,
          allowedApps.contains(sourceApp) else {
        return false
    }

    // 使用 Universal Links 替代
    return true
}
```

### 3.3 App Transport Security (M5)

#### 危险配置
```xml
<!-- Info.plist - 全局禁用 ATS -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>

<!-- 特定域名例外 -->
<key>NSExceptionDomains</key>
<dict>
    <key>insecure.example.com</key>
    <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
        <key>NSExceptionMinimumTLSVersion</key>
        <string>TLSv1.0</string>
    </dict>
</dict>
```

#### 快速检测
```bash
# 检查 ATS 配置
plutil -p Info.plist | grep -A10 "NSAppTransportSecurity"
```

### 3.4 数据存储安全 (M9)

#### 危险存储检测
```swift
// NSUserDefaults 存储敏感数据
UserDefaults.standard.set(password, forKey: "password")
UserDefaults.standard.set(token, forKey: "auth_token")

// Plist 文件存储
let plistPath = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
NSDictionary(dictionary: ["password": password]).write(toFile: plistPath, atomically: true)

// Core Data 未加密
let container = NSPersistentContainer(name: "DataModel")  // 默认不加密
```

#### 文件保护级别
```swift
// 安全: 使用文件保护
try data.write(to: fileURL, options: .completeFileProtection)

// 检查保护级别
let attributes = try FileManager.default.attributesOfItem(atPath: path)
let protection = attributes[.protectionKey]
```

### 3.5 WKWebView 安全 (M4)

#### 危险配置
```swift
// JavaScript 注入风险
let config = WKWebViewConfiguration()
let script = WKUserScript(source: jsCode, injectionTime: .atDocumentStart, forMainFrameOnly: false)
config.userContentController.addUserScript(script)

// 不安全的消息处理
class WebHandler: NSObject, WKScriptMessageHandler {
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        // 漏洞: 未验证消息来源
        if let body = message.body as? String {
            eval(body)  // 危险!
        }
    }
}
```

#### 安全配置
```swift
// 限制 JavaScript
let preferences = WKPreferences()
preferences.javaScriptEnabled = false  // 如不需要则禁用

// URL 白名单
func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    guard let url = navigationAction.request.url,
          let host = url.host,
          allowedHosts.contains(host) else {
        decisionHandler(.cancel)
        return
    }
    decisionHandler(.allow)
}
```

### 3.6 越狱检测绕过

#### 常见检测方法
```swift
// 文件检测
func isJailbroken() -> Bool {
    let paths = ["/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd"]
    return paths.contains { FileManager.default.fileExists(atPath: $0) }
}

// URL Scheme 检测
func canOpenCydia() -> Bool {
    return UIApplication.shared.canOpenURL(URL(string: "cydia://")!)
}

// 沙箱完整性检测
func checkSandbox() -> Bool {
    let path = "/private/test.txt"
    do {
        try "test".write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(atPath: path)
        return true  // 越狱
    } catch {
        return false
    }
}
```

#### Frida 绕过
```javascript
// Hook FileManager
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function(args) {
        this.path = ObjC.Object(args[2]).toString();
    },
    onLeave: function(retval) {
        if (this.path.indexOf('Cydia') !== -1 || this.path.indexOf('bash') !== -1) {
            retval.replace(0);
        }
    }
});
```

### 3.7 Pasteboard 数据泄露 (M6)

```swift
// 漏洞: 复制敏感数据
UIPasteboard.general.string = password

// 安全: 使用私有剪贴板
let privatePasteboard = UIPasteboard(name: UIPasteboard.Name("com.app.private"), create: true)
privatePasteboard?.string = sensitiveData

// 设置过期时间
UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: data]], options: [.expirationDate: Date().addingTimeInterval(60)])
```

### 3.8 后台截图泄露 (M6)

```swift
// 漏洞: 敏感页面被截图
// 进入后台时系统会自动截图

// 安全: 添加遮罩
func applicationWillResignActive(_ application: UIApplication) {
    let blurEffect = UIBlurEffect(style: .light)
    let blurView = UIVisualEffectView(effect: blurEffect)
    blurView.frame = window?.frame ?? .zero
    blurView.tag = 999
    window?.addSubview(blurView)
}

func applicationDidBecomeActive(_ application: UIApplication) {
    window?.viewWithTag(999)?.removeFromSuperview()
}
```

---

## 4. 通用移动安全问题

### 4.1 密码学误用 (M10)

#### 危险模式
```java
// Android - ECB 模式
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // 危险

// Android - 弱随机数
Random random = new Random();  // 可预测
byte[] key = new byte[16];
random.nextBytes(key);

// Android - 硬编码密钥
private static final String KEY = "hardcoded123456";
```

```swift
// iOS - ECB 模式
let cryptor = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
    CCOptions(kCCOptionECBMode), ...)  // 危险

// iOS - 弱随机数
let random = arc4random() // 某些场景不够安全
```

#### 安全实践
```java
// Android - 安全加密
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecureRandom secureRandom = new SecureRandom();
byte[] iv = new byte[12];
secureRandom.nextBytes(iv);
```

```swift
// iOS - 安全加密
var key = Data(count: kCCKeySizeAES256)
let result = key.withUnsafeMutableBytes {
    SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES256, $0.baseAddress!)
}
```

### 4.2 认证绕过 (M3)

#### 生物认证绕过
```swift
// iOS 漏洞: 仅客户端验证
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Login") { success, error in
    if success {
        self.unlockApp()  // 可被 hook 绕过
    }
}
```

```java
// Android 漏洞: 仅客户端验证
BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
        unlockApp();  // 可被 Frida 绕过
    }
};
```

#### 安全实践
```java
// Android - 使用 CryptoObject 绑定
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);

BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);

// 验证时必须使用解密后的数据
@Override
public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
    Cipher cipher = result.getCryptoObject().getCipher();
    byte[] decrypted = cipher.doFinal(encryptedToken);
    // 使用解密的 token 向服务器验证
}
```

### 4.3 证书固定绕过检测

#### 检测技术
```bash
# 使用 objection 检测
objection -g com.app.name explore
> android sslpinning disable
> ios sslpinning disable

# Frida 脚本
frida -U -l ssl_bypass.js -f com.app.name
```

### 4.4 深度链接漏洞

#### Android App Links
```xml
<!-- AndroidManifest.xml -->
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="example.com"/>
</intent-filter>
```

#### iOS Universal Links
```json
// apple-app-site-association
{
    "applinks": {
        "apps": [],
        "details": [{
            "appID": "TEAM_ID.com.example.app",
            "paths": ["/open/*", "/auth/*"]
        }]
    }
}
```

---

## 5. 安全配置检查清单

### 5.1 Android 审计清单

```markdown
## AndroidManifest.xml
- [ ] android:debuggable="false"
- [ ] android:allowBackup="false"
- [ ] android:usesCleartextTraffic="false"
- [ ] 检查所有 exported="true" 组件
- [ ] 自定义权限使用 signature 保护级别

## 网络安全
- [ ] 配置 network_security_config.xml
- [ ] 禁用明文流量
- [ ] 实施证书固定

## 数据存储
- [ ] 使用 EncryptedSharedPreferences
- [ ] Keystore 存储敏感密钥
- [ ] 禁用外部存储敏感数据

## WebView
- [ ] setJavaScriptEnabled(false) 或最小化
- [ ] setAllowFileAccess(false)
- [ ] 验证 loadUrl 输入

## 日志与调试
- [ ] Release 版本移除 Log 语句
- [ ] 禁用 WebView 调试
```

### 5.2 iOS 审计清单

```markdown
## Info.plist
- [ ] NSAppTransportSecurity 配置安全
- [ ] 最小化 URL Schemes
- [ ] 实施 Universal Links

## Keychain
- [ ] 使用 kSecAttrAccessibleWhenUnlockedThisDeviceOnly
- [ ] 实施访问控制 (biometrics)
- [ ] 禁用 iCloud Keychain 同步

## 数据存储
- [ ] 避免 NSUserDefaults 存储敏感数据
- [ ] 使用 Data Protection API
- [ ] Core Data 加密

## WebView
- [ ] WKWebView 替代 UIWebView
- [ ] 实施导航白名单
- [ ] 验证 JavaScript 消息

## 隐私
- [ ] 实施后台截图保护
- [ ] 避免 Pasteboard 敏感数据
```

---

## 6. 审计工具与命令

### 6.1 静态分析工具

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **jadx** | Android 反编译 | `jadx -d output app.apk` |
| **apktool** | APK 解包/重打包 | `apktool d app.apk` |
| **MobSF** | 自动化扫描 | `docker run mobsf` |
| **class-dump** | iOS 头文件导出 | `class-dump -H App.app` |
| **Hopper/IDA** | 二进制分析 | GUI |

### 6.2 动态分析工具

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **Frida** | 运行时 Hook | `frida -U -l script.js -f com.app` |
| **objection** | 自动化测试 | `objection -g com.app explore` |
| **Burp Suite** | 流量拦截 | 配置代理 + 证书 |
| **Drozer** | Android 组件测试 | `run app.package.attacksurface` |

### 6.3 常用 Frida 脚本

```javascript
// 绕过 Root/越狱检测
Java.perform(function() {
    var RootDetection = Java.use("com.app.security.RootDetection");
    RootDetection.isRooted.implementation = function() {
        return false;
    };
});

// Hook 加密函数
Interceptor.attach(Module.findExportByName("libcrypto.so", "AES_encrypt"), {
    onEnter: function(args) {
        console.log("AES_encrypt called");
        console.log("Input: " + hexdump(args[0], { length: 16 }));
    }
});

// 打印调用栈
Java.perform(function() {
    var Exception = Java.use("java.lang.Exception");
    var Log = Java.use("android.util.Log");

    var targetClass = Java.use("com.app.TargetClass");
    targetClass.targetMethod.implementation = function() {
        Log.d("Frida", Log.getStackTraceString(Exception.$new()));
        return this.targetMethod.apply(this, arguments);
    };
});
```

### 6.4 快速检测命令

```bash
# Android APK 基础信息
aapt dump badging app.apk

# 检查签名
apksigner verify --verbose app.apk
jarsigner -verify -verbose app.apk

# 检查混淆
grep -r "proguard\|R8" app/build.gradle

# iOS 二进制保护
otool -hv App.app/App | grep PIE
otool -Iv App.app/App | grep -i stack

# 检查 ARC
otool -I App.app/App | grep _objc_release
```

---

## 参考资源

- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Mobile Security Testing Guide](https://mas.owasp.org/MASTG/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [iOS Security Guide](https://support.apple.com/guide/security/)
- [Frida Documentation](https://frida.re/docs/home/)
