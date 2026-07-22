# 移动端逆向参考手册

## 一、APK 结构与反编译

### APK 结构

```
app.apk (ZIP)
├── AndroidManifest.xml      # 应用清单（二进制 XML）
├── classes.dex              # 主 DEX 字节码
├── lib/                     # Native SO 库（armeabi-v7a/arm64-v8a/x86_64）
├── res/                     # 编译后的资源
├── assets/                  # 原始资源
├── resources.arsc           # 资源索引表
└── META-INF/                # 签名信息
```

### jadx-gui 分析

```bash
jadx-gui app.apk
# Ctrl+Shift+F 文本搜索 → API URL、密钥、硬编码凭证
# Ctrl+N 类搜索 → 定位特定类
# X 交叉引用 → 查找方法/字段所有调用点
```

### apktool 工作流

```bash
apktool d app.apk -o app_decompiled/    # 反编译
apktool b app_decompiled/ -o app_mod.apk # 重新打包
zipalign -v 4 app_mod.apk app_aligned.apk
apksigner sign --ks my.keystore --ks-pass pass:123456 app_aligned.apk
adb install app_aligned.apk
```

## 二、Smali 编程

### 寄存器与方法签名

```smali
# v0,v1... = 本地寄存器, p0,p1... = 参数寄存器
# 非静态方法 p0=this, p1=第一个参数
# 静态方法 p0=第一个参数

.method public onCreate(Landroid/os/Bundle;)V
    .registers 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    return-void
.end method
```

### 常用操作码

```smali
invoke-virtual {v0, v1}, Lcom/example/Foo;->bar(I)V    # 调用实例方法
invoke-static {v0}, Lcom/Util;->encrypt(Ljava/lang/String;)Ljava/lang/String;
const-string v0, "Hello"     # 字符串常量
move-result-object v0        # 获取返回值
return-object v0             # 返回对象
if-eqz v0, :label            # if (v0 == 0) goto label
```

### 编辑示例：强制返回 true

```smali
.method public isRegistered()Z
    .registers 2
    const/4 v0, 0x1    # v0 = 1 (true)
    return v0
.end method
```

## 三、IPA 分析

```bash
# class-dump 提取 ObjC 头文件
class-dump -H Payload/App.app/App -o headers/

# Cycript 运行时探索
cycript -p AppName
UIApp.keyWindow.rootViewController

# Flexdecrypt 解密 App Store 应用
flexdecrypt /path/to/App
```

## 四、Frida 完整参考

### 环境搭建

```bash
pip install frida-tools objection
# 下载 frida-server 推送到设备
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
```

### CLI 命令

```bash
frida -U -f com.example.app -l script.js --no-pause  # spawn 模式
frida -U com.example.app -l script.js                  # 附加模式
frida-ps -Ua                                           # 列出应用
frida-trace -U -f com.example.app -j "*!*encrypt*"     # Java 方法追踪
frida-trace -U -f com.example.app -i "encrypt"           # Native 函数追踪
frida-discover -U -f com.example.app                     # 自动发现函数
```

### frida-discover（自动函数发现）

```bash
# 黑盒分析：不需要知道函数名，自动探测可 Hook 的函数
# 输出 CSV 格式函数列表，可用于后续精确 Hook
```

### Stalker（指令级跟踪）

```javascript
// 指令级别跟踪目标函数，适用于分析混淆后的加密逻辑
Interceptor.attach(Module.findExportByName("lib.so", "target"), {
    onEnter(args) {
        Stalker.follow(this.threadId, {
            events: { call: true, ret: true },
            onCallSummary(summary) { console.log(JSON.stringify(summary)); }
        });
    },
    onLeave(retval) {
        Stalker.unfollow(this.threadId);
        Stalker.garbageCollect();
    }
});
```

### Frida 检测绕过（来自官方文档）

```
1. 改名 frida-server → 随机名称
2. 移动到 /dev/ 目录
3. 使用 frida-gadget 代替 frida-server（免 Root 方案）
4. 修改监听端口: frida-server -l 0.0.0.0:8888
```

### Hook Java 方法（Android）

```javascript
Java.perform(function() {
    var MainActivity = Java.use("com.example.MainActivity");

    // Hook 方法（带重载）
    MainActivity.encrypt.overload('java.lang.String').implementation = function(input) {
        console.log("[*] encrypt() input=" + input);
        var result = this.encrypt(input);
        console.log("[*] encrypt() output=" + result);
        return result;
    };

    // 修改返回值
    MainActivity.isRegistered.implementation = function() {
        return true;
    };
});
```

### Hook Native 函数

```javascript
// Hook SO 中的函数
Interceptor.attach(Module.findExportByName("libnative.so", "encrypt"), {
    onEnter: function(args) {
        console.log("[*] arg0=" + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log("[*] retval=" + retval.readUtf8String());
    }
});

// Hook 指定地址
var libBase = Module.findBaseAddress("libnative.so");
Interceptor.attach(libBase.add(0x1234), { onEnter(args) { /* ... */ }, onLeave(retval) { /* ... */ } });
```

### 内存操作

```javascript
// 读写
var bytes = Memory.readByteArray(ptr("0x12345678"), 64);
Memory.writeByteArray(ptr("0x12345678"), [0x90, 0x90, 0x90, 0x90]);

// 扫描
Memory.scan(Module.findBaseAddress("lib.so"), 0x100000, "48 89 e5", {
    onMatch(address, size) { console.log("Found: " + address); },
    onComplete() { console.log("Done"); }
});
```

### ObjC Bridge（iOS）

```javascript
if (ObjC.available) {
    var VC = ObjC.classes.ViewController;
    Interceptor.attach(VC['- viewDidAppear:'].implementation, {
        onEnter(args) { console.log("[*] viewDidAppear"); }
    });
    // 遍历实例
    ObjC.choose(ObjC.classes.UIButton, {
        onMatch(obj) { console.log("UIButton: " + obj.description()); },
        onComplete() {}
    });
}
```

### Frida Gadget（非 Root）

```bash
apktool d app.apk -o app_gadget/
# 将 libfrida-gadget.so 复制到 lib/arm64-v8a/
# 在 Application smali 中添加: System.loadLibrary("frida-gadget")
apktool b app_gadget/ -o app_gadget.apk
# 签名安装后: frida -U Gadget -l script.js
```

### Objection 常用命令

```bash
objection -g com.example.app explore
android root disable              # 绕过 root 检测
android sslpinning disable        # 绕过 SSL 锁定
android hooking list classes      # 列出所有类
android hooking watch class com.example.App  # 监控类方法
ios sslpinning disable
ios keychain dump
```

### SSL 解锁脚本

```javascript
Java.perform(function() {
    // TrustManager 绕过
    try {
        var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI.verifyChain.implementation = function() { return arguments[0]; };
    } catch(e) {}
    // OkHttp3 CertificatePinner
    try {
        var CP = Java.use("okhttp3.CertificatePinner");
        CP.check.overload('java.lang.String','java.util.List').implementation = function() {};
    } catch(e) {}
    // WebView SSL
    try {
        var WVC = Java.use("android.webkit.WebViewClient");
        WVC.onReceivedSslError.implementation = function(v,h,e) { h.proceed(); };
    } catch(e) {}
    console.log("[*] SSL bypass loaded");
});
```

### Root 检测绕过脚本

```javascript
Java.perform(function() {
    // 直接修改返回值
    try {
        var RD = Java.use("com.example.security.RootDetection");
        RD.isRooted.implementation = function() { return false; };
    } catch(e) {}
    // 文件检测绕过
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var p = this.getAbsolutePath();
        if (p.indexOf("su")!==-1 || p.indexOf("Superuser")!==-1) return false;
        return this.exists();
    };
    // Build.TAGS
    Java.use("android.os.Build").TAGS.value = "release-keys";
});
```

## 五、Xposed 框架

### 模块结构

```java
public class HookMain implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.example.target")) return;

        XposedHelpers.findAndHookMethod("com.example.target.SecurityManager",
            lpparam.classLoader, "isRooted", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    param.setResult(false);
                }
            });
    }
}
```

```
// assets/xposed_init
com.example.xposed.HookMain
```

### Frida vs Xposed

| 特性 | Frida | Xposed/LSPosed |
|------|-------|----------------|
| Root 要求 | 可用 Gadget 绕过 | 必须 Root |
| 语言 | JavaScript | Java |
| 即时修改 | 支持（热重载） | 需重启应用 |
| Native Hook | 原生支持 | 需额外库 |
| 持久性 | 临时 | 永久 |
| iOS 支持 | 支持 | 不支持 |

## 六、Unity 游戏引擎逆向

### Unity Mono 模式

```bash
# DLL 位置: assets/bin/Data/Managed/Assembly-CSharp.dll
# 用 dnSpy 打开反编译，查看 MonoBehaviour 方法（Awake/Start/Update）
```

### Unity IL2CPP 模式

```bash
# 识别: libil2cpp.so + global-metadata.dat
# Il2CppDumper
./Il2CppDumper libil2cpp.so global-metadata.dat output/
# 输出: dump.cs（类/方法定义）, script.json（地址映射）, stringliteral.json（字符串字面量）
# script.json 可导入 IDA/Ghidra 用于重命名函数
```

**Metadata 版本差异：**
```
MetadataVersion 24: Unity 5.x
MetadataVersion 27: Unity 2017-2018
MetadataVersion 29: Unity 2019-2020
MetadataVersion 29 (v2): Unity 2021+
MetadataVersion 29 (v3): Unity 2022+
# Il2CppDumper 自动检测版本，新版本可能需要更新工具
```

**IL2CPP API 动态查找（无需地址）：**
```javascript
// 通过 IL2CPP 导出 API 动态查找函数，不依赖 Il2CppDumper 地址
function il2cpp_resolve(className, methodName, paramCount) {
    var domain = new NativeFunction(
        Module.findExportByName(null, "il2cpp_domain_get"), 'pointer', [])();
    var klass = new NativeFunction(
        Module.findExportByName(null, "il2cpp_class_from_name"),
        'pointer', ['pointer', 'pointer', 'pointer'])(
            ptr(0), Memory.allocUtf8String(""), Memory.allocUtf8String(className));
    var method = new NativeFunction(
        Module.findExportByName(null, "il2cpp_class_get_method_from_name"),
        'pointer', ['pointer', 'pointer', 'int'])(
            klass, Memory.allocUtf8String(methodName), paramCount);
    return method;
}
// 用法: var addr = il2cpp_resolve("GameManager", "AddGold", 1);
// Interceptor.attach(addr, { onEnter(args) { ... } });
```

### Frida Hook IL2CPP

```javascript
var libil2cpp = Module.findBaseAddress("libil2cpp.so");
var addGoldAddr = libil2cpp.add(0x1234567); // RVA from Il2CppDumper
Interceptor.attach(addGoldAddr, {
    onEnter(args) {
        console.log("[*] AddGold amount=" + args[1].toInt32());
        args[1] = ptr(999999); // 修改参数
    }
});
```

### Unreal Engine

```bash
# UObject 反射: GNames/GObjects
# UE4Dumper 生成 SDK
# Frida hook: Module.findExportByName("libUE4.so", "GetObjectName")
```

### Cocos2d-x

```bash
# Lua 脚本提取: assets/ 下的 .luac 文件
java -jar unluac.jar script.luac > script.lua

# Frida hook Lua 引擎
Interceptor.attach(Module.findExportByName("libcocos2dcpp.so", "luaL_loadbuffer"), {
    onEnter(args) {
        console.log("[Lua] " + args[1].readUtf8String(args[2].toInt32()).substring(0, 500));
    }
});
```

## 七、Android 脱壳

### Frida dump DEX

```javascript
// frida_dump_dex.js — 在 DEX 加载时 dump
Java.perform(function() {
    var DexFile = Java.use("dalvik.system.DexFile");
    DexFile.$init.overload('java.lang.String').implementation = function(path) {
        console.log("[*] DexFile opened: " + path);
        var fis = Java.use("java.io.FileInputStream").$new(path);
        var bytes = Java.use("java.io.ByteArrayOutputStream").$new();
        var buf = Java.array('byte', new Array(4096).fill(0));
        var len;
        while ((len = fis.read(buf)) !== -1) bytes.write(buf, 0, len);
        fis.close();
        var outputPath = "/data/local/tmp/dump_" + Date.now() + ".dex";
        var fos = Java.use("java.io.FileOutputStream").$new(outputPath);
        fos.write(bytes.toByteArray());
        fos.close();
        console.log("[*] Dumped to: " + outputPath);
        return this.$init(path);
    };
});
```

### BlackDex / FART

```bash
# BlackDex — 免 Root 脱壳，利用虚拟化技术
# 安装后打开 → 选择目标应用 → 一键脱壳
# 输出: /sdcard/BlackDex/com.target.app/

# FART — ART 环境脱壳（需刷入修改 ROM 或使用 Frida 版脚本）
# 原理: 类初始化时 dump DEX，通杀大多数壳
```

## 八、网络抓包（免代理）

| 工具 | 原理 | Root | 特点 |
|------|------|------|------|
| **R0capture** | Frida 绕 SSL 抓明文 | 需要 | 免代理，输出 pcap |
| **PCAPdroid** | VPN 模式抓包 | 不需要 | Android App |
| **HttpCanary** | VPN 模式 HTTP(S) | 不需要 | 图形化 |
| **tcpdump** | 底层抓包 | 需要 | 命令行 |

```bash
# R0capture
frida -U -f com.target.app -l r0capture.js --no-pause -o capture.pcap

# 设备端 tcpdump
adb push tcpdump /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/tcpdump
adb shell su -c "/data/local/tmp/tcpdump -i any -w /sdcard/cap.pcap"
adb pull /sdcard/cap.pcap
```

## 九、ADB 高级操作

```bash
# 信息收集
adb shell dumpsys package com.target.app | head -50
adb shell dumpsys activity com.target.app
adb shell cat /data/data/com.target.app/shared_prefs/*.xml
adb shell sqlite3 /data/data/com.target.app/databases/app.db "SELECT * FROM users"

# 启动组件
adb shell am start -n com.target.app/.MainActivity
adb shell am start -a android.intent.action.VIEW -d "https://example.com"
adb shell am broadcast -a com.target.app.CUSTOM_ACTION

# 备份提取
adb backup -f backup.ab com.target.app
# 解包: java -jar abe.jar unpack backup.ab backup.tar
```

## 十、drozer 安全测试

```bash
adb forward tcp:31415 tcp:31415
drozer console connect

# 信息收集
run app.package.info -a com.target.app
run app.package.attacksurface com.target.app

# Content Provider
run scanner.provider.finduris -a com.target.app
run app.provider.query content://com.target.app/users --vertical

# Activity / Service / Receiver
run app.activity.info -a com.target.app
run app.activity.start --component com.target.app com.target.app.DebugActivity
run app.service.info -a com.target.app
run app.broadcast.info -a com.target.app
```

## 十一、Root 方案对比

| 方案 | 原理 | Android | 特点 |
|------|------|---------|------|
| **Magisk** | Systemless boot | 6.0-15 | 主流，Zygisk + DenyList |
| **KernelSU** | 内核级 Root | 11+ | 更隐蔽 |
| **APatch** | 内核补丁 | 11+ | 新方案 |

**隐藏链路:** Magisk → Zygisk → DenyList + Shamiko → Play Integrity Fix

## 十二、SO 文件分析

```bash
readelf -s libtarget.so | grep -E "(encrypt|JNI|Register)"
readelf -s libtarget.so | grep Java_        # JNI 静态注册
strings libtarget.so | grep -iE "(key|secret|api|http)"
```

**IDA 分析 SO:** 搜索 `JNI_OnLoad` → 分析动态注册 → 定位加密函数 → F5 反编译

## 十三、反检测绕过

| 检测类型 | 方案 |
|---------|------|
| Root 检测 | Magisk DenyList / Shamiko / KernelSU / Frida 脚本 |
| SSL 锁定 | Frida 脚本 / JustTrustMe / ReFlutter (Flutter) |
| 签名校验 | CorePatch / 手动 patch smali |
| 模拟器检测 | 修改 `ro.product.model` 等 prop |
| Play Integrity | Play Integrity Fix 模块 |
| Frida 检测 | Gadget / 改名 frida-server / 反检测脚本 |
| 调试检测 | Frida hook `ptrace` / Xposed 绕过 |
