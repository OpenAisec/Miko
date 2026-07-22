# 手游平台特化 (Platform Mobile)

## Android 逆向

### 工具链

```
APK 分析:
- jadx — APK 反编译为 Java 源码
- apktool — 资源文件解包
- JEB — 商业级反编译器
- Android Studio — 调试和分析

动态分析:
- Frida — 动态插桩框架
- Xposed — Java 层 Hook 框架
- Magisk — Root 管理
- LSPosed — 新一代 Xposed 框架

Native 分析:
- IDA Pro / Ghidra — so 文件分析
- Il2CppDumper — Unity IL2CPP 分析
```

### Frida 基础

```bash
# 安装
pip install frida-tools

# 在手机上运行 frida-server
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# 列出进程
frida-ps -U

# 附加到应用
frida -U -f com.game.package -l script.js
```

### Frida Hook Java 层

```javascript
// Hook Java 方法
Java.perform(function() {
    // 获取类
    var PlayerClass = Java.use("com.game.Player");
    
    // Hook 方法
    PlayerClass.getHealth.implementation = function() {
        console.log("getHealth called");
        var result = this.getHealth();
        console.log("Original health: " + result);
        return 9999;  // 修改返回值
    };
    
    // Hook 构造函数
    PlayerClass.$init.overload('java.lang.String').implementation = function(name) {
        console.log("Player created: " + name);
        this.$init(name);
    };
    
    // Hook 重载方法
    PlayerClass.attack.overload('int').implementation = function(damage) {
        console.log("Attack damage: " + damage);
        this.attack(damage * 10);  // 10倍伤害
    };
    
    // 枚举所有方法
    var methods = PlayerClass.class.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
        console.log("Method: " + methods[i].getName());
    }
});
```

### Frida Hook Native 层

```javascript
// Hook native 函数
Interceptor.attach(Module.findExportByName("libil2cpp.so", "Player_GetHealth"), {
    onEnter: function(args) {
        console.log("Player_GetHealth called");
        // args[0] = this pointer
    },
    onLeave: function(retval) {
        console.log("Original health: " + retval.toInt32());
        retval.replace(9999);  // 修改返回值
    }
});

// Hook 任意地址
var baseAddr = Module.findBaseAddress("libil2cpp.so");
var targetFunc = baseAddr.add(0x123456);  // 函数偏移

Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("arg0: " + args[0].toInt32());
        console.log("arg1: " + args[1].toInt32());
        console.log("arg2: " + Memory.readUtf8String(args[2]));
    },
    onLeave: function(retval) {
        retval.replace(1);  // 修改返回值
    }
});
```

### Unity IL2CPP 分析

```bash
# 使用 Il2CppDumper
# 1. 从 APK 中提取:
#    - lib/arm64-v8a/libil2cpp.so
#    - assets/bin/Data/Managed/Metadata/global-metadata.dat

# 2. 运行 Il2CppDumper
Il2CppDumper.exe libil2cpp.so global-metadata.dat output/

# 3. 输出:
#    - dump.cs — 所有类和方法声明
#    - script.json — 方法地址映射（可导入 IDA/Ghidra）

# 4. 在 Ghidra 中导入 script.json 自动标注函数名
```

```javascript
// Frida Hook IL2CPP 函数
// 通过方法名查找地址
function hook_il2cpp_method(class_name, method_name, callback) {
    var il2cpp = Process.findModuleByName("libil2cpp.so");
    
    // 使用 il2cpp API 获取方法
    var il2cpp_domain_get = new NativeFunction(
        Module.findExportByName("libil2cpp.so", "il2cpp_domain_get"),
        'pointer', []);
    var il2cpp_class_from_name = new NativeFunction(
        Module.findExportByName("libil2cpp.so", "il2cpp_class_from_name"),
        'pointer', ['pointer', 'pointer', 'pointer']);
    var il2cpp_class_get_method_from_name = new NativeFunction(
        Module.findExportByName("libil2cpp.so", "il2cpp_class_get_method_from_name"),
        'pointer', ['pointer', 'pointer', 'int']);
    
    var domain = il2cpp_domain_get();
    // ... 获取 class 和 method
    // 最终 Hook 目标方法
}
```

## iOS 逆向

### 工具链

```
越狱环境:
- checkra1n / palera1n — 越狱工具
- Cydia / Sileo — 包管理器

分析工具:
- class-dump — 导出头文件
- Frida — 动态插桩
- Hopper Disassembler — 反汇编
- IDA Pro — 静态分析
- Reveal — UI 分析
```

### Frida iOS

```bash
# 在越狱设备上安装 Frida
# 通过 Cydia 添加源: https://build.frida.re

# 列出进程
frida-ps -U

# 附加到应用
frida -U -f com.game.app -l script.js
```

```javascript
// Hook Objective-C 方法
if (ObjC.available) {
    var PlayerClass = ObjC.classes.Player;
    
    // Hook 方法
    Interceptor.attach(PlayerClass['- getHealth'].implementation, {
        onEnter: function(args) {
            // args[0] = self
            // args[1] = _cmd (selector)
        },
        onLeave: function(retval) {
            console.log("Health: " + retval.toInt32());
            retval.replace(9999);
        }
    });
    
    // 枚举方法
    var methods = PlayerClass.$ownMethods;
    for (var i = 0; i < methods.length; i++) {
        console.log(methods[i]);
    }
}
```

## Unity 跨平台分析

### AssetBundle 分析

```python
# 使用 UnityPy 解包 AssetBundle
import UnityPy

env = UnityPy.load("game_assets")
for obj in env.objects:
    data = obj.read()
    if obj.type.name == "Texture2D":
        # 导出贴图
        img = data.image
        img.save(f"{data.name}.png")
    elif obj.type.name == "MonoBehaviour":
        # 读取配置数据
        print(data.read_typetree())
```

### UE4 手游分析

```
UE4 手游的特点:
- 使用 .pak 文件打包资源
- C++ 编译为 .so (Android) 或 dylib (iOS)
- 可能使用蓝图编译后的字节码

分析方法:
1. 用 UE4PakExtractor 解包 .pak
2. 用 IDA/Ghidra 分析 .so 文件
3. 找到 GNames 和 GObjects 全局表
4. 通过反射系统遍历类和函数
```

## 手游保护系统分析

### 腾讯 MTP / ACE 手游保护

```
腾讯手游保护 (MTP/ACE) 架构:

1. Java 层保护:
   - 类加载监控
   - 反射调用检测
   - 动态代理检测
   - 模拟器检测

2. Native 层保护 (libtp2.so / libACE.so):
   - so 文件完整性校验
   - 调试器检测 (ptrace, /proc/self/status)
   - Frida 检测 (扫描 /proc/self/maps 中的 frida-agent)
   - Root 检测 (Magisk, SuperSU)
   - Xposed 检测 (XposedBridge.jar)
   - 内存完整性校验

3. 驱动层保护 (部分游戏):
   - 内核级调试器检测
   - 进程保护
   - 内存保护

检测 Frida 的常见方法:
- 扫描 /proc/self/maps 查找 frida-agent
- 检查 Frida 默认端口 (27042)
- 扫描内存中的 Frida 特征字符串
- 检查 /proc/self/fd/ 下的匿名管道
- ptrace 自检
```

### 网易易盾保护

```
网易易盾手游保护:

1. so 加壳:
   - 代码段加密
   - 运行时解密
   - 反 dump 保护

2. Java 方法保护:
   - 方法抽取（运行时才还原字节码）
   - 字符串加密
   - 控制流混淆

3. 检测机制:
   - 调试器检测
   - Root/越狱检测
   - 模拟器检测
   - 内存修改检测
```

### Mono vs IL2CPP 逆向差异

```
Unity Mono 游戏:
- 可以直接用 dnSpy 反编译 Assembly-CSharp.dll
- 代码清晰，接近原始 C# 源码
- 可以直接修改 DLL 实现 Mod
- 保护通常在 Native 层（libmono.so）

Unity IL2CPP 游戏:
- C# 代码被编译为 C++ 再编译为原生代码
- 需要 Il2CppDumper 提取元数据
- 反编译结果是 C++ 伪代码，不如 C# 直观
- 修改需要重新编译 so/DLL

判断方法:
- 存在 Assembly-CSharp.dll → Mono
- 存在 GameAssembly.dll / libil2cpp.so + global-metadata.dat → IL2CPP
```

### so 加壳/混淆识别与处理

```
常见 so 加壳方案:
1. UPX — 最常见，特征明显 (UPX!)
2. DEXProtect — DEX 加壳
3. 梆梆加固 — 国内主流
4. 爱加密 — 国内主流
5. 360加固 — 国内主流
6. 网易易盾 — 网易系游戏

识别方法:
- 查看 ELF 头信息: readelf -h libxxx.so
- 检查段名: readelf -S libxxx.so
- 查看导入表: 简单壳通常只有少量导入
- entropy 分析: 加壳后 entropy 接近 8.0

脱壳方法:
1. 内存 dump: 运行时 dump 解密后的 so
   - 使用 Frida dump 内存
   - 使用 IDA 附加后 dump
2. 通用脱壳机: FDex2 (DEX), dumpdex (Native)
3. 手动修复: dump 后需要修复 ELF 头和段表

Frida dump so:
```javascript
// dump 指定模块
function dump_so(name) {
    var module = Process.findModuleByName(name);
    var file = new File("/sdcard/" + name + ".dump", "wb");
    file.write(Memory.readByteArray(module.base, module.size));
    file.close();
    console.log("Dumped " + name + " (" + module.size + " bytes)");
}
dump_so("libil2cpp.so");
```
```
