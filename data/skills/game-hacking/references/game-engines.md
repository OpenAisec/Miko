# 游戏引擎逆向特化 (Game Engine Reverse Engineering)

## 目录

1. [Unity IL2CPP](#unity-il2cpp)
2. [Unity Mono](#unity-mono)
3. [Unreal Engine 4/5](#unreal-engine-45)
4. [Cocos2d-x](#cocos2d-x)
5. [自研引擎通用分析](#自研引擎通用分析)
6. [引擎识别方法](#引擎识别方法)

---

## Unity IL2CPP

### IL2CPP 编译流程

```
C# 源码 → C# 编译器 → IL 中间代码 → IL2CPP 转换 → C++ 代码 → 原生编译 → .so / GameAssembly.dll
```

### 关键文件

| 文件 | 位置 | 用途 |
|------|------|------|
| GameAssembly.dll / libil2cpp.so | 游戏目录 | IL2CPP 编译后的原生代码 |
| global-metadata.dat | assets/bin/Data/Managed/Metadata/ | 类/方法/字符串元数据 |
| UnityFramework (iOS) | app bundle | iOS 的 IL2CPP 二进制 |

### Il2CppDumper 使用

```bash
# 下载: github.com/Perfare/Il2CppDumper

# 使用方法
Il2CppDumper.exe <GameAssembly.dll/libil2cpp.so> <global-metadata.dat> <output_dir>

# 输出文件:
# dump.cs — 所有类、方法、字段的声明（类似 C# 源码）
# script.json — 方法地址映射（可导入 IDA/Ghidra）
# stringliteral.json — 字符串字面量
```

### Metadata 版本差异

```
不同 Unity 版本的 global-metadata.dat 格式不同:

MetadataVersion 24: Unity 5.x
MetadataVersion 27: Unity 2017-2018
MetadataVersion 29: Unity 2019-2020
MetadataVersion 29 (v2): Unity 2021+
MetadataVersion 29 (v3): Unity 2022+

Il2CppDumper 会自动检测版本。
如果遇到新版本不支持，需要更新 Il2CppDumper 或手动分析。
```

### Frida Hook IL2CPP 函数

```javascript
// 方法1: 通过 Il2CppDumper 输出的地址 Hook
// 在 dump.cs 中找到目标方法，查 script.json 获取地址

var gameAssembly = Module.findBaseAddress("GameAssembly.dll");  // Windows
// var gameAssembly = Module.findBaseAddress("libil2cpp.so");   // Android

// Hook 特定方法（地址来自 script.json）
var targetAddr = gameAssembly.add(0x123456);  // 替换为实际偏移
Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        // args[0] = this (对于实例方法)
        // args[1+] = 方法参数
        console.log("Method called");
    },
    onLeave: function(retval) {
        console.log("Return:", retval.toInt32());
        retval.replace(9999);  // 修改返回值
    }
});

// 方法2: 通过 IL2CPP API 动态查找
function il2cpp_resolve(className, methodName, paramCount) {
    var il2cpp_domain_get = new NativeFunction(
        Module.findExportByName(null, "il2cpp_domain_get"), 'pointer', []);
    var il2cpp_class_from_name = new NativeFunction(
        Module.findExportByName(null, "il2cpp_class_from_name"),
        'pointer', ['pointer', 'pointer', 'pointer']);
    var il2cpp_class_get_method_from_name = new NativeFunction(
        Module.findExportByName(null, "il2cpp_class_get_method_from_name"),
        'pointer', ['pointer', 'pointer', 'int']);

    var domain = il2cpp_domain_get();
    var assemblies = Memory.alloc(Process.pointerSize);
    var count = Memory.alloc(4);

    // il2cpp_domain_get_assemblies
    var get_assemblies = new NativeFunction(
        Module.findExportByName(null, "il2cpp_domain_get_assemblies"),
        'pointer', ['pointer', 'pointer']);
    var assemblyList = get_assemblies(domain, count);
    var assemblyCount = Memory.readUInt(count);

    // 遍历 assembly 查找类
    for (var i = 0; i < assemblyCount; i++) {
        var assembly = Memory.readPointer(assemblyList.add(i * Process.pointerSize));
        // il2cpp_assembly_get_image
        var get_image = new NativeFunction(
            Module.findExportByName(null, "il2cpp_assembly_get_image"),
            'pointer', ['pointer']);
        var image = get_image(assembly);

        var klass = il2cpp_class_from_name(image, 
            Memory.allocUtf8String(""), Memory.allocUtf8String(className));
        if (klass.isNull()) continue;

        var method = il2cpp_class_get_method_from_name(klass,
            Memory.allocUtf8String(methodName), paramCount);
        if (!method.isNull()) {
            // 读取方法的 RVA
            var slot = Memory.readU32(method.add(0x18));  // MethodPointer offset
            return method;
        }
    }
    return null;
}

// 使用
var method = il2cpp_resolve("Player", "GetHealth", 0);
if (method) {
    var addr = Memory.readPointer(method.add(0x08));  // method pointer
    Interceptor.attach(addr, {
        onLeave: function(retval) { retval.replace(9999); }
    });
}
```

### Ghidra 自动标注 IL2CPP

```bash
# 使用 GhidraScript 导入 Il2CppDumper 的 script.json
# 脚本: github.com/Perfare/Il2CppDumper 中的 GhidraScripts/

# 在 Ghidra 中:
# 1. File → Script Manager
# 2. 导入 il2cpp_ghidra.py
# 3. 运行脚本，选择 script.json
# 4. 自动标注所有函数名、类名
```

---

## Unity Mono

### Mono 与 IL2CPP 的区别

```
Mono:
- C# 代码编译为 IL 中间代码
- 运行时由 Mono VM 解释执行
- 可以直接用 dnSpy 反编译为 C# 源码
- 程序集文件: Assembly-CSharp.dll

IL2CPP:
- IL 代码先转为 C++，再编译为原生代码
- 反编译结果是 C++ 伪代码，不如 C# 直观
- 需要 Il2CppDumper + IDA/Ghidra 分析
- 元数据在 global-metadata.dat 中
```

### dnSpy 反编译 Mono 游戏

```
1. 找到游戏目录下的 Managed/ 文件夹
2. 用 dnSpy 打开 Assembly-CSharp.dll
3. 直接查看 C# 源码
4. 可以修改代码并保存（实现 Mod）

优势:
- 代码几乎和原始源码一样
- 可以直接理解游戏逻辑
- 修改方便（编辑 → 编译 → 保存）
```

---

## Unreal Engine 4/5

### UE4 内存结构

```
UE4 的核心数据结构:

GNames (全局名称表):
- 存储所有 UObject 的名称
- 类型: TArray<FNameEntry*>
- 每个 chunk 包含 16384 个 FNameEntry

GObjects (全局对象表):
- 存储所有 UObject 实例
- 类型: TUObjectArray
- 可以遍历所有游戏对象

UObject:
- 每个游戏对象的基类
- 包含: ClassPrivate, NamePrivate, OuterPrivate
- 通过 GObjects 索引访问
```

### 定位 GNames 和 GObjects

```cpp
// 方法1: 通过字符串搜索
// 在 IDA 中搜索已知的 UObject 名称字符串
// 然后追踪引用找到 GNames 表

// 方法2: 通过特征码
// GNames 通常是全局变量，包含指针数组
// 搜索特征码定位

// 方法3: 使用 UE4SS 工具
// 自动定位 GNames 和 GObjects
```

### UE4SS 工具

```
UE4SS (Unreal Engine 4 Scripting System):
- github.com/UE4SS-RE/RE-UE4SS

功能:
- 自动定位 GNames/GObjects
- 提供 Lua 脚本接口
- 支持 UE4/UE5
- 可以遍历所有 UObject
- 支持 Hook UE4 函数

使用方法:
1. 下载 UE4SS
2. 将 xinput1_3.dll 放到游戏目录
3. 运行游戏
4. UE4SS 自动注入并提供脚本接口
```

### UE4 对象遍历

```python
# 使用 Frida 遍历 UE4 GNames
def dump_ue4_names(base_addr, gnames_offset):
    """遍历 UE4 GNames 表"""
    gnames_ptr = read_pointer(base_addr + gnames_offset)

    for chunk_idx in range(100):  # 遍历 chunks
        chunk_ptr = read_pointer(gnames_ptr + chunk_idx * 8)
        if not chunk_ptr:
            break

        for entry_idx in range(16384):  # 每个 chunk 的条目
            entry_ptr = read_pointer(chunk_ptr + entry_idx * 8)
            if not entry_ptr:
                continue

            # FNameEntry 的字符串偏移因版本而异
            name = read_string(entry_ptr + 0x10)
            if name:
                print(f"[{chunk_idx * 16384 + entry_idx}] {name}")
```

### UE4 反射系统

```
UE4 使用反射系统，可以通过名称动态查找:

UClass::FindClass("Blueprint'/Game/Player/BP_Player.BP_Player_C'")
UFunction::FindFunction("Function Engine.Actor.K2_SetActorLocation")

这意味着:
1. 可以通过字符串查找任意类和函数
2. 可以动态调用游戏函数
3. 蓝图编译后的字节码也可以分析
```

---

## Cocos2d-x

### 特征识别

```
Cocos2d-x 游戏特征:
- 存在 libcocos2d.so / cocos2d.dll
- 可能有 Lua/JS 脚本文件
- 资源文件通常在 assets/ 目录
```

### Lua 脚本提取

```python
# Cocos2d-x Lua 游戏的脚本通常被编译为字节码
# 使用 luadec 或 unluac 反编译

# 如果脚本未加密:
# 直接在 APK 的 assets/ 目录下找到 .lua 文件

# 如果脚本被编译为字节码:
# 使用 luadec 反编译

# 如果脚本被加密:
# 需要找到解密函数（通常在 libcocos2d.so 中）
# IDA 搜索 "xxtea" 或 "encrypt" 关键字
```

### Frida Hook Cocos2d-x

```javascript
// Hook Cocos2d-x 的 Lua 接口
Interceptor.attach(Module.findExportByName("libcocos2d.so", "luaL_loadbuffer"), {
    onEnter: function(args) {
        // args[1] = buffer (Lua 脚本内容)
        // args[2] = size
        var size = args[2].toInt32();
        if (size > 0 && size < 100000) {
            var script = Memory.readUtf8String(args[1], size);
            console.log("[Lua Script]\n" + script.substring(0, 500));
        }
    }
});

// Hook Cocos2d-x 的文件加载
Interceptor.attach(Module.findExportByName("libcocos2d.so", "CCFileUtils::getFileData"), {
    onEnter: function(args) {
        var filename = Memory.readUtf8String(args[0]);
        console.log("Loading file: " + filename);
    }
});
```

---

## 自研引擎通用分析

### 分析步骤

```
1. 引擎识别:
   - 搜索引擎特征字符串
   - 分析导入表（DirectX/OpenGL/Vulkan）
   - 查看资源文件格式

2. 渲染管线分析:
   - 找到 DirectX/OpenGL/Vulkan 初始化代码
   - 定义 Present/SwapBuffers 函数
   - 分析绘制调用流程

3. 对象系统分析:
   - 搜索构造/析构函数模式
   - 分析内存分配器
   - 还原对象继承关系

4. 资源系统分析:
   - 分析资源文件格式
   - 找到资源加载函数
   - 理解资源引用机制
```

### 常见模式

```
内存分配器:
- 自定义 malloc/free 包装
- 对象池 (Object Pool)
- 内存池 (Memory Pool)
- 分析分配器可以理解对象大小和布局

渲染管线:
- DX9: IDirect3DDevice9::EndScene
- DX11: IDXGISwapChain::Present
- DX12: IDXGISwapChain::Present
- OpenGL: wglSwapBuffers / eglSwapBuffers
- Vulkan: vkQueuePresentKHR
```

---

## 引擎识别方法

### 快速判断

```bash
# 查看游戏目录结构

# Unity:
# - global-metadata.dat
# - GameAssembly.dll (Windows) / libil2cpp.so (Android)
# - UnityPlayer.dll
# - *_Data/ 目录

# Unreal Engine:
# - .pak 资源文件
# - Engine/ 目录
# - UnrealEngine 相关 DLL

# Cocos2d-x:
# - libcocos2d.so
# - assets/ 下有 .lua 或 .jsc 文件
# - cocos2d 相关特征
```

### 通过导入表判断

```
# 用 Dependencies 或 IDA 查看导入表

Unity (IL2CPP):
- il2cpp 相关函数
- UnityPlayer.dll 导出

Unreal Engine:
- UE4 相关特征函数
- FMemory::Malloc 等

Cocos2d-x:
- cocos2d 命名空间的函数
- Lua 相关 API
```
