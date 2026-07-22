# 反编译详解 (Decompilation)

## 目录

1. [反编译概述](#反编译概述)
2. [静态分析工具](#静态分析工具)
3. [动态调试工具](#动态调试工具)
4. [游戏引擎特化](#游戏引擎特化)
5. [代码还原技巧](#代码还原技巧)
6. [实战案例](#实战案例)

---

## 反编译概述

反编译是将编译后的二进制代码还原为可读的高级语言代码的过程。在游戏辅助开发中，反编译用于：

- 理解游戏的核心逻辑（伤害计算、移动机制等）
- 定位关键函数和数据结构
- 找到加密/校验算法
- 分析反外挂机制

### 分析流程

```
1. 确定目标文件（exe、dll、so、dat）
2. 用静态分析工具打开，了解整体结构
3. 定位关键函数（搜索字符串、API调用、特征码）
4. 动态调试验证分析结果
5. 还原关键逻辑的 C/Python 代码
```

---

## 静态分析工具

### IDA Pro

IDA 是最强大的反汇编/反编译工具：

```
常用操作:
- Space: 切换图形/文本视图
- F5: 反编译为伪代码（需要 Hex-Rays 插件）
- X: 查看交叉引用（谁调用了这个函数）
- N: 重命名变量/函数
- G: 跳转到地址
- Y: 修改变量类型
- ;: 添加注释

分析技巧:
1. 先看字符串窗口 (View → Open Subviews → Strings)
2. 搜索关键字符串（如 "health", "damage", "login"）
3. 通过字符串交叉引用找到相关函数
4. 分析函数的参数和返回值
5. 重命名有意义的函数和变量
```

### Ghidra（免费）

NSA 开源的逆向工具，功能接近 IDA：

```
优势:
- 完全免费
- 支持反编译（类似 Hex-Rays）
- 支持脚本自动化（Java/Python）
- 支持协作分析

常用操作:
- L: 重命名
- Ctrl+E: 编辑函数签名
- 右键 → Retype Variable: 修改变量类型
- Window → Decompile: 打开反编译窗口
```

### Binary Ninja

现代化的逆向工具，API 友好：

```python
# Binary Ninja Python API 示例
import binaryninja as bn

bv = bn.open_view("game.exe")

# 查找所有字符串
for string in bv.strings:
    if "health" in str(string).lower():
        print(f"Found: {string} at {hex(string.start)}")

# 查找函数
for func in bv.functions:
    if "player" in func.name.lower():
        print(f"Function: {func.name} at {hex(func.start)}")
```

---

## 动态调试工具

### x64dbg

Windows 下最流行的动态调试器：

```
基本操作:
- F2: 设置断点
- F7: 单步步入（进入函数）
- F8: 单步步过（跳过函数）
- F9: 运行
- Ctrl+G: 跳转到地址

调试技巧:
1. 在关键函数设断点
2. 观察寄存器和栈中的参数
3. 跟踪函数调用链
4. 修改寄存器/内存值测试效果
5. 记录关键偏移和特征码
```

### OllyDbg（32位经典）

```
窗口说明:
- 反汇编窗口: 显示汇编代码
- 寄存器窗口: 显示 CPU 寄存器
- 内存窗口: 显示内存数据
- 栈窗口: 显示调用栈
```

### WinDbg（内核调试）

```
# 附加到进程
.attach

# 设置断点
bp game+0x1234
bp game!FunctionName

# 查看内存
db address    ; 字节
dd address    ; 双字
dq address    ; 四字

# 查看调用栈
k

# 查看模块
lm
```

### Frida（动态插桩）

跨平台动态插桩框架，特别适合手游：

```javascript
// Hook 函数并打印参数
Interceptor.attach(Module.findExportByName("libc.so", "send"), {
    onEnter: function(args) {
        console.log("send called");
        console.log("  socket:", args[0].toInt32());
        console.log("  buffer:", hexdump(args[1], {length: args[2].toInt32()}));
        console.log("  length:", args[2].toInt32());
    },
    onLeave: function(retval) {
        console.log("  return:", retval.toInt32());
    }
});

// Hook 游戏内部函数
var gameModule = Module.findBaseAddress("libil2cpp.so");
var targetAddr = gameModule.add(0x123456);  // 目标函数偏移

Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        // args[0] = this 指针
        // args[1], args[2]... = 函数参数
        console.log("Function called, arg1:", args[1].toInt32());
    }
});
```

---

## 游戏引擎特化

### Unity (IL2CPP)

Unity 游戏编译为 IL2CPP 后，C# 代码被转为 C++：

```bash
# 使用 Il2CppDumper 提取元数据
# 1. 找到游戏的 global-metadata.dat 和 libil2cpp.so (或 GameAssembly.dll)
# 2. 运行 Il2CppDumper

Il2CppDumper.exe libil2cpp.so global-metadata.dat output/

# 输出:
# dump.cs — 所有类和方法的声明
# script.json — 方法地址映射

# 用 Ghidra 导入脚本分析
# File → Script Manager → 导入 GhidraScripts
# 加载 il2cpp_ghidra.py 自动标注函数名
```

```python
# 使用 Frida Hook Unity IL2CPP 函数
import frida

# 获取 IL2CPP 方法地址
def get_il2cpp_method_addr(module_name, class_name, method_name, param_count=0):
    script = f"""
    var module = Module.findBaseAddress("{module_name}");
    var il2cpp_domain = Module.findExportByName("{module_name}", "il2cpp_domain_get");
    var il2cpp_class = Module.findExportByName("{module_name}", "il2cpp_class_from_name");
    
    // 获取 domain
    var domain = new NativeFunction(il2cpp_domain, 'pointer', [])();
    
    // 获取 assembly 和 image
    var assemblies = Memory.alloc(Process.pointerSize);
    var count = Memory.alloc(4);
    // ... 完整实现需要调用多个 IL2CPP API
    """
    return script
```

### Unreal Engine 4

```
UE4 游戏分析要点:
1. 找到 GNames 和 GObjects 全局表
2. 通过 GNames 查找对象名称
3. 通过 GObjects 遍历所有 UObject
4. UE4 使用反射系统，可以动态查找类和函数

常用工具:
- UE4SS (Unreal Engine 4 Scripting System)
- Frida + UE4 插件
```

```python
# UE4 GNames 遍历示例
def dump_ue4_names(base_addr):
    """遍历 UE4 GNames 表"""
    gnames_ptr = read_pointer(base_addr + GNames_Offset)
    
    for i in range(100000):
        chunk_idx = i // 16384
        within_chunk = i % 16384
        
        chunk_ptr = read_pointer(gnames_ptr + chunk_idx * 8)
        if not chunk_ptr:
            break
        
        name_entry = read_pointer(chunk_ptr + within_chunk * 8)
        if not name_entry:
            continue
        
        name = read_string(name_entry + 0x10)  # FName 的字符串偏移
        if name:
            print(f"[{i}] {name}")
```

### 自研引擎

```
自研引擎没有通用方法，需要:
1. 分析入口函数和主循环
2. 找到渲染管线（DirectX/OpenGL 调用）
3. 通过字符串和 API 调用定位关键系统
4. 分析内存分配模式（对象池、链表等）
5. 逐步还原数据结构
```

---

## 代码还原技巧

### 识别常见模式

```
循环模式:
- for (i=0; i<n; i++)  → cmp + jl/jb 指令
- while (condition)    → test + jnz 指令

条件分支:
- if (x > 0)          → test eax, eax + jg
- switch/case          → 跳转表 (jump table)

函数调用:
- 函数序言: push ebp; mov ebp, esp
- 参数传递: 前4个用 ecx/edx/esi/edi (thiscall/fastcall)
- 返回值: eax/rax

虚函数调用:
- mov eax, [ecx]       ; 获取虚表
- call [eax+0x10]      ; 调用虚函数
```

### 结构体还原

```
1. 观察基址 + 偏移的访问模式
2. 根据数据大小推断类型:
   - 1字节: bool, char, byte
   - 2字节: short, WORD
   - 4字节: int, float, DWORD
   - 8字节: double, __int64, pointer (64位)
   - 变长: 可能是字符串或数组
3. 根据上下文推断字段含义
4. 在 IDA 中创建结构体 (Alt+Q)
```

---

## 实战案例

### 案例：找到伤害计算函数

```
目标: 找到游戏的伤害计算逻辑

步骤:
1. 在 IDA 中搜索字符串 "damage", "hurt", "hit"
2. 找到字符串 "Critical Hit!" 位于地址 0x10045678
3. 查看交叉引用 → 被函数 sub_10023456 引用
4. F5 反编译该函数:

int __fastcall calculate_damage(int attacker, int defender, int skill_id) {
    int base_damage = *(int*)(attacker + 0x50);  // 攻击力
    int defense = *(int*)(defender + 0x54);       // 防御力
    float skill_multiplier = get_skill_multiplier(skill_id);
    
    int damage = (int)(base_damage * skill_multiplier - defense);
    
    // 暴击判定
    float crit_rate = *(float*)(attacker + 0x60);
    if (random_float() < crit_rate) {
        damage *= 2;
        // 显示 "Critical Hit!"
    }
    
    return max(damage, 1);  // 最低伤害为1
}

5. 记录偏移:
   - attacker + 0x50 = 攻击力
   - attacker + 0x54 = 防御力
   - attacker + 0x60 = 暴击率
6. 函数地址: game.exe + 0x23456
```

### 案例：分析登录加密

```
目标: 理解登录密码的加密方式

步骤:
1. x64dbg 在 send 函数设断点
2. 触发登录，观察栈参数
3. 密码在发送前已被加密
4. 回溯调用栈，找到加密函数
5. IDA 分析加密函数:

void encrypt_password(char* input, char* output) {
    char key[] = "GameKey2024";
    int key_len = strlen(key);
    int input_len = strlen(input);
    
    for (int i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % key_len];
        output[i] = (output[i] << 3) | (output[i] >> 5);  // 循环左移3位
    }
}

6. 用 Python 实现相同的加密:
def encrypt_password(password):
    key = b"GameKey2024"
    result = bytearray()
    for i, b in enumerate(password.encode()):
        val = b ^ key[i % len(key)]
        val = ((val << 3) | (val >> 5)) & 0xFF
        result.append(val)
    return bytes(result)
```
