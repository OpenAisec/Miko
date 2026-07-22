# 二进制逆向参考手册

## 一、PE 文件结构

### PE 头结构

```
┌─────────────────────┐ 0x00
│   DOS Header        │ "MZ" 魔数, e_lfanew → NT Headers
├─────────────────────┤
│   DOS Stub          │ "This program cannot be run in DOS mode"
├─────────────────────┤ e_lfanew
│   PE Signature      │ "PE\0\0"
├─────────────────────┤
│   File Header       │ Machine, NumberOfSections, TimeDateStamp
├─────────────────────┤
│   Optional Header   │ AddressOfEntryPoint, ImageBase, SectionAlignment
├─────────────────────┤
│   Section Headers   │ .text, .data, .rdata, .rsrc, .reloc
└─────────────────────┘
```

### 重要段

| 段名 | 内容 | 属性 |
|------|------|------|
| `.text` | 可执行代码 | R-X |
| `.data` | 已初始化全局变量 | RW- |
| `.rdata` | 只读数据（常量、导入表） | R-- |
| `.rsrc` | 资源（图标、对话框、版本信息） | R-- |
| `.reloc` | 重定位表 | R-- |
| `.rva`/`.idata` | 导入表 | R-- |

### Python pefile 解析

```python
import pefile

pe = pefile.PE("target.exe")
print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
print(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")

# 遍历段
for section in pe.sections:
    print(f"{section.Name.decode().rstrip(chr(0)):8s} VA=0x{section.VirtualAddress:x} Size=0x{section.Misc_VirtualSize:x}")

# 遍历导入
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"\n{entry.dll.decode()}")
    for imp in entry.imports:
        print(f"  {imp.name.decode() if imp.name else 'ordinal':40s} @ 0x{imp.address:x}")
```

## 二、ELF 文件结构

```bash
# 查看 ELF 头
readelf -h target.elf

# 查看段/节
readelf -S target.elf       # 节头
readelf -l target.elf       # 程序头（段）

# 查看符号
readelf -s target.elf       # 符号表
nm target.elf               # 符号列表
objdump -d target.elf       # 反汇编

# 查看动态链接
readelf -d target.elf       # 动态段
ldd target.elf              # 依赖库
```

### 关键节

| 节名 | 内容 |
|------|------|
| `.text` | 代码段 |
| `.plt` | 过程链接表（动态函数调用跳板） |
| `.got` | 全局偏移表（外部函数/变量地址） |
| `.data` | 已初始化数据 |
| `.bss` | 未初始化数据 |
| `.rodata` | 只读数据 |

## 三、IDA Pro 进阶

### 快捷键

| 快捷键 | 功能 | 快捷键 | 功能 |
|--------|------|--------|------|
| F5 | 伪代码（Hex-Rays） | Esc | 返回上一视图 |
| X | 交叉引用 | N | 重命名 |
| G | 跳转到地址 | ; | 添加注释 |
| Y | 修改类型 | H | 十进制/十六进制切换 |
| P | 创建函数 | U | 取消定义 |
| D | 数据类型切换 | C | 转为代码 |
| Space | 图形/文本切换 | Ctrl+F | 搜索 |

### IDAPython 脚本

```python
import idautils, idc, idaapi

# 搜索字符串
for s in idautils.Strings():
    if "encrypt" in str(s).lower():
        print(f"0x{s.ea:x}: {s}")

# 枚举所有函数
for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    if "key" in name.lower() or "crypt" in name.lower():
        print(f"0x{func_ea:x}: {name}")

# 修改字节（Patch）
idc.patch_byte(addr, 0x90)  # NOP

# 获取函数调用图
func = idaapi.get_func(here())
for xref in idautils.CodeRefsTo(func.start_ea, 0):
    print(f"Called from: 0x{xref:x} ({idc.get_func_name(xref)})")
```

### 常见模式识别

```asm
; 函数序言 (x86)
push ebp
mov ebp, esp
sub esp, 0x40        ; 局部变量空间

; 函数序言 (x64)
push rbp
mov rbp, rsp
sub rsp, 0x40

; switch 跳转表: 间接跳转 + 表
cmp eax, 5
ja default
jmp [table + eax*4]

; 虚函数调用 (C++)
mov ecx, [this]           ; this 指针
mov eax, [ecx]            ; vtable
call [eax + 0x10]         ; 虚函数偏移
```

## 四、Ghidra 工作流

```
1. File → Import File → 选择二进制
2. Auto-Analysis → 是（自动分析）
3. Search → For Strings → 搜索关键字符串
4. 右键函数 → Decompile（伪代码）
5. Window → Defined Strings → 定位密钥/URL
6. Script Manager → 运行分析脚本
```

### Ghidra Python 脚本

```python
# 在 Ghidra Script Manager 中运行
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface

# 搜索字符串
listing = currentProgram.getListing()
for s in currentProgram.getListing().getDefinedData(True):
    if "api" in str(s.getValue()).lower():
        print(f"0x{s.getAddress()}: {s.getValue()}")

# 反编译函数
decomp = DecompInterface()
decomp.openProgram(currentProgram)
func = getGlobalFunctions("main")[0]
result = decomp.decompileFunction(func, 60, None)
print(result.getDecompiledFunction().getC())
```

## 五、x64dbg 调试

### 快捷键

| 快捷键 | 功能 |
|--------|------|
| F2 | 设置/取消断点 |
| F7 | 单步步入（Step Into） |
| F8 | 单步步过（Step Over） |
| F9 | 运行 |
| Ctrl+F9 | 运行到返回（Step Until Return） |
| Ctrl+G | 跳转到地址 |
| Space | 修改汇编指令 |

### 反调试绕过

```asm
; IsDebuggerPresent 补丁
; 找到调用: call IsDebuggerPresent
; 改为: xor eax, eax; nop (返回 0)

; 手动补丁方法:
; 1. 在 IsDebuggerPresent 下断点
; 2. 命中后修改 EAX = 0
; 3. 或直接 patch: mov eax, 0; ret

; NtQueryInformationProcess 绕过
; 在调用处下断点，修改返回值 ProcessDebugPort = 0

; 时间检测绕过
; 使用硬件断点避免 rdtsc 检测
; 或 patch rdtsc: xor eax,eax; xor edx,edx
```

### 脱壳通用方法

```
1. ESP 定律:
   - F8 单步到 OEP 附近
   - ESP 变化后设硬件断点 (Hardware Breakpoint on ESP)
   - F9 运行到 OEP

2. 单步跟踪:
   - F7/F8 一步步跟踪
   - 遇到向上跳转用 F4 跳过循环
   - 到达大跳转（jmp far）通常就是 OEP

3. 内存断点:
   - 在 .text 段设内存执行断点
   - 脱壳代码执行完后会跳到 OEP 触发断点
```

## 六、DLL 注入

### CreateRemoteThread 注入（C）

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    DWORD pid = atoi(argv[1]);
    const char* dll_path = "C:\\path\\to\\inject.dll";

    // 1. 打开目标进程
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("OpenProcess failed: %d\n", GetLastError()); return 1; }

    // 2. 在目标进程分配内存
    LPVOID remote_mem = VirtualAllocEx(hProc, NULL, strlen(dll_path)+1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 3. 写入 DLL 路径
    WriteProcessMemory(hProc, remote_mem, dll_path, strlen(dll_path)+1, NULL);

    // 4. 创建远程线程调用 LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"),
        remote_mem, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    // 清理
    VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    printf("Injection complete!\n");
    return 0;
}
```

### Inline Hook（MinHook）

```c
#include <MinHook.h>

typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t fpMessageBoxA = NULL;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[HOOK] MessageBox: %s\n", lpText);
    return fpMessageBoxA(hWnd, "Hooked!", lpCaption, uType);
}

void InstallHook() {
    MH_Initialize();
    MH_CreateHookApi(L"user32", "MessageBoxA", &HookedMessageBoxA, (LPVOID*)&fpMessageBoxA);
    MH_EnableHook(MH_ALL_HOOKS);
}
```

### VMT Hook（虚函数表 Hook）

```c
// C++ 虚函数表 Hook — 适用于 COM 接口、游戏引擎对象
// 对象内存: [vtable_ptr] → [vtable] → [func0, func1, func2...]

void** GetVTable(void* obj) {
    return *(void***)obj;  // 第一个成员是指向 vtable 的指针
}

void VMT_Hook(void* obj, int index, void* hookFunc, void** origFunc) {
    void** vtable = GetVTable(obj);
    DWORD oldProtect;
    VirtualProtect(&vtable[index], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
    if (origFunc) *origFunc = vtable[index];  // 保存原始函数
    vtable[index] = hookFunc;                  // 替换为 Hook 函数
    VirtualProtect(&vtable[index], sizeof(void*), oldProtect, &oldProtect);
}

// 使用示例: Hook 虚函数表第 3 个函数
// typedef HRESULT (__stdcall* Present_t)(void*, UINT, UINT);
// Present_t origPresent = NULL;
// HRESULT __stdcall HookedPresent(void* swapChain, UINT syncInterval, UINT flags) {
//     // 自定义渲染逻辑（Overlay 等）
//     return origPresent(swapChain, syncInterval, flags);
// }
// VMT_Hook(swapChain, 8, HookedPresent, (void**)&origPresent);
```

### AOB 特征码扫描

```python
import ctypes
from ctypes import wintypes

def aob_scan(process_handle, pattern, mask, start=0, size=0x7FFFFFFF):
    """在目标进程中扫描特征码
    pattern: bytes, 如 b'\x55\x8B\xEC\x83'
    mask: str, 如 'xxxx??xx' (x=精确匹配, ??=通配)
    """
    # 读取内存
    data = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    ctypes.windll.kernel32.ReadProcessMemory(
        process_handle, ctypes.c_void_p(start), data, size, ctypes.byref(bytes_read))

    # 扫描
    for i in range(bytes_read.value - len(pattern)):
        match = True
        for j in range(len(pattern)):
            if mask[j] == 'x' and data[i+j] != pattern[j]:
                match = False
                break
        if match:
            return start + i
    return None

# 示例: 搜索 55 8B EC 83 E4 F8 ?? ?? ?? 53 56 8B F1
# addr = aob_scan(hProc, b'\x55\x8B\xEC\x83\xE4\xF8\x00\x00\x00\x53\x56\x8B\xF1',
#                  'xxxxxx???xxxx')
```

### 指针链与基址定位

```python
# 多级指针追踪: 基址 + offset1 → + offset2 → + offset3 = 目标地址
def read_pointer_chain(hProc, base, offsets):
    """追踪多级指针链"""
    addr = base
    for offset in offsets:
        addr = read_memory(hProc, addr, 4)  # 读取指针值
        if addr == 0:
            return None
        addr += offset
    return addr

# 示例: game.exe+0x123456 → +0x10 → +0x20 → +0x4 = 血量地址
# base = get_module_base("game.exe") + 0x123456
# hp_addr = read_pointer_chain(hProc, base, [0x10, 0x20, 0x4])
```

## 七、.NET 逆向

### dnSpy 工作流

```
1. 打开 .exe 或 .dll
2. 浏览 Assembly → Namespace → Class → Methods
3. 右键方法 → Edit Method (IL) 或 Edit Method (C#)
4. Debug → Attach to Process → 选择 .NET 进程
5. 设置断点 → 触发 → 查看变量
```

### de4dot 反混淆

```bash
# 自动检测并去除 .NET 混淆
de4dot obfuscated.exe -o clean.exe

# 指定混淆器
de4dot obfuscated.exe -p dotfuscator -o clean.exe
```

### Harmony 补丁（运行时修改 .NET 方法）

```csharp
using HarmonyLib;

// 前置补丁：方法执行前
[HarmonyPatch(typeof(TargetClass), "TargetMethod")]
class Patch {
    static bool Prefix(ref int __result) {
        __result = 999;  // 修改返回值
        return false;    // false = 不执行原方法
    }
}

// 启动
var harmony = new Harmony("com.example.patch");
harmony.PatchAll();
```

## 八、Java 逆向

### jadx-gui 工作流

```bash
jadx-gui target.jar     # 或 target.apk
# 搜索字符串、类、方法
# 反编译为 Java 源码
# 导出为 Gradle 项目
```

### CFR 命令行反编译

```bash
java -jar cfr.jar target.class --outputdir output/
java -jar cfr.jar target.jar --outputdir output/
# 支持 Java 21+, 处理 lambda、switch expression 等新语法
```

### Java Agent 注入

```java
// Agent 类
public class MyAgent {
    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer((loader, className, classBeingRedefined, protectionDomain, classfileBuffer) -> {
            if (className.equals("com/example/Target")) {
                System.out.println("[Agent] Transforming: " + className);
                // 使用 ASM 修改字节码
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
                cr.accept(new MyClassVisitor(cw), 0);
                return cw.toByteArray();
            }
            return null;
        });
    }
}
# 启动: java -javaagent:agent.jar -jar target.jar
```
