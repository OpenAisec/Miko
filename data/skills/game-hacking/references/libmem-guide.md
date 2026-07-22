# libmem 库使用指南

## 概述

libmem 是一个高级游戏黑客库，支持 C、C++、Rust 和 Python。提供进程操作、内存读写、模式扫描、Hook、汇编/反汇编等功能。

**GitHub:** https://github.com/rdbo/libmem (1.2k stars)
**支持平台:** Windows / Linux / FreeBSD (x86/x64)

## 安装

### Python
```bash
pip install libmem
```

### C++ (CMake)
```cmake
include(FetchContent)
FetchContent_Declare(libmem-config
    URL "https://raw.githubusercontent.com/rdbo/libmem/config-v1/libmem-config.cmake"
    DOWNLOAD_NO_EXTRACT TRUE)
FetchContent_MakeAvailable(libmem-config)
set(CMAKE_PREFIX_PATH "${libmem-config_SOURCE_DIR}" "${CMAKE_PREFIX_PATH}")
set(LIBMEM_DOWNLOAD_VERSION "5.1.4")
find_package(libmem CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE libmem::libmem)
```

### Rust
```toml
# Cargo.toml
[dependencies]
libmem = "5"
```

## 核心 API

### 进程操作

```python
from libmem import *

# 查找进程
process = find_process("game.exe")
print(f"PID: {process.pid}, Name: {process.name}")

# 枚举所有进程
for proc in enum_processes():
    print(f"{proc.pid}: {proc.name}")

# 检查进程是否存活
if is_process_alive(process):
    print("Process is running")
```

### 模块操作

```python
# 查找模块
module = find_module_ex(process, "game.dll")
print(f"Base: {hex(module.base)}, Size: {module.size}")

# 枚举所有模块
for mod in enum_modules_ex(process):
    print(f"{mod.name} @ {hex(mod.base)}")

# 查找符号地址
addr = find_symbol_address(module, "get_player_health")
print(f"get_player_health @ {hex(addr)}")
```

### 内存读写

```python
# 读取内存
health = read_memory_ex(process, health_addr, 4)  # 读取 4 字节
health_int = int.from_bytes(health, 'little')
print(f"Health: {health_int}")

# 写入内存
new_health = int(999).to_bytes(4, 'little')
write_memory_ex(process, health_addr, new_health)

# 深度指针追踪
# base + offset1 -> ptr1 + offset2 -> ptr2 + offset3 -> final_addr
final_addr = deep_pointer_ex(process, module.base + 0x1234, [0x10, 0x20, 0x30])
```

### 模式扫描

```python
# 签名扫描（查找特征码）
# ?? 表示通配符
pattern = "55 8B EC 83 E4 F8 ?? ?? ?? ?? ?? ?? 56 8B F1"
addr = sig_scan_ex(process, pattern, module.base, module.size)
print(f"Found pattern at: {hex(addr)}")

# 数据扫描
data = b"\x89\x5C\x24\x08"
addr = data_scan_ex(process, data, module.base, module.size)
```

### Hook 操作

```python
# C++ 示例（Python 版 Hook 支持有限）
# Inline Hook
"""
#include <libmem/libmem.h>

void hooked_function(int arg1) {
    printf("Hooked! arg1=%d\n", arg1);
    // 调用原函数
    original_function(arg1);
}

// 安装 Hook
lm_address_t target = LM_FindSymbolAddress(&module, "target_function");
LM_HookCode(target, (lm_address_t)hooked_function, &trampoline);
"""

# Python 版替代方案：使用 frida
# pip install frida-tools
```

### 汇编/反汇编

```python
# 汇编
payload = assemble("mov eax, 1; ret", 64)  # x64
print(f"Assembled: {payload.hex()}")

# 反汇编
code = bytes([0x55, 0x48, 0x89, 0xE5])
instructions = disassemble(code, 64, 0)
for inst in instructions:
    print(f"{hex(inst.address)}: {inst.mnemonic} {inst.op_str}")
```

## 实战示例

### 无限生命值

```python
from libmem import *
import time

process = find_process("game.exe")
module = find_module_ex(process, "game.exe")

# 方法1：直接地址（需要先用 CE 找到地址）
health_addr = module.base + 0x1A3B5C  # 偏移地址

while True:
    write_memory_ex(process, health_addr, int(999).to_bytes(4, 'little'))
    time.sleep(0.1)
```

### 指针链追踪

```python
from libmem import *

process = find_process("game.exe")
module = find_module_ex(process, "game.exe")

# CE 找到的指针链: game.exe+0x1A3B5C -> +0x10 -> +0x20 -> +0x30
health_ptr = deep_pointer_ex(
    process,
    module.base + 0x1A3B5C,
    [0x10, 0x20, 0x30]
)

# 读取生命值
health = int.from_bytes(read_memory_ex(process, health_ptr, 4), 'little')
print(f"Health: {health}")
```

### 特征码扫描 + 修改

```python
from libmem import *

process = find_process("game.exe")
module = find_module_ex(process, "game.exe")

# 找到"扣血"函数的特征码
damage_pattern = "55 8B EC 83 E4 F8 83 EC 10 56 8B F1"
damage_func = sig_scan_ex(process, damage_pattern, module.base, module.size)

if damage_func:
    # NOP 掉扣血指令（用 0x90 填充）
    nop_bytes = b"\x90" * 5  # NOP 5 字节（一条 call 指令的长度）
    write_memory_ex(process, damage_func + 0x15, nop_bytes)
    print("Damage function patched!")
```

## C++ 完整示例

```cpp
#include <libmem/libmem.hpp>
#include <iostream>

using namespace libmem;

int main() {
    // 查找进程
    auto process = FindProcess("game.exe");
    if (!process.has_value()) {
        std::cerr << "Process not found" << std::endl;
        return 1;
    }

    // 查找模块
    auto module = FindModuleEx(&process.value(), "game.dll");
    if (!module.has_value()) {
        std::cerr << "Module not found" << std::endl;
        return 1;
    }

    // 签名扫描
    auto addr = SigScanEx(&process.value(),
        "55 8B EC ?? ?? ?? 56 8B F1",
        module.value().base,
        module.value().size);

    if (addr.has_value()) {
        std::cout << "Found at: " << std::hex << addr.value() << std::endl;

        // 读取内存
        int health = 0;
        ReadMemoryEx(&process.value(), addr.value(), &health, sizeof(health));
        std::cout << "Health: " << health << std::endl;

        // 写入内存
        int new_health = 999;
        WriteMemoryEx(&process.value(), addr.value(), &new_health, sizeof(new_health));
    }

    return 0;
}
```

## 常见问题

**Q: 找不到进程？**
A: 确保以管理员权限运行，游戏可能需要管理员权限才能访问。

**Q: 写入内存失败？**
A: 使用 `ProtMemoryEx` 先修改内存保护属性为可写。

**Q: 特征码扫描找不到？**
A: 特征码可能因游戏版本不同而变化，需要重新用 CE/x64dbg 分析。

**Q: 指针链失效？**
A: 游戏更新后指针链可能变化，需要用 CE 重新扫描。
