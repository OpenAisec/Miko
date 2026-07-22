# 内存读写详解 (Memory R/W)

## 目录

1. [基础概念](#基础概念)
2. [Cheat Engine 思路](#cheat-engine-思路)
3. [指针链与基址定位](#指针链与基址定位)
4. [API 读写实现](#api-读写实现)
5. [驱动级读写](#驱动级读写)
6. [数据类型与结构体还原](#数据类型与结构体还原)
7. [实战案例](#实战案例)

---

## 基础概念

游戏运行时，所有数据（血量、坐标、物品、技能CD等）都存储在进程的虚拟内存空间中。内存读写就是**定位这些数据的地址，然后读取或修改它们**。

### 关键术语

| 术语 | 含义 |
|------|------|
| 基址 (Base Address) | 模块加载的起始地址，通常不变 |
| 偏移 (Offset) | 相对于基址的位移量 |
| 指针 (Pointer) | 存储另一个地址的地址 |
| 指针链 (Pointer Chain) | 多级指针的追踪路径 |
| 静态地址 | 由基址+偏移计算得出，相对稳定 |
| 动态地址 | 每次运行都变化的地址 |
| AOB (Array of Bytes) | 字节数组，用于特征码搜索 |

### Windows 内存布局

```
0x00000000 - 0x0000FFFF  NULL 页面（不可访问）
0x00010000 - 0x7FFEFFFF  用户空间（游戏数据在此）
0x7FFF0000 - 0x7FFFFFFF  用户空间顶部
0x80000000 - 0xFFFFFFFF  内核空间（32位）
```

64位进程的用户空间扩展到 `0x00007FFFFFFFFFFF`。

---

## Cheat Engine 思路

CE 的扫描流程是内存修改的标准方法论：

### 精确值扫描

```
1. 知道目标值（如血量 = 100）
2. 首次扫描：搜索值为 100 的地址 → 得到大量结果
3. 回到游戏，让血量变化（如受伤变为 80）
4. 再次扫描：在上次结果中搜索值为 80 的地址 → 结果大幅减少
5. 重复步骤 3-4，直到只剩 1-2 个地址
```

### 模糊扫描

当不知道精确值时：

```
1. 首次扫描：记录所有当前值
2. 回到游戏让值变化
3. 再次扫描：选择"增加了"/"减少了"/"变化了"
4. 逐步缩小范围
```

### 特征码扫描 (AOB Scan)

当需要跨版本兼容时，用特征码代替硬编码地址：

```python
# 特征码示例：找到某个函数的入口
# 原始字节: 55 8B EC 83 E4 F8 83 EC 10 53 56 8B F1
# 通配符:   55 8B EC ?? ?? ?? ?? ?? ?? 53 56 8B F1

# Python 实现 AOB 扫描
def aob_scan(process_handle, pattern, mask):
    """在目标进程中扫描特征码"""
    pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
    # 遍历内存区域
    address = 0
    while address < 0x7FFFFFFFFFFF:
        try:
            mbi = VirtualQueryEx(process_handle, address)
            if mbi.State == MEM_COMMIT and mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE):
                data = ReadProcessMemory(process_handle, address, mbi.RegionSize)
                offset = pattern_match(data, pattern_bytes, mask)
                if offset != -1:
                    return address + offset
        except:
            pass
        address += mbi.RegionSize
    return None
```

---

## 指针链与基址定位

### 为什么需要指针

游戏中的对象通常通过多级指针引用：

```
基址 (静态) → 偏移1 → 偏移2 → 偏移3 → 实际数据
[game.exe+0x1A3F50] → [+0x10] → [+0x28] → [+0x4] → 血量
```

基址是模块加载地址 + 固定偏移，每次运行都不会变。

### 指针追踪步骤

```
1. 找到目标数据的动态地址（如 0x12345678 存储血量）
2. 在 CE 中搜索"哪些地址存储了 0x12345678"
3. 找到一个来自静态模块的指针（如 game.exe 模块内）
4. 记录偏移链：[game.exe+0x1A3F50]+0x10+0x28+0x4
5. 验证：重启游戏后用指针链访问，值是否正确
```

### 多级指针的 C 读写

```c
// 通过指针链读取最终值
uintptr_t read_pointer_chain(HANDLE hProc, uintptr_t base, 
                              const uintptr_t* offsets, int count) {
    uintptr_t addr = base;
    for (int i = 0; i < count; i++) {
        ReadProcessMemory(hProc, (LPCVOID)addr, &addr, sizeof(addr), NULL);
        addr += offsets[i];
    }
    return addr;
}

// 使用示例
uintptr_t base = GetModuleBaseAddress("game.exe") + 0x1A3F50;
uintptr_t offsets[] = {0x10, 0x28, 0x4};
uintptr_t health_addr = read_pointer_chain(hProc, base, offsets, 3);

int health;
ReadProcessMemory(hProc, (LPCVOID)health_addr, &health, sizeof(health), NULL);
printf("血量: %d\n", health);
```

---

## API 读写实现

### Windows API

```c
#include <windows.h>
#include <tlhelp32.h>

// 获取进程 ID
DWORD GetProcessIdByName(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    
    if (Process32First(snapshot, &pe)) {
        do {
            if (strcmp(pe.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
}

// 获取模块基址
uintptr_t GetModuleBaseAddress(DWORD pid, const char* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32 me = { .dwSize = sizeof(me) };
    
    if (Module32First(snapshot, &me)) {
        do {
            if (strcmp(me.szModule, moduleName) == 0) {
                CloseHandle(snapshot);
                return (uintptr_t)me.modBaseAddr;
            }
        } while (Module32Next(snapshot, &me));
    }
    CloseHandle(snapshot);
    return 0;
}

// 读取内存
template<typename T>
T ReadMemory(HANDLE hProc, uintptr_t address) {
    T value;
    ReadProcessMemory(hProc, (LPCVOID)address, &value, sizeof(T), NULL);
    return value;
}

// 写入内存
template<typename T>
BOOL WriteMemory(HANDLE hProc, uintptr_t address, T value) {
    return WriteProcessMemory(hProc, (LPVOID)address, &value, sizeof(T), NULL);
}
```

### Python 实现（pymem）

```python
import pymem
import pymem.process

# 连接进程
pm = pymem.Pymem("game.exe")

# 获取模块基址
module = pymem.process.module_from_name(pm.process_handle, "game.exe")
base_addr = module.lpBaseOfDll

# 读写内存
health_addr = base_addr + 0x1A3F50
health = pm.read_int(health_addr)
print(f"血量: {health}")

# 写入新值
pm.write_int(health_addr, 9999)
```

---

## 驱动级读写

当游戏有反调试保护时，用户态 API 可能被拦截，需要使用驱动级读写。

### 原理

```
用户态: ReadProcessMemory → NtReadVirtualMemory → 内核态
驱动态: 直接调用内核 API (MmCopyVirtualMemory)，绕过用户态检测
```

### 通信方式

```
应用层 ←→ IOCTL ←→ 驱动层
应用层 ←→ 共享内存 ←→ 驱动层
应用层 ←→ MDL ←→ 驱动层
```

详见 `driver-dev.md` 文档。

---

## 数据类型与结构体还原

### 常见游戏数据类型

| 数据 | 类型 | 大小 | 特征 |
|------|------|------|------|
| 血量/蓝量 | int / float | 4字节 | 通常为整数或浮点 |
| 坐标 (x,y,z) | float[3] | 12字节 | 三个连续浮点数 |
| 朝向/角度 | float | 4字节 | 范围 0-360 或 -180~180 |
| 状态标志 | int / byte | 1-4字节 | 位标志或枚举值 |
| 字符串 | char[] / wchar[] | 变长 | 以 null 结尾 |

### 结构体还原方法

```
1. 找到对象基址
2. 逐个偏移读取数据，观察值的变化
3. 根据数据类型和大小推断字段
4. 在 IDA 中对照反编译代码验证
5. 逐步还原完整结构体
```

```c
// 还原的游戏角色结构体示例
struct GamePlayer {
    char pad_0[0x10];           // +0x00  未知填充
    int health;                 // +0x10  当前血量
    int max_health;             // +0x14  最大血量
    float position[3];          // +0x18  坐标 (x, y, z)
    float rotation;             // +0x24  朝向角度
    int team_id;                // +0x28  队伍ID
    char pad_2C[0x4];           // +0x2C  填充
    wchar_t name[16];           // +0x30  角色名
    // ... 更多字段
};
```

---

## 实战案例

### 案例：定位 FPS 游戏的血量

```
目标: 找到玩家血量的内存地址

步骤:
1. CE 附加游戏进程
2. 当前血量 100，首次扫描 Exact Value = 100
3. 回到游戏被打一下，血量变 90
4. CE 再次扫描 Exact Value = 90
5. 重复几次后锁定地址 0x2A3F8000
6. CE "Find out what writes to this address"
7. 被打时显示: mov [esi+10], eax
8. esi = 角色对象基址，+0x10 = 血量偏移
9. 追踪 esi 的来源，找到静态指针链
10. 验证：重启后指针链仍指向正确血量
```

### 案例：坐标修改（瞬移）

```c
// 找到坐标结构后，直接写入目标坐标
float target_pos[3] = {100.0f, 50.0f, 200.0f};
uintptr_t pos_addr = player_base + 0x18;
WriteProcessMemory(hProc, (LPVOID)pos_addr, target_pos, sizeof(target_pos), NULL);
```

### 案例：特征码跨版本兼容

```python
# 不同游戏版本的地址会变，但特征码通常不变
# 找到特征码后，通过相对偏移计算目标地址

def find_pattern_and_read(pm, module, pattern, offsets):
    """扫描特征码并读取指针链"""
    addr = pm.pattern_scan_module(pattern, module)
    if not addr:
        return None
    
    result = addr
    for offset in offsets:
        result = pm.read_longlong(result) + offset
    return result
```
