# DLL 注入技术详解

## 概述

DLL 注入是将自定义代码加载到目标进程地址空间中的技术。在游戏外挂中，DLL 注入用于：
- 在游戏进程内部执行代码
- Hook 游戏函数
- 读写游戏内存
- 绘制覆盖层（ESP/透视）

## 注入方法

### 1. CreateRemoteThread（最经典）

**原理：** 在目标进程中创建一个新线程，调用 `LoadLibraryA` 加载 DLL。

**步骤：**
```
1. OpenProcess(PROCESS_ALL_ACCESS, pid) → 获取进程句柄
2. VirtualAllocEx(hProcess, size) → 在目标进程分配内存
3. WriteProcessMemory(hProcess, dll_path) → 写入 DLL 路径
4. GetProcAddress("LoadLibraryA") → 获取函数地址
5. CreateRemoteThread(hProcess, LoadLibraryA, dll_path) → 创建线程
6. WaitForSingleObject(hThread) → 等待加载完成
7. VirtualFreeEx + CloseHandle → 清理
```

**代码模板（C）：**
```c
#include <Windows.h>

BOOL InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;

    // 分配内存
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                       MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) { CloseHandle(hProcess); return FALSE; }

    // 写入 DLL 路径
    WriteProcessMemory(hProcess, remoteMem, dllPath, strlen(dllPath) + 1, NULL);

    // 获取 LoadLibraryA 地址
    FARPROC loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    // 创建远程线程
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}
```

**检测风险：** 高。反外挂监控 `CreateRemoteThread` 和 `WriteProcessMemory` 调用。

### 2. SetWindowsHookEx

**原理：** 利用系统钩子机制，当目标进程触发事件时自动加载 DLL。

**代码模板：**
```c
// 在 DLL 中导出钩子函数
__declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // 注入后的逻辑
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// 注入端
HHOOK hHook = SetWindowsHookEx(WH_GETMESSAGE, HookProc, hDll, targetThreadId);
// 触发消息让目标进程加载 DLL
PostThreadMessage(targetThreadId, WM_NULL, 0, 0);
```

**检测风险：** 中。反外挂监控钩子安装。

### 3. APC 注入

**原理：** 利用异步过程调用（APC）在目标线程的上下文中执行代码。

**代码模板：**
```c
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTid);
if (hThread) {
    QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)remoteMem);
    CloseHandle(hThread);
}
```

**检测风险：** 中。比 CreateRemoteThread 更隐蔽。

### 4. 进程空洞（Process Hollowing）

**原理：** 创建挂起的合法进程，替换其内存内容为恶意代码。

**步骤：**
```
1. CreateProcess(target.exe, CREATE_SUSPENDED) → 创建挂起进程
2. NtUnmapViewOfSection → 取消映射原始代码
3. VirtualAllocEx → 分配新内存
4. WriteProcessMemory → 写入恶意代码
5. SetThreadContext → 修改入口点
6. ResumeThread → 恢复执行
```

**检测风险：** 高。但隐蔽性好，进程看起来是合法程序。

### 5. 反射式注入（Reflective Injection）

**原理：** DLL 自己实现 `LoadLibrary` 逻辑，不经过系统 API。

**特点：**
- DLL 不会出现在模块列表中
- 不经过 `LoadLibrary`，不触发 DLL 加载监控
- 需要自定义 PE 加载器

**检测风险：** 最低。最隐蔽的注入方式。

## Interception 驱动注入（硬件级）

**原理：** 使用 Interception 内核驱动，在驱动层注入鼠标/键盘输入。

**安装：**
```bash
# 下载 Interception
# https://github.com/oblitum/Interception
# 以管理员运行 install-interception.exe
# 重启电脑
```

**Python 使用：**
```python
import interception
interception.auto_capture_devices()

# 移动鼠标（内核级，游戏无法检测）
interception.move_relative(dx, dy)

# 监听鼠标事件
while True:
    stroke = interception.get_mouse()
    if stroke:
        print(f"Mouse: x={stroke.x}, y={stroke.y}, state={stroke.state}")
```

**优势：**
- 输入来自驱动层，和真实硬件输入无法区分
- 反外挂只能检测软件级输入（SendInput、mouse_event）
- Interception 是合法的输入驱动，不被标记为恶意

## 工具推荐

| 工具 | 用途 |
|------|------|
| **Process Hacker** | 查看进程模块、线程、内存 |
| **x64dbg** | 动态调试注入过程 |
| **API Monitor** | 监控 API 调用 |
| **libmem** | 自动化注入框架 |
| **X-Inject** | 开源 DLL 注入器 |

## 参考项目

- **libmem** — 游戏黑客库 https://github.com/rdbo/libmem
- **X-Inject** — DLL 注入框架 https://github.com/rdbo/x-inject
- **Interception** — 内核输入驱动 https://github.com/oblitum/Interception
