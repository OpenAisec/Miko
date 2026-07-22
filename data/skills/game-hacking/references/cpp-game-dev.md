# C++ 游戏外挂开发完整指南

## 概述

C++ 是游戏外挂开发的核心语言。相比 Python，C++ 的优势：
- 编译后体积小（几百KB vs 几百MB）
- 运行速度快（原生执行 vs 解释执行）
- 可以内存读写、DLL 注入、Hook（Python 做不到或很慢）
- 编译后无法反编译（保护代码）
- 可以开发内核驱动

## 环境搭建

### Visual Studio 2022+

```
1. 下载 Visual Studio Community（免费）
2. 工作负载勾选"使用 C++ 的桌面开发"
3. 安装 Windows SDK
```

### CMake

```
# Windows: 下载 cmake.org 或 VS 自带
# Linux: sudo apt install cmake
```

### 依赖库

| 库 | 用途 | 安装方式 |
|---|------|---------|
| libmem | 内存读写/Hook | vcpkg install libmem |
| DirectX SDK | 渲染 Hook | Windows SDK 自带 |
| OpenCV | 图像处理 | vcpkg install opencv |
| ONNX Runtime | AI 推理 | 下载预编译包 |
| Interception | 硬件级输入 | github.com/oblitum/Interception |

## 基础知识

### Windows API 常用函数

```cpp
// 进程操作
HANDLE OpenProcess(DWORD access, BOOL inherit, DWORD pid);
BOOL TerminateProcess(HANDLE hProcess, UINT exitCode);
DWORD GetCurrentProcessId();

// 内存操作
LPVOID VirtualAllocEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
BOOL VirtualFreeEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD type);
BOOL ReadProcessMemory(HANDLE h, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T* read);
BOOL WriteProcessMemory(HANDLE h, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T* written);
BOOL VirtualProtectEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD newProt, DWORD* oldProt);

// 线程操作
HANDLE CreateRemoteThread(HANDLE h, LPSECURITY_ATTRIBUTES sa, SIZE_T stack,
                          LPTHREAD_START_ROUTINE func, LPVOID param, DWORD flags, DWORD* tid);
DWORD WaitForSingleObject(HANDLE h, DWORD ms);

// 模块操作
HMODULE GetModuleHandleA(LPCSTR name);
FARPROC GetProcAddress(HMODULE mod, LPCSTR name);
HMODULE LoadLibraryA(LPCSTR name);

// 输入操作
UINT SendInput(UINT count, LPINPUT inputs, int size);
BOOL SetCursorPos(int x, int y);
```

### 内存操作基础

```cpp
#include <Windows.h>
#include <iostream>

// 读取游戏内存
template<typename T>
T ReadMemory(HANDLE hProcess, uintptr_t address) {
    T value;
    ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(T), nullptr);
    return value;
}

// 写入游戏内存
template<typename T>
void WriteMemory(HANDLE hProcess, uintptr_t address, T value) {
    WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(T), nullptr);
}

// 使用示例
int main() {
    DWORD pid = 12345; // 目标进程 ID
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    uintptr_t baseAddr = 0x7FF612340000; // 模块基址
    uintptr_t healthOffset = 0x1A3B5C;   // 生命值偏移

    int health = ReadMemory<int>(hProc, baseAddr + healthOffset);
    std::cout << "Health: " << health << std::endl;

    WriteMemory<int>(hProc, baseAddr + healthOffset, 999);

    CloseHandle(hProc);
    return 0;
}
```

### 指针链追踪

```cpp
// 多级指针追踪
uintptr_t ResolvePointer(HANDLE hProc, uintptr_t base, const std::vector<uintptr_t>& offsets) {
    uintptr_t addr = base;
    for (auto offset : offsets) {
        addr = ReadMemory<uintptr_t>(hProc, addr) + offset;
    }
    return addr;
}

// 使用
uintptr_t playerBase = moduleBase + 0x1A3B5C;
std::vector<uintptr_t> offsets = {0x10, 0x20, 0x30};
uintptr_t healthAddr = ResolvePointer(hProc, playerBase, offsets);
int health = ReadMemory<int>(hProc, healthAddr);
```

## DLL 注入

### CreateRemoteThread 注入器

```cpp
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

DWORD GetProcessId(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = { sizeof(entry) };

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (wcscmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

bool InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    // 分配内存
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, strlen(dllPath) + 1,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { CloseHandle(hProc); return false; }

    // 写入 DLL 路径
    WriteProcessMemory(hProc, remoteMem, dllPath, strlen(dllPath) + 1, NULL);

    // 获取 LoadLibraryA 地址
    FARPROC loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // 创建远程线程
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return hThread != NULL;
}

int main() {
    DWORD pid = GetProcessId(L"game.exe");
    if (pid) {
        InjectDLL(pid, "C:\\cheats\\myhack.dll");
    }
    return 0;
}
```

### 被注入的 DLL 模板

```cpp
#include <Windows.h>
#include <iostream>

// 全局变量
HANDLE g_hThread = NULL;
bool g_running = true;

// 主逻辑线程
DWORD WINAPI MainThread(LPVOID lpParam) {
    // 等待游戏模块加载
    Sleep(2000);

    // 获取模块基址
    uintptr_t baseAddr = (uintptr_t)GetModuleHandleA("game.dll");
    if (!baseAddr) return 0;

    // 获取进程句柄
    HANDLE hProc = GetCurrentProcess();

    while (g_running) {
        // 读取生命值
        uintptr_t healthAddr = baseAddr + 0x1A3B5C;
        int health = 0;
        ReadProcessMemory(hProc, (LPCVOID)healthAddr, &health, sizeof(health), nullptr);

        // 无限生命值
        if (health < 100) {
            int maxHealth = 999;
            WriteProcessMemory(hProc, (LPVOID)healthAddr, &maxHealth, sizeof(maxHealth), nullptr);
        }

        Sleep(10);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            g_hThread = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            g_running = false;
            if (g_hThread) {
                WaitForSingleObject(g_hThread, 3000);
                CloseHandle(g_hThread);
            }
            break;
    }
    return TRUE;
}
```

## Inline Hook

### 基本原理

```
原始函数:
  0x1000: push rbp         ← 5 字节
  0x1001: mov rbp, rsp     ← 3 字节
  0x1004: sub rsp, 0x20    ← 4 字节
  ...

Hook 后:
  0x1000: jmp my_hook      ← 5 字节（替换前 5 字节）
  0x1005: sub rsp, 0x20    ← 原来的代码继续
  ...

my_hook:
  执行自定义逻辑
  执行被覆盖的原指令 (push rbp; mov rbp, rsp)
  jmp 0x1005              ← 跳回原函数继续
```

### MinHook 库（推荐）

```cpp
#include <MinHook.h>

// 原函数指针
typedef int (*fn_get_health)(void* player);
fn_get_health orig_get_health = nullptr;

// Hook 函数
int hooked_get_health(void* player) {
    int health = orig_get_health(player);
    // 修改返回值
    if (health < 100) {
        return 999; // 无限生命
    }
    return health;
}

// 安装 Hook
void InstallHook() {
    MH_Initialize();

    uintptr_t targetAddr = 0x7FF612345678; // 目标函数地址

    MH_CreateHook((LPVOID)targetAddr, &hooked_get_health, (LPVOID*)&orig_get_health);
    MH_EnableHook((LPVOID)targetAddr);
}

// 卸载 Hook
void RemoveHook() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}
```

## DirectX Hook（透视/ESP）

### DXGI Hook（DirectX 11）

```cpp
#include <d3d11.h>
#include <dxgi.h>

// 函数指针
typedef HRESULT(__stdcall* fnPresent)(IDXGISwapChain*, UINT, UINT);
fnPresent oPresent = nullptr;

// Hook 函数
HRESULT __stdcall hkPresent(IDXGISwapChain* swapChain, UINT syncInterval, UINT flags) {
    // 获取设备和上下文
    ID3D11Device* device = nullptr;
    swapChain->GetDevice(__uuidof(ID3D11Device), (void**)&device);

    ID3D11DeviceContext* context = nullptr;
    device->GetImmediateContext(&context);

    // 获取后缓冲
    ID3D11Texture2D* backBuffer = nullptr;
    swapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backBuffer);

    // 在这里绘制 ESP/透视
    // ...

    backBuffer->Release();
    context->Release();
    device->Release();

    // 调用原函数
    return oPresent(swapChain, syncInterval, flags);
}

// 安装 Hook
void InstallDXGIHook() {
    // 创建临时 D3D11 设备获取 vtable
    DXGI_SWAP_CHAIN_DESC desc = {};
    desc.BufferCount = 1;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.OutputWindow = GetDesktopWindow();
    desc.SampleDesc.Count = 1;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    IDXGISwapChain* swapChain = nullptr;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;

    D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION, &desc, &swapChain, &device, nullptr, &context);

    // 获取 vtable
    void** vtable = *(void***)swapChain;
    oPresent = (fnPresent)vtable[8]; // Present 是 vtable 第 8 个函数

    // 安装 Hook
    MH_Initialize();
    MH_CreateHook((LPVOID)oPresent, &hkPresent, (LPVOID*)&oPresent);
    MH_EnableHook((LPVOID)oPresent);

    swapChain->Release();
    device->Release();
    context->Release();
}
```

## SendInput 高级用法

```cpp
#include <Windows.h>

// 鼠标移动（相对）
void MouseMove(int dx, int dy) {
    INPUT input = {};
    input.type = INPUT_MOUSE;
    input.mi.dx = dx;
    input.mi.dy = dy;
    input.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &input, sizeof(INPUT));
}

// 鼠标移动（绝对）
void MouseMoveAbsolute(int x, int y) {
    INPUT input = {};
    input.type = INPUT_MOUSE;
    input.mi.dx = x * (65535 / GetSystemMetrics(SM_CXSCREEN));
    input.mi.dy = y * (65535 / GetSystemMetrics(SM_CYSCREEN));
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    SendInput(1, &input, sizeof(INPUT));
}

// 鼠标点击
void MouseClick() {
    INPUT inputs[2] = {};
    inputs[0].type = INPUT_MOUSE;
    inputs[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    inputs[1].type = INPUT_MOUSE;
    inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
    SendInput(2, inputs, sizeof(INPUT));
}

// 键盘按键
void KeyPress(WORD key) {
    INPUT inputs[2] = {};
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = key;
    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wVk = key;
    inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, inputs, sizeof(INPUT));
}
```

## 进程隐藏

### 修改进程名

```cpp
// 修改 PEB 中的进程路径（对抗进程名扫描）
#include <winternl.h>

void HideProcess() {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    // 修改进程名
    wchar_t fakePath[] = L"C:\\Windows\\System32\\svchost.exe";
    wcscpy(peb->ProcessParameters->ImagePathName.Buffer, fakePath);
}
```

### 服务伪装

```cpp
// 注册为 Windows 服务（看起来像系统服务）
// 需要管理员权限
#include <Winsvc.h>

void InstallAsService() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scm) {
        SC_HANDLE service = CreateServiceA(
            scm,
            "SystemService",           // 服务名
            "System Audio Service",    // 显示名
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            "C:\\Windows\\System32\\svchost.exe",
            NULL, NULL, NULL, NULL, NULL
        );
        if (service) CloseServiceHandle(service);
        CloseServiceHandle(scm);
    }
}
```

## 编译优化

### CMake 配置

```cmake
cmake_minimum_required(VERSION 3.20)
project(MyHack LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

# Release 优化
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG /MT")

# 隐藏控制台窗口
add_link_options(/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup)

# 静态链接（不依赖运行时 DLL）
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_executable(hack WIN32 src/main.cpp)
target_link_libraries(hack PRIVATE d3d11 dxgi user32)
```

### 打包优化

```bash
# 使用 UPX 压缩
upx --best hack.exe

# 结果：从 2MB 压缩到 500KB
```

## 参考资源

- **libmem** — 游戏黑客库 https://github.com/rdbo/libmem
- **MinHook** — 轻量 Hook 库 https://github.com/TsudaKageworking/minhook
- **DX11-BaseHook** — DirectX 11 Hook 示例 https://github.com/rdbo/DX11-BaseHook
- **AssaultCube-Multihack** — 完整外挂示例 https://github.com/rdbo/AssaultCube-Multihack
- **Windows Internals** — 深入理解 Windows 内部原理
