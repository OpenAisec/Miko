# PC 平台特化 (Platform PC)

## DirectX Hook 详解

### DirectX 版本检测

```
游戏常用的 DirectX 版本:
- DirectX 9 (d3d9.dll) — 老游戏、部分网游
- DirectX 11 (d3d11.dll) — 主流游戏
- DirectX 12 (d3d12.dll) — 新游戏

检测方法:
1. 查看游戏目录下的 DLL 文件
2. 用 Process Monitor 监控加载的模块
3. 用 Dependencies 工具查看导入表
```

### DX9 Hook 完整流程

```
1. 创建 Dummy D3D9 设备获取 VMT
2. 记录关键函数地址:
   - EndScene (index 42) — 渲染结束时绘制
   - Reset (index 16) — 设备重置时重建资源
   - Present (index 17) — 画面呈现
3. 用 VMT Hook 替换目标函数
4. 在 Hook 中初始化 ImGui 绘制 ESP/菜单
```

### DX11 Hook

```
DX11 没有直接的 EndScene，需要 Hook:
- IDXGISwapChain::Present — 交换链呈现
- ID3D11DeviceContext::DrawIndexed — 绘制调用

流程:
1. 创建 Dummy DXGI SwapChain
2. 获取 VMT
3. Hook Present 函数
4. 在 Hook 中使用 DX11 绘制
```

## 进程注入技术汇总

### 注入方式选择

```
简单注入 (适合学习):
- CreateRemoteThread + LoadLibrary
- SetWindowsHookEx

高级注入 (绕过检测):
- NtCreateThreadEx
- APC 注入
- 反射注入
- 线程劫持
- 注册表注入 (AppInit_DLLs)
```

### 线程劫持注入

```c
// 挂起目标线程 → 修改 RIP → 恢复执行
void thread_hijack_inject(DWORD pid, DWORD tid, const char* dll_path) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    SuspendThread(hThread);
    
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    
    // 在目标进程分配内存写入 shellcode
    // Shellcode: 调用 LoadLibrary(dll_path) 然后跳回原始 RIP
    // 修改 RIP 指向 shellcode
    
    ResumeThread(hThread);
    CloseHandle(hThread);
}
```

## 反调试对抗

### 常见反调试手段

```
1. IsDebuggerPresent — 检查 PEB.BeingDebugged
2. NtQueryInformationProcess — 查询调试端口
3. CheckRemoteDebuggerPresent — 远程调试检测
4. 时间检测 — 执行时间异常
5. INT 2D — 内核调试断点
6. 硬件断点检测 — 检查 DR 寄存器
7. 代码完整性校验 — CRC/Hash 检查
```

### 绕过方法

```c
// 1. Patch IsDebuggerPresent
// 将 PEB.BeingDebugged 设为 0
PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
peb->BeingDebugged = 0;

// 2. Hook NtQueryInformationProcess
// 返回欺骗值

// 3. 修改时间检测
// Hook GetTickCount / QueryPerformanceCounter

// 4. 清除硬件断点
// 设置 DR0-DR3 为 0，清除 DR7 标志
```

## 常用工具链

```
逆向分析:
- IDA Pro 7.x — 静态分析
- Ghidra — 免费替代
- x64dbg — 动态调试
- WinDbg — 内核调试
- Process Monitor — 文件/注册表/网络监控
- Process Hacker — 进程分析

抓包:
- Wireshark — 底层抓包
- Fiddler — HTTP 代理
- mitmproxy — 可编程代理

开发:
- Visual Studio 2022 — C/C++ IDE
- MinGW — GCC 编译器
- CMake — 构建系统
- vcpkg — 包管理器

Hook 库:
- MinHook — 轻量级 Hook 库
- Microsoft Detours — 微软官方
- PolyHook2 — 功能丰富
- ImGui — GUI 绘制库
```

## 反外挂对抗详解（安全研究）

### 六种调试器检测详解

```c
// 1. PEB.BeingDebugged
// 最基本的检测，修改 PEB 即可绕过
PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
peb->BeingDebugged = 0;

// 2. NtQueryInformationProcess(ProcessDebugPort)
// 查询调试端口，非0表示被调试
DWORD debugPort = 0;
NtQueryInformationProcess(hProc, 7, &debugPort, 4, NULL);
// 绕过: Hook 此函数，将 debugPort 设为 0

// 3. NtQueryInformationProcess(ProcessDebugObjectHandle)
// 查询调试对象句柄，成功表示被调试
HANDLE debugObject = NULL;
NTSTATUS status = NtQueryInformationProcess(hProc, 0x1E, &debugObject, sizeof(debugObject), NULL);
// 绕过: Hook 此函数，返回 STATUS_PORT_NOT_SET

// 4. NtSetInformationThread(ThreadHideFromDebugger)
// 将线程对调试器隐藏，调试器将无法收到此线程的事件
NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);

// 5. 时间检测 (rdtsc / GetTickCount)
// 单步执行会导致时间异常
DWORD start = GetTickCount();
// ... 操作 ...
DWORD elapsed = GetTickCount() - start;
if (elapsed > 100) { /* 可能在被调试 */ }
// 绕过: Hook GetTickCount / QueryPerformanceCounter

// 6. 硬件断点检测
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    /* 有硬件断点，可能在被调试 */
}
// 绕过: 清除 DR 寄存器
```

### 完整性校验对抗

```
游戏的代码完整性校验通常检查:
1. .text 段的 CRC32/SHA256
2. 导入表的哈希值
3. 特定函数的字节序列

对抗方法:
1. 找到校验函数并 Patch（跳过校验）
2. 在校验之后再修改代码
3. 使用硬件断点（不修改代码字节）
4. 使用驱动级 Hook（在更底层拦截）
5. 修改校验结果的存储位置
```

### 驱动保护对抗

```
现代反外挂使用内核驱动保护:

1. 驱动签名验证
   - Windows 10+ 要求驱动有有效签名
   - 测试签名模式: bcdedit /set testsigning on
   - 或使用已泄露/购买的签名证书

2. 回调监控
   - PsSetCreateProcessNotifyCallback — 进程创建
   - PsSetLoadImageNotifyCallback — 模块加载
   - CmRegisterCallback — 注册表操作
   - 反外挂通过回调拦截可疑行为

3. 内核对象保护
   - 保护 EPROCESS 不被修改
   - 保护 SSDT 不被 Hook
   - 监控内核内存修改

对抗研究方向:
- 分析反外挂驱动的保护逻辑
- 研究内核回调的注册和清理
- 理解驱动的通信机制
```
