---
name: game-hacking
category: redteam
description: Authorized game security, reverse engineering, protocol analysis, memory analysis, hook, and automation workflow guide.
---
# 游戏辅助开发全链路指南

## 概述

游戏辅助开发是逆向工程的一个分支，核心是**理解游戏的运行机制，然后在此基础上扩展或修改其行为**。

开发流程遵循「由外到内、由浅入深」的原则：

```
目标分析 → 方案选择 → 环境搭建 → 逆向分析 → 功能实现 → 测试验证
```

## 何时使用

- 开发游戏辅助工具（自瞄、透视、加速等）
- 分析游戏网络协议（抓包、重放、伪造）
- 逆向游戏客户端逻辑（反编译、动态调试）
- 修改游戏内存数据（血量、坐标、物品等）
- 编写游戏自动化脚本（挂机、刷副本、日常任务）
- 学习游戏安全与逆向工程

## 技术栈速查

| 语言/工具 | 用途 |
|-----------|------|
| C/C++ | 内存读写、DLL注入、Hook实现、驱动开发 |
| Python | 协议分析、自动化脚本、Frida脚本、图像识别 |
| x86/x64 汇编 | 代码分析、Shellcode编写、指令级修改 |
| DirectX/OpenGL | 渲染Hook、透视实现、Overlay绘制 |
| Frida | 手游动态插桩、函数Hook |
| IDA Pro / Ghidra | 静态反编译分析 |
| x64dbg / WinDbg | 动态调试跟踪 |
| Wireshark / mitmproxy | 网络协议抓包分析 |
| OpenCV | 图像识别、模板匹配 |

## 开发工作流

### 第一步：目标分析

在动手之前，先弄清楚目标游戏的基本信息：

1. **游戏引擎** — Unity（C#/IL2CPP）、Unreal Engine（C++）、自研引擎
2. **保护机制** — 反调试、加壳、完整性校验、驱动保护
3. **运行平台** — Windows / Android / iOS / 主机
4. **网络架构** — 客户端权威 / 服务器权威 / P2P
5. **内存特征** — 关键数据结构、基址、偏移

```bash
# 快速判断引擎
# Unity: 存在 global-metadata.dat、il2cpp 相关文件
# UE4: 存在 .pak 文件、UE4 编辑器特征
# 自研: 需要更深入的逆向分析

# 查看进程模块
# Windows: 使用 Process Hacker 或 tasklist /m
# Android: adb shell cat /proc/<pid>/maps
```

### 第二步：方案选择

根据需求选择技术路线：

| 需求 | 推荐方案 | 参考文档 |
|------|----------|----------|
| 修改游戏数值 | 内存读写 | `references/memory-rw.md` |
| 分析/伪造网络包 | 协议分析 | `references/protocol-analysis.md` |
| 理解游戏逻辑 | 反编译 | `references/decompilation.md` |
| 拦截/修改函数 | Hook技术 | `references/hook-techniques.md` |
| 隐藏辅助进程 | 驱动开发 | `references/driver-dev.md` |
| 自动执行操作 | 自动化脚本 | `references/automation.md` |

### 第三步：环境搭建

**基础工具链（Windows PC）：**

```
逆向分析:
  - IDA Pro 7.x 或 Ghidra（免费）— 静态分析
  - x64dbg — 动态调试
  - Cheat Engine — 内存扫描
  - Process Hacker — 进程分析

网络分析:
  - Wireshark — 底层抓包
  - mitmproxy — HTTP/HTTPS 代理
  - Fiddler — Web 调试代理

开发工具:
  - Visual Studio — C/C++ 开发
  - Python 3.x + pip — 脚本开发
  - MinGW — GCC 编译器

手游特化:
  - Frida — 动态插桩
  - jadx — APK 反编译
  - Il2CppDumper — Unity IL2CPP 分析
```

**Android 手游环境：**

```bash
# 安装 Frida
pip install frida-tools

# Root 设备 + Magisk + LSPosed
# 安装 Xposed 框架用于 Hook Java 层
```

### 第四步：逆向分析

按照「静态 → 动态 → 协议」的顺序逐步深入：

1. **静态分析** — 用 IDA/Ghidra 打开目标文件，找到关键函数
2. **动态调试** — 用 x64dbg/Frida 跟踪运行时行为
3. **协议分析** — 抓包分析网络通信结构

详见各模块 reference 文档。

### 第五步：功能实现

根据分析结果选择实现方式：

- **内存修改类**：使用 `ReadProcessMemory` / `WriteProcessMemory` 或驱动级读写
- **Hook类**：Inline Hook / IAT Hook / 渲染Hook
- **协议类**：代理转发 / 自定义客户端 / 协议重放
- **自动化类**：图像识别 + 模拟输入

代码模板位于 `scripts/templates/` 目录。

### 第六步：测试验证

- 功能测试：验证功能是否正常工作
- 稳定性测试：长时间运行是否崩溃
- 兼容性测试：不同游戏版本是否兼容
- 检测测试：是否被反外挂系统检测

## 平台特化

根据目标平台选择对应的特化文档：

- **PC 端游** — `references/platform-pc.md`（DirectX Hook、进程注入、驱动开发）
- **手游** — `references/platform-mobile.md`（Frida、Xposed、so注入、il2cpp）
- **主机** — `references/platform-console.md`（存档修改、自制系统）

## 安全与法律提醒

本技能仅用于**合法的安全研究和授权测试**。在使用前确保：

- 仅在自己拥有或获得授权的环境中测试
- 遵守目标游戏的服务条款和当地法律法规
- 不用于破坏他人游戏体验或商业牟利
- 了解相关法律风险（计算机欺诈和滥用法等）

## 学习路径

### 入门阶段（1-2个月）

```
1. Cheat Engine Tutorial — CE 自带的 7 关教程，学习内存扫描基础
2. 基础汇编 — x86 汇编基础（寄存器、指令、栈）
3. 简单游戏逆向 — 用 CE 分析单机游戏的血量、金币
4. Python 基础 — 后续脚本开发需要
```

### 进阶阶段（3-6个月）

```
1. IDA/Ghidra 使用 — 静态分析入门
2. x64dbg 动态调试 — 跟踪函数调用、分析逻辑
3. Hook 技术 — Inline Hook, IAT Hook, DLL 注入
4. 协议分析 — Wireshark 抓包、HTTP/HTTPS 代理
5. 游戏引擎基础 — Unity/UE4 的基本结构
```

### 高级阶段（6个月+）

```
1. 驱动开发 — WDF 框架、内核通信
2. 反外挂对抗 — 分析主流反外挂系统
3. 引擎逆向 — IL2CPP/UE4 深度分析
4. 混淆与反混淆 — 代码保护与绕过
5. 安全研究 — 漏洞挖掘、安全审计
```

## 高级技术详解

### DLL 注入

DLL 注入是将自定义代码加载到目标游戏进程中的核心技术。

**6 种注入方法（从简单到高级）：**

| 方法 | 原理 | 隐蔽性 | 难度 |
|------|------|--------|------|
| **CreateRemoteThread** | 创建远程线程调用 LoadLibrary | 低 | ★★ |
| **SetWindowsHookEx** | 利用系统钩子机制注入 | 中 | ★★ |
| **APC 注入** | 异步过程调用注入 | 中 | ★★★ |
| **进程空洞 (Process Hollowing)** | 挂起进程，替换内存内容 | 高 | ★★★★ |
| **Thread Hijacking** | 劫持已有线程执行注入代码 | 高 | ★★★★ |
| **反射式注入** | DLL 自加载，不经过 LoadLibrary | 最高 | ★★★★★ |

**CreateRemoteThread 基本流程：**
```
1. OpenProcess() — 打开目标进程
2. VirtualAllocEx() — 在目标进程分配内存
3. WriteProcessMemory() — 写入 DLL 路径
4. CreateRemoteThread() — 创建线程调用 LoadLibraryA
5. CloseHandle() — 清理句柄
```

**Interception 驱动注入（硬件级）：**
```
- 内核级输入注入，和真实硬件输入无法区分
- 安装 Interception 驱动后用 Python/C++ 调用
- 游戏无法检测（反外挂只能检测软件级输入）
- 详见: https://github.com/oblitum/Interception
```

### 内存读写（高级）

**libmem 库（推荐）：**
- 跨平台游戏黑客库（C/C++/Rust/Python）
- GitHub 1.2k stars: https://github.com/rdbo/libmem
- 功能：进程查找、内存读写、模式扫描、Hook、汇编/反汇编
- Python 安装：`pip install libmem`

**核心 API：**
```
进程操作: LM_FindProcess, LM_EnumProcesses, LM_IsProcessAlive
模块操作: LM_FindModule, LM_EnumModules, LM_LoadModule
内存操作: LM_ReadMemory, LM_WriteMemory, LM_AllocMemory
扫描操作: LM_PatternScan, LM_SigScan, LM_DeepPointer
Hook操作: LM_HookCode, LM_VmtHook, LM_UnhookCode
```

**指针追踪（Pointer Chain）：**
```
游戏基址 → 第一层偏移 → 第二层偏移 → ... → 最终地址
每次游戏更新基址会变，但指针链结构通常不变
使用 Cheat Engine 的指针扫描功能找到稳定指针链
```

### Hook 技术（高级）

| 类型 | 原理 | 用途 |
|------|------|------|
| **Inline Hook** | 替换函数开头几条指令为跳转 | 拦截任意函数 |
| **IAT Hook** | 修改导入地址表 | 拦截 API 调用 |
| **VMT Hook** | 替换虚函数表指针 | 拦截 C++ 虚函数 |
| **DXGI Hook** | 拦截 DirectX 渲染管线 | 透视、ESP |
| **DirectInput Hook** | 拦截输入 API | 绕过输入捕获 |

**Inline Hook 原理：**
```
原始函数:
  push rbp        ← 保存原指令
  mov rbp, rsp    ← 保存原指令
  ...             ← 原函数逻辑

Hook 后:
  jmp my_hook     ← 替换为跳转到自定义函数
  nop             ← 填充
  ...             ← 原函数逻辑（不执行）

my_hook:
  执行自定义逻辑
  执行被替换的原指令
  jmp 回原函数继续执行
```

### 反外挂对抗

**主流反外挂系统：**
| 系统 | 保护游戏 | 检测方式 |
|------|---------|---------|
| **EasyAntiCheat (EAC)** | Fortnite, Apex | 内核驱动 + 行为分析 |
| **BattlEye** | PUBG, R6S | 内核驱动 + 内存扫描 |
| **VAC** | CS2, Dota2 | 签名扫描 + 行为分析 |
| **Vanguard** | Valorant | 内核驱动（开机启动） |
| **ACE** | 和平精英 | 驱动 + 硬件指纹 + 行为分析 |

**检测手段：**
```
1. 进程扫描 — 检查可疑进程名、窗口标题
2. 内存扫描 — 扫描游戏内存是否被修改
3. 模块扫描 — 检查是否有多余的 DLL 加载
4. API 监控 — 监控 SendInput、ReadProcessMemory 等
5. 行为分析 — 鼠标轨迹、命中率、反应时间统计
6. 驱动检测 — 检查是否有可疑内核驱动
7. 完整性校验 — 检查游戏文件是否被修改
```

**绕过思路：**
```
1. 隐藏进程 — 驱动级进程隐藏（DKOM）
2. 隐藏模块 — 手动映射 DLL（反射式注入）
3. 绕过内存扫描 — 使用硬件断点代替软件修改
4. 绕过 API 监控 — 使用原生 API（ntdll 直接调用）
5. 绕过行为分析 — 加入随机延迟和人类行为模拟
6. 绕过驱动检测 — 使用已签名的合法驱动
7. 绕过完整性校验 — 内存补丁代替文件修改
```

### 逆向工程工具链

| 工具 | 用途 | 平台 |
|------|------|------|
| **Ghidra** | 静态反编译（免费） | 全平台 |
| **IDA Pro** | 静态反编译（商业） | 全平台 |
| **x64dbg** | 动态调试 | Windows |
| **Cheat Engine** | 内存扫描和修改 | Windows |
| **Process Hacker** | 进程分析 | Windows |
| **Frida** | 动态插桩 | 全平台 |
| **Binary Ninja** | 反编译 | 全平台 |
| **GDB** | 动态调试 | Linux |
| **Wireshark** | 网络抓包 | 全平台 |
| **PCILeech** | DMA 硬件读写 | 硬件 |
| **ImGui** | 覆盖层 UI | C++ |

### 最新技术（2025-2026）

**DMA 硬件级内存读写：**
```
原理：通过 PCIe 接口直接读取 GPU/内存，绕过所有软件层检测
工具：PCILeech、FPGA 自定义设备
优势：反外挂完全无法检测（硬件层面）
缺点：需要额外硬件（~$300-500）
```

**虚拟化层攻击（Hypervisor）：**
```
原理：用 VT-x/EPT 在 Ring -1 层拦截游戏，反外挂看不到
技术：EPT Hook、VMExit 拦截、内存隐藏
优势：比内核驱动更隐蔽
缺点：开发难度极高，需要深入理解 CPU 虚拟化
```

**直接系统调用（Direct Syscalls）：**
```
原理：绕过 ntdll.dll，直接调用内核系统调用
技术：手动构造 syscall 指令、SSN 解析、栈伪造
优势：反外挂无法通过 API 监控检测
工具：SysWhispers、HellsGate、RecycledGate
```

**内核回调解除（Callback Unlinking）：**
```
原理：断开反外挂注册的内核回调函数
技术：PsSetCreateProcessNotifyoutine 回调数组解除
      ObRegisterCallbacks 回调解除
      驱动模块隐藏（DKOM）
```

**硬件指纹伪装（HWID Spoof）：**
```
原理：修改机器码让反外挂无法追踪硬件
项目：https://github.com/RejiDev/game-hacking-guidelines/blob/master/techniques/hwid.md
内容：主板序列号、硬盘序列号、MAC地址、CPU ID、GPU ID、TPM
```

**Windows 安全绕过：**
```
VBS (Virtualization Based Security) — 虚拟化安全
HVCI (Hypervisor-protected Code Integrity) — 代码完整性保护
CET (Control-flow Enforcement Technology) — 控制流保护
ETW (Event Tracing for Windows) — 事件追踪
```

### 项目开发工作流（8 阶段）

```
阶段 0: 侦察 — 目标分析、反外挂识别、环境搭建
阶段 1: 静态分析 — 二进制逆向、偏移提取
阶段 2: 动态分析 — 实时内存验证（只读）
阶段 3: 概念验证 — 最小渲染、首次写入
阶段 4: 核心构建 — 完整功能实现
阶段 5: 加固 — 检测规避、发布准备
阶段 6: 测试 — 多会话验证
阶段 7: 维护 — 补丁更新、持续维护
```

### 实战项目参考

**GitHub 开源项目：**
- **libmem** — 游戏黑客库（1.2k stars）https://github.com/rdbo/libmem
- **game-hacking-guidelines** — 最全游戏外挂参考指南 https://github.com/RejiDev/game-hacking-guidelines
- **Cat-Driver** — 内核驱动模板 https://github.com/vic4key/Cat-Driver
- **Windows_Kernel_Based_GAMEHACKING** — 内核驱动游戏外挂教程 https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2
- **FullKernelCheat** — 纯内核驱动外挂示例 https://github.com/DeiVid-12/FullKernelCheat
- **AssaultCube-Multihack** — libmem 实战示例 https://github.com/rdbo/AssaultCube-Multihack
- **DX11-BaseHook** — DirectX 11 Hook 基础 https://github.com/rdbo/DX11-BaseHook
- **X-Inject** — DLL 注入框架 https://github.com/rdbo/x-inject
- **Interception** — 内核级输入驱动 https://github.com/oblitum/Interception

## 推荐资源

详见 reference 文档：

- **开源项目与工具** → `references/resources.md`
- **反外挂系统分析** → `references/anti-cheat.md`
- **游戏引擎逆向** → `references/game-engines.md`
- **DLL 注入** → `references/dll-injection.md`
- **Hook 技术** → `references/hook-techniques.md`
- **libmem 库** → `references/libmem-guide.md`
- **C++ 游戏开发** → `references/cpp-game-dev.md`
