# 反外挂系统分析 (Anti-Cheat Systems)

## 目录

1. [反外挂概述](#反外挂概述)
2. [BattlEye](#battleye)
3. [Easy Anti-Cheat (EAC)](#easy-anti-cheat-eac)
4. [Vanguard](#vanguard)
5. [VAC (Valve Anti-Cheat)](#vac-valve-anti-cheat)
6. [nProtect GameGuard](#nprotect-gameguard)
7. [腾讯 ACE / TP](#腾讯-ace--tp)
8. [反外挂通用检测原理](#反外挂通用检测原理)
9. [对抗思路（安全研究）](#对抗思路安全研究)

---

## 反外挂概述

反外挂系统是游戏安全的第一道防线，主要分为三个层次：

```
┌─────────────────────────────────────────┐
│          云端检测 (Cloud-side)           │
│   - 行为分析、机器学习、举报系统          │
├─────────────────────────────────────────┤
│          用户态检测 (User-mode)          │
│   - 进程扫描、内存校验、API Hook 检测     │
├─────────────────────────────────────────┤
│          内核态检测 (Kernel-mode)        │
│   - 驱动保护、回调监控、完整性校验        │
└─────────────────────────────────────────┘
```

### 检测分类

| 检测类型 | 方法 | 示例 |
|----------|------|------|
| 签名检测 | 扫描已知外挂的特征码 | VAC, ACE |
| 内存完整性 | 校验游戏内存是否被修改 | BattlEye, EAC |
| 进程检测 | 扫描可疑进程/模块 | GameGuard, TP |
| 驱动检测 | 检测未签名/可疑驱动 | Vanguard, ACE |
| 调试器检测 | 检测调试器存在 | 所有反外挂 |
| 行为分析 | 分析玩家操作模式 | 云端系统 |
| Hook 检测 | 检测 API Hook | EAC, BattlEye |
| 代码完整性 | 校验代码段 CRC/Hash | VAC, ACE |

---

## BattlEye

### 基本信息

- **开发商**: BattlEye Innovations (德国)
- **使用游戏**: PUBG, Arma 3, Rainbow Six Siege, DayZ, Escape from Tarkov
- **架构**: 内核驱动 + 用户态服务

### 检测机制

```
1. 内核驱动 (BEDaisy.sys):
   - 拦截内核回调（进程创建/模块加载）
   - 检测可疑驱动加载
   - 监控内核对象修改
   - 扫描隐藏进程/模块

2. 用户态服务 (BEService.exe):
   - 扫描游戏进程内存
   - 检测 DLL 注入
   - 检测调试器（硬件断点、调试端口）
   - 扫描已知外挂特征码
   - 校验游戏文件完整性

3. 游戏内嵌:
   - Lua 脚本检测
   - 游戏逻辑校验
   - 截图功能（用于举报分析）
```

### 关键检测点

- `NtQueryInformationProcess` — 调试端口检测
- `NtQuerySystemInformation` — 进程/模块枚举
- 驱动对象遍历 — 检测可疑驱动
- 内存页属性扫描 — 检测 RWX 页
- 导入表完整性 — 检测 IAT Hook

---

## Easy Anti-Cheat (EAC)

### 基本信息

- **开发商**: Epic Games
- **使用游戏**: Fortnite, Apex Legends, Rust, Fall Guys
- **架构**: 内核驱动 + 用户态 + 云端

### 检测机制

```
1. 内核驱动 (EasyAntiCheat.sys):
   - 进程/线程创建回调
   - 模块加载回调
   - 注册表过滤
   - 文件系统过滤
   - 网络过滤

2. 用户态 (EasyAntiCheat.exe):
   - 完整性校验（游戏文件 + 内存）
   - 调试器检测（多种方法）
   - 注入检测（DLL/SO 注入）
   - 模拟器检测
   - 沙箱检测

3. 云端分析:
   - 行为模式分析
   - 统计异常检测
   - 机器学习模型
```

### 特殊检测

- Hyperion 保护引擎（EAC 的核心组件）
- 基于硬件的检测（TPM, UEFI 安全启动）
- 运行时代码混淆
- 反调试器的多层嵌套

---

## Vanguard

### 基本信息

- **开发商**: Riot Games
- **使用游戏**: Valorant, League of Legends (部分地区)
- **架构**: 内核驱动（开机启动）

### 检测机制

```
Vanguard 的独特之处: 开机即启动内核驱动

1. 内核驱动 (vgk.sys):
   - 系统启动时加载（早于游戏）
   - 拦截所有驱动加载（黑名单机制）
   - 监控调试器注册
   - 检测内核调试
   - 阻止可疑进程运行

2. 用户态:
   - 游戏运行时的内存保护
   - 完整性校验
   - 行为监控

3. 云端:
   - 硬件 ID 封禁
   - 行为分析
   - 机器学习
```

### 争议点

- 开机启动引发隐私争议
- 可能阻止合法软件运行
- 内核级权限过高

---

## VAC (Valve Anti-Cheat)

### 基本信息

- **开发商**: Valve
- **使用游戏**: CS2, Dota 2, TF2, 所有 Steam 游戏
- **架构**: 纯用户态 + 云端

### 检测机制

```
VAC 相对"温和"，不使用内核驱动:

1. 签名检测:
   - 维护已知外挂的签名数据库
   - 扫描游戏进程内存中的特征码
   - 定期更新签名库

2. 代码完整性:
   - 校验游戏模块的完整性
   - 检测代码段修改

3. Steam 信任系统 (Trust Factor):
   - 基于玩家行为的信任评分
   - 低信任玩家匹配在一起
   - 不直接封禁，而是隔离

4. Overwatch 系统:
   - 玩家举报 → 高信誉玩家审核
   - 人工判定是否作弊
```

### 特点

- 延迟封禁（收集证据后批量封禁）
- 不实时阻止外挂运行
- 依赖云端分析

---

## nProtect GameGuard

### 基本信息

- **开发商**: INCA Internet (韩国)
- **使用游戏**: 韩国网游 (MapleStory, Black Desert, Lineage)
- **架构**: 内核驱动

### 检测机制

```
1. 内核驱动:
   - 拦截系统调用
   - 检测调试器
   - 阻止内存修改工具
   - 进程保护

2. 用户态:
   - 扫描已知外挂
   - 检测模拟器
   - 完整性校验
```

---

## 腾讯 ACE / TP

### 基本信息

- **开发商**: 腾讯安全
- **使用游戏**: 和平精英, 英雄联盟, 穿越火线, DNF 等
- **架构**: 内核驱动 + 用户态 + 云端

### 检测机制

```
1. 内核驱动 (TesMon.sys / ACE-*):
   - 进程/线程监控
   - 模块加载拦截
   - 内存保护
   - 驱动黑名单
   - 注册表/文件过滤

2. 用户态:
   - 特征码扫描
   - 调试器检测（多种方法）
   - 注入检测
   - 模拟器检测
   - 完整性校验
   - 行为分析

3. 云端:
   - 机器学习模型
   - 行为画像
   - 硬件指纹
   - 实时分析
```

### 特殊机制

- 游戏内举报 + AI 审核
- 视频回放分析
- 硬件封禁（主板/硬盘/网卡）
- 手游端: 设备指纹 + 行为分析

---

## 反外挂通用检测原理

### 调试器检测

```c
// 1. IsDebuggerPresent
if (IsDebuggerPresent()) { /* 被调试 */ }

// 2. PEB.BeingDebugged
PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
if (peb->BeingDebugged) { /* 被调试 */ }

// 3. NtQueryInformationProcess
DWORD debugPort = 0;
NtQueryInformationProcess(hProc, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) { /* 被调试 */ }

// 4. 时间检测
DWORD start = GetTickCount();
// ... 一些操作 ...
DWORD elapsed = GetTickCount() - start;
if (elapsed > threshold) { /* 单步调试导致时间异常 */ }

// 5. 硬件断点检测
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) { /* 有硬件断点 */ }

// 6. INT 2D
__try {
    __int2d();
} __except (EXCEPTION_EXECUTE_HANDLER) {
    // 正常情况下会触发异常
    // 如果被调试器捕获，说明在被调试
}
```

### 注入检测

```
1. 模块枚举 — 遍历加载的 DLL，检测不在白名单中的
2. 内存扫描 — 搜索可疑的 JMP/CALL 指令（Inline Hook 特征）
3. 导入表校验 — 检查 IAT 是否被修改
4. 代码段校验 — CRC/Hash 检查代码段完整性
5. 线程起始地址 — 检测非正常起始地址的线程
```

### 驱动检测

```
1. 驱动对象枚举 — 遍历内核驱动链表
2. 驱动签名验证 — 检查驱动是否有有效签名
3. 回调函数检测 — 检查系统回调是否被注册
4. SSDT 检测 — 检查系统服务描述表是否被 Hook
5. 内核内存扫描 — 搜索内核空间的可疑代码
```

---

## 对抗思路（安全研究）

> 以下内容仅用于**授权的安全研究和防御技术学习**。

### 分层对抗模型

```
检测层级          对抗方法                    难度
──────────────────────────────────────────────
签名检测      ←  代码混淆/加密/变异          低
内存完整性    ←  驱动级读写/硬件断点          中
进程检测      ←  进程隐藏/模块隐藏           中
驱动检测      ←  自签名驱动/驱动漏洞利用      高
行为分析      ←  人类化操作/随机延迟          中
云端检测      ←  难以对抗（数据在服务器端）    极高
```

### 研究方向

1. **反调试绕过研究** — ScyllaHide, HyperHide 等工具的原理
2. **内核保护分析** — 分析反外挂驱动的保护机制
3. **完整性校验绕过** — 理解 CRC/Hash 校验的实现和绕过
4. **行为模拟** — 如何让自动化操作看起来像人类
5. **检测原理分析** — 理解反外挂的检测逻辑以改进防御

### 学习建议

```
入门: 分析 VAC（纯用户态，相对简单）
进阶: 分析 GameGuard（内核驱动，韩国游戏常用）
高级: 分析 EAC/BattlEye（多层保护）
挑战: 分析 Vanguard（开机启动，最高安全级别）
```
