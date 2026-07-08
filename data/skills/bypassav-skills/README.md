# bypassav-skills

Go语言免杀技术套件，结合多种高级技术生成高免杀效果的Shellcode Loader。

## 版本信息

- **版本**: v3.0
- **日期**: 2026-04-24
- **语言**: Go

## 功能概述

本工具套件提供完整的Go语言免杀解决方案，针对主流杀软（360 QVM、火绒、卡巴斯基、Windows Defender）优化，包含以下核心技术：

- **Shellcode预处理**: SGN加密编码
- **多层加密**: DoubleXOR/ADD+XOR/AES/ChaCha20
- **混淆编码**: IPv4/UUID/MAC/IPv6混淆
- **IAT隐藏**: PEB Walk动态API解析
- **内存保护**: VEH异常处理器、睡眠混淆
- **NTDLL脱钩**: 绕过EDR API Hook
- **抗检测**: 沙箱检测、减熵处理、静态伪装

## 目录结构

```
bypassav-skills/
├── SKILL.md                    # 技能入口描述 & 工作流
├── tools/                      # 工具目录
│   ├── sgn2.0.1/               # SGN加密工具
│   │   ├── sgn.exe             # Shellcode编码器
│   │   └── keystone.dll        # 依赖库
│   └── gobuildfuzz/            # Fuzz编译工具
│       └── gobuildfuzz.exe     # 编译优化工具
└── references/                 # 技术参考文件
    ├── execution.md            # Shellcode加载 & 执行方式
    ├── iat_hiding.md           # API哈希 & IAT隐藏
    ├── syscalls.md             # 直接/间接系统调用
    ├── advanced_syscalls.md    # 高级系统调用技术
    ├── ntdll_unhook.md         # NTDLL脱钩技术
    ├── veh_memory_protection.md # VEH内存保护技术
    ├── cold_callback_execution.md # 冷门回调执行方式
    ├── entropy_reduction.md    # 减熵处理技术
    ├── anti_sandbox.md         # 抗沙箱检测技术
    ├── api_hash_randomization.md # API Hash随机化
    ├── process_manipulation.md # 进程操控基础
    ├── advanced_process_manipulation.md # 高级进程操控
    ├── mapping_injection.md    # 映射注入技术
    ├── parameter_spoofing.md   # 参数欺骗技术
    ├── dispatch_table.md       # 分发表API混淆
    ├── memory_evasion.md       # 内存规避技术
    ├── sleep_obfuscation.md    # 睡眠混淆技术
    ├── pe_fluctuation.md       # PE波动技术
    ├── defense_evasion.md      # ETW/AMSI绕过
    └── credential_access.md    # 凭据访问技术
```

## 工具说明

### sgn.exe

Shellcode编码器，用于对原始shellcode进行SGN加密处理。

**使用方法**:
```bash
tools/sgn2.0.1/sgn.exe -a 64 -c 1 -o output_sgn.bin -i input.bin
```

**参数说明**:
- `-a 64`: 64位架构
- `-c 1`: 加密轮数
- `-o output_sgn.bin`: 输出文件
- `-i input.bin`: 输入文件

### gobuildfuzz.exe

模糊编译工具，用于规避敏感参数查杀，自动应用编译优化。

**使用方法**:
```bash
tools/gobuildfuzz/gobuildfuzz.exe -f loader.go
```
以上两款工具请自行添加到对应目录下即可！


## 技术模块

### 执行方式（12种）

**本地执行（5种）**:
1. VirtualAlloc + CreateThread
2. syscall.SyscallN + CreateThread
3. Fiber（纤程执行）
4. APC自注入
5. Callback回调执行

**远程注入（7种）**:
1. 经典注入
2. 映射注入
3. 进程镂空
4. 幽灵注入
5. Herpaderping
6. Early Bird
7. 无线程注入

### 加密方式（4种）

| 加密方式 | 密钥长度 | 特点 |
|----------|----------|------|
| DoubleXOR | 两个16-32字节 | 双重XOR混淆，速度快 |
| ADD+XOR | 三个16-32字节 | 三重混淆，强度更高 |
| AES | 16/24/32字节 | 强加密，使用BCrypt API |
| ChaCha20 | 32字节 | 现代流加密，安全性高 |

### 混淆方式（4种）

| 混淆方式 | 特点 |
|----------|------|
| IPv4 | 每4字节转IPv4地址，最稳定 |
| UUID | 每16字节转UUID字符串 |
| MAC | 每6字节转MAC地址 |
| IPv6 | 每16字节转IPv6地址 |

### 必须高级技术（10项）

| 技术 | 作用 |
|------|------|
| 减熵处理 | 熵值≤6，规避静态检测 |
| 抗沙箱检测 | 规避沙箱分析 |
| API隐藏 | PEB Walk动态获取API |
| VEH内存保护 | 异常处理器保护shellcode内存 |
| NTDLL脱钩 | 绕过EDR API Hook |
| 内存加密保护 | 执行后加密内存 |
| ETW绕过 | 禁用事件追踪 |
| AMSI绕过 | 禁用内存扫描 |
| 睡眠混淆 | 睡眠期间加密shellcode |
| PE波动 | 伪装内存为合法PE |

## 工作流程

```
原始Shellcode → SGN加密 → 二次加密 → IPv4/UUID混淆 → 生成Go Loader → gobuildfuzz编译 → 输出exe
```

### 完整流程

1. **SGN预处理**: 使用sgn.exe加密shellcode
2. **二次加密**: DoubleXOR/ADD+XOR/AES/ChaCha20
3. **混淆编码**: IPv4/UUID/MAC/IPv6混淆
4. **生成Loader**: 生成Go源码，包含解密逻辑和执行方式
5. **初始化模块**: `go mod init loader && go mod tidy`
6. **编译**: 使用gobuildfuzz编译生成exe

## 推荐技术组合

### 360安全卫士
```
VEH内存保护 + 减熵处理 + 抗沙箱检测
API Hash随机化 + 冷门回调执行
SGN预处理 + 多层加密
```

### Windows Defender
```
NTDLL脱钩 + VEH内存保护
直接syscall + Hell's Gate
睡眠混淆 + 堆加密
```

### 卡巴斯基
```
NTDLL脱钩 + VEH内存保护
API Hash随机化 + 冷门回调执行
减熵处理 + 抗沙箱检测
```

### 火绒
```
冷门回调执行 + API Hash随机化
VEH内存保护 + IAT隐藏
多层加密 + IPv4混淆
```

## 使用指南

### 1. 准备工作

- 准备原始shellcode文件（.bin格式，64位）
- 确保已安装Go环境
- 确保工具路径正确

### 2. 生成Loader

向AI描述需求，例如：
- "使用VirtualAlloc+CreateThread方式生成loader"
- "组合syscall和ETW绕过技术生成loader"
- "使用Early Bird注入方式生成loader"

### 3. 编译

```bash
# 初始化Go模块
go mod init loader
go mod tidy

# 使用gobuildfuzz编译
tools/gobuildfuzz/gobuildfuzz.exe -f loader.go
```

## 注意事项

1. **合法性**: 仅用于授权安全测试、CTF比赛和渗透评估
2. **SGN处理**: SGN加密后的shellcode运行时无需解密SGN层
3. **Go模块**: 编译前必须执行`go mod init`和`go mod tidy`
4. **编译方式**: 必须使用gobuildfuzz编译
5. **时效性**: 免杀技术会随杀软更新失效，需定期更新策略
6. **ETW/AMSI**: 必须在main函数第一行执行绕过

## 免杀效果参考

| 组合类型 | 360 | Defender | 卡巴斯基 | 火绒 |
|----------|-----|----------|----------|------|
| 基础组合 | 中 | 低 | 低 | 中 |
| +ETW/AMSI绕过 | 高 | 高 | 中 | 高 |
| +Hell's Gate | 高 | 高 | 高 | 高 |
| +睡眠混淆+PE波动 | 高 | 高 | 高 | 高 |
| 完整高免杀组合 | 极高 | 极高 | 极高 | 极高 |

## 参考资料

详细技术实现请参考 `references/` 目录下的技术文档。

## License

仅供安全研究和授权测试使用。
