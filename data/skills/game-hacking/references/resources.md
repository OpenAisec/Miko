# 开源项目与学习资源 (Resources)

> 数据来源: GitHub API 实时搜索 + dsasmblr/game-hacking 资源库 (5471 stars) + ridpath/gamehacking-cheatsheet (61 stars, 8831行速查表)

## 目录

1. [核心开源项目](#核心开源项目)
2. [开发库与框架](#开发库与框架)
3. [学习资源](#学习资源)
4. [社区与论坛](#社区与论坛)
5. [练习环境](#练习环境)
6. [工具链安装速查](#工具链安装速查)

---

## 核心开源项目

### 逆向分析工具 (GitHub Stars 排序)

| 项目 | Stars | 用途 | 地址 |
|------|-------|------|------|
| Ghidra | 69k+ | NSA 开源逆向框架，反编译+脚本 | github.com/NationalSecurityAgency/ghidra |
| ImHex | 53k+ | 面向逆向工程师的十六进制编辑器 | github.com/WerWolv/ImHex |
| x64dbg | 48k+ | Windows x86/x64 动态调试器 | github.com/x64dbg/x64dbg |
| radare2 | 23k+ | UNIX 逆向框架（命令行） | github.com/radareorg/radare2 |
| Cutter | 18k+ | Rizin 的 GUI 前端 | github.com/rizinorg/cutter |
| Bytecode Viewer | 15k+ | Java/APK 逆向套件 | github.com/Konloch/bytecode-viewer |
| Binary Ninja | — | 现代逆向平台（商业+免费版） | binary.ninja |
| Hopper | — | macOS/Linux 反汇编器 | hopperapp.com |
| IDA Pro | — | 行业标准反编译器（商业） | hex-rays.com |

### 内存分析与调试工具

| 项目 | Stars | 用途 | 地址 |
|------|-------|------|------|
| Cheat Engine | — | 内存扫描/修改/调试，游戏逆向标配 | github.com/cheat-engine/cheat-engine |
| Squalr | — | C# 游戏 hacking 工具，功能对标 CE | github.com/Squalr/Squalr |
| PINCE | — | Linux/macOS 的 CE 替代品 (GDB 前端) | github.com/korcankaraokcu/PINCE |
| Process Hacker | — | 进程分析与管理 | github.com/processhacker/processhacker |
| ReClass.NET | — | .NET 内存结构重建工具 | github.com/KN4CK3R/ReClass.NET |
| ReClassEx | — | C++ 内存结构重建 | github.com/dude719/ReClassEx |
| MhsX | 109 | 内存 hacking 软件 | github.com/L-Spiro/MhsX |
| MemRE | 62 | 支持 UE 的内存编辑器 | github.com/Do0ks/MemRE |

### 游戏特化工具

| 项目 | Stars | 用途 | 地址 |
|------|-------|------|------|
| Il2CppDumper | 9k+ | Unity IL2CPP 元数据提取 | github.com/Perfare/Il2CppDumper |
| Zygisk-Il2CppDumper | 3.1k | Zygisk 运行时 dump il2cpp | github.com/Perfare/Zygisk-Il2CppDumper |
| dnSpy | — | .NET 反编译器/调试器（Unity Mono） | github.com/dnSpy/dnSpy |
| ILSpy | — | .NET 程序集浏览器和反编译器 | github.com/icsharpcode/ILSpy |
| AssetStudio | — | Unity 资源提取工具 | github.com/Perfare/AssetStudio |
| UABE | — | Unity .assets 和 AssetBundle 编辑器 | github.com/DerPopo/UABE |
| Frida-il2cpp-bridge | — | Frida 的 IL2CPP bridge | github.com/nickelorg/frida-il2cpp-bridge |
| Il2CppMemoryDumper | 199 | 从进程内存 dump Il2Cpp | github.com/MlgmXyysd/Il2CppMemoryDumper |
| frida-il2cppDumper | 249 | Riru Il2cppDumper 加强版（支持易盾） | github.com/IIIImmmyyy/frida-il2cppDumper |
| UnityResolve.hpp | 443 | Unity C++ 接口 (Mono/il2cpp) | github.com/issuimo/UnityResolve.hpp |

### 图形调试工具

| 项目 | 用途 | 地址 |
|------|------|------|
| RenderDoc | Vulkan/DX11/DX12/OpenGL 图形调试 | renderdoc.org |
| PIX | DirectX 性能调优和调试 | blogs.msdn.microsoft.com/pix |
| Ninja Ripper | 从运行中的游戏提取 3D 模型/贴图 | gamebanana.com/tools/5638 |
| ReShade | 通用后处理注入器（DX/OpenGL） | github.com/crosire/reshade |

### 网络分析工具

| 项目 | 用途 | 地址 |
|------|------|------|
| Wireshark | 网络协议分析器 | wireshark.org |
| Fiddler | Web 调试代理 | telerik.com/fiddler |
| mitmproxy | 可编程 HTTP/HTTPS 代理 | mitmproxy.org |

### 进程/文件分析工具

| 项目 | 用途 | 地址 |
|------|------|------|
| Process Monitor | 文件/注册表/进程实时监控 | docs.microsoft.com/sysinternals |
| Process Explorer | 进程句柄和 DLL 查看 | docs.microsoft.com/sysinternals |
| Exeinfo PE | 壳/压缩检测工具 | exeinfo.atwebpages.com |
| CFF Explorer | PE 文件检查器 | ntcore.com |
| Binwalk | 固件/二进制文件分析 | github.com/ReFirmLabs/binwalk |
| YARA | 二进制模式匹配引擎 | github.com/virustotal/yara |

### DLL 注入器

| 项目 | 用途 | 地址 |
|------|------|------|
| Xenos | Windows DLL 注入器 (基于 Blackbone) | github.com/DarthTon/Xenos |
| Blackbone | Windows x86/x64 hacking 库 | github.com/DarthTon/Blackbone |
| Bleak | C# Windows DLL 注入库 | github.com/Akaion/Bleak |

---

## 开发库与框架

### Hook 库

| 库名 | 语言 | Stars | 特点 |
|------|------|-------|------|
| MinHook | C | — | 轻量级 x86/x64 API Hook，最常用 |
| Microsoft Detours | C/C++ | — | 微软官方，32位免费 |
| PolyHook | C++ | — | 抽象 C++11 接口，多种 Hook 方式 |
| EasyHook | C# | — | .NET Hook 库 |
| CoreHook | C# | — | .NET Core Hook 库 |
| mhook | C | — | Windows API Hook 库 |
| Deviare In-Process | C++ | — | Detours 的免费替代品 |

### 内存编辑库

| 库名 | 语言 | 用途 |
|------|------|------|
| memory.dll | C# | PC 游戏 trainer 开发 |
| MemorySharp | C# | 远程进程内存编辑 |
| Jupiter | C# | Windows 内存编辑库 |
| pymem | Python | Windows 进程内存读写 |
| hacklib | C++ | 模式扫描+Hook+绘制 |

### 反调试学习

| 项目 | 用途 | 地址 |
|------|------|------|
| AntiDBG | Windows 反调试技术集合（C） | github.com/cetfor/AntiDBG |
| al-khaser | VM/调试器/沙箱检测 PoC | github.com/LordNoteworthy/al-khaser |
| makin | 揭示游戏使用的调试器检测技术 | github.com/secrary/makin |

### 汇编/反汇编引擎

| 库名 | 用途 |
|------|------|
| Keystone | 汇编引擎（机器码 → 汇编） |
| Capstone | 反汇编引擎（汇编 → 机器码） |
| Unicorn | CPU 模拟器（执行任意机器码） |
| Zydis | 快速 x86/x64 反汇编库 |
| angr | Python 二进制分析框架（符号执行等） |

### Python 库

| 库名 | 用途 | 安装 |
|------|------|------|
| pymem | Windows 进程内存读写 | `pip install pymem` |
| frida | Frida Python 绑定 | `pip install frida-tools` |
| capstone | 反汇编 | `pip install capstone` |
| keystone-engine | 汇编 | `pip install keystone-engine` |
| unicorn | CPU 模拟 | `pip install unicorn` |
| pefile | PE 文件解析 | `pip install pefile` |
| lief | 多格式二进制解析 | `pip install lief` |
| UnityPy | Unity 资源解析 | `pip install UnityPy` |

### 其他实用工具

| 项目 | 用途 |
|------|------|
| Kaitai Struct | 二进制格式声明式解析语言 |
| CyberChef | 在线编码/加密/解密工具 |
| QuickBMS | 游戏资源文件解析/提取 |
| de4dot | .NET 反混淆/脱壳 |
| xortool | XOR 密钥分析工具 |
| Noriben | Process Monitor 自动化分析脚本 |

---

## 学习资源

### 书籍

| 书名 | 作者 | 适合阶段 |
|------|------|----------|
| Game Hacking: Developing Autonomous Bots for Online Games | Nick Cano | 入门-进阶 |
| 《游戏安全: 网络游戏外挂技术分析与防御》 | 吕志强 | 入门-进阶 |
| 《逆向工程核心原理》 | 李承远 | 入门-进阶 |
| 《加密与解密》(看雪) | 段钢 | 进阶 |
| Exploiting Online Games: Cheating Massively Distributed Systems | Greg Hoglund | 进阶 |
| 《Android 软件安全权威指南》 | 丰生强 | 手游进阶 |
| Practical Reverse Engineering | Bruce Dang | 高级 |
| Attacking Network Protocols | James Forshaw | 协议分析 |
| Practical Packet Analysis (3rd Ed.) | Chris Sanders | 抓包分析 |

### 在线教程与课程

| 资源 | 内容 | 链接 |
|------|------|------|
| Game Hacking Academy | CE 和游戏逆向入门 | gamehacking.academy |
| begin.re | 逆向工程入门教程（扫雷逆向） | begin.re |
| Guided Hacking | 游戏黑客教程系列 | guidedhacking.com |
| OpenSecurityTraining | 免费安全培训课程 | opensecuritytraining.info |
| 看雪学院 | 国内安全培训 | kx.pediy.com |
| 吾爱破解培训 | 逆向基础培训 | 52pojie.cn |
| Introduction to Lua using Cheat Engine | CE Lua 脚本入门 | dsasmblr.com |
| Reverse Engineering for Beginners | RE 入门工作坊 | begin.re |

### 博客与文章

| 标题 | 内容 |
|------|------|
| Hack.lu 2017: Reverse Engineering a MMORPG | Pwn Adventure 3 逆向工作坊 |
| Hooking LuaJIT | 通过 Hook 脚本引擎加速逆向 |
| Reversing LoL Client | 用 API Monitor 逆向英雄联盟客户端 |
| Reverse Engineering Animal Crossing's Developer Mode | 逆向动物森友会开发者模式 |
| Reverse Engineering the Rendering of The Witcher 3 | 巫师3 渲染管线逆向 |
| GTA V Graphics Study | GTA V 图形技术深度分析 |
| Game Hacking: Hammerwatch Invincibility | dnSpy hack Mono 游戏案例 |
| Riot's Approach to Anti-Cheat | Riot 反外挂方法论 |

### 视频教程

| 频道/系列 | 内容 |
|-----------|------|
| Guided Hacking (YouTube) | 游戏黑客系列教程 |
| Cheat Engine Tutorial (YouTube) | CE 内存/脚本/反汇编深度教程 |
| Introduction to IDA Pro (YouTube) | IDA Pro 入门 |
| DEF CON 25: Manfred | 专业在线游戏黑客演示 |
| GDC 2018: Valve Deep Learning Anti-Cheat | VACnet 深度学习反外挂 |
| Sega Saturn Cracked | 世嘉土星 20 年保护破解 |

---

## 社区与论坛

| 社区 | 语言 | 内容 | 链接 |
|------|------|------|------|
| UnknownCheats | 英文 | 最大的游戏逆向社区 | unknowncheats.me |
| Guided Hacking | 英文 | 游戏黑客教程+论坛 | guidedhacking.com |
| FearLess Cheat Engine | 英文 | CE cheat table 和教程 | fearlessrevolution.com |
| 吾爱破解 (52pojie) | 中文 | 国内最大逆向社区 | 52pojie.cn |
| 看雪论坛 (pediy) | 中文 | 安全研究论坛 | pediy.com |
| r/REGames | 英文 | Reddit 游戏逆向子版 | reddit.com/r/REGames |
| r/ReverseEngineering | 英文 | Reddit 逆向工程子版 | reddit.com/r/ReverseEngineering |
| RE StackExchange | 英文 | 逆向工程问答 | reverseengineering.stackexchange.com |
| ElitePVPers | 英文 | MMO hacks/bots/cheats | elitepvpers.com |
| OwnedCore | 英文 | MMO 社区 | ownedcore.com |

---

## 练习环境

### 安全游戏（专为逆向设计）

| 游戏 | 内容 | 链接 |
|------|------|------|
| Pwn Adventure 3 | 第一人称 MMORPG，专为 hacking 设计 | pwnadventure.com |
| Pwn Adventure Z | NES 僵尸生存游戏，专为 hacking 设计 | github.com/Vector35/PwnAdventureZ |
| Pwn Adventure 2 | Unity 3D MMOFPS，需修改客户端完成任务 | ghostintheshellcode.com |
| AssaultCube | 开源多人 FPS | assault.cubers.net |
| Xonotic | 开源竞技场 FPS | xonotic.org |
| Minetest | 开源 Minecraft 克隆 | minetest.net |

### CTF 平台

| 平台 | 内容 | 链接 |
|------|------|------|
| pwnable.kr | Linux Pwn 入门 | pwnable.kr |
| pwnable.tw | 台湾 Pwn 进阶 | pwnable.tw |
| root-me.org | 综合安全挑战 | root-me.org |
| crackmes.one | 逆向工程挑战 | crackmes.one |
| reversing.kr | 逆向工程挑战 | reversing.kr |
| Hack The Box | 综合渗透 | hackthebox.com |

### 实用工具

| 工具 | 用途 |
|------|------|
| Cheat Engine Tutorial | CE 自带教程（7关），入门首选 |
| Compiler Explorer | 在线查看 C/C++ 编译后的汇编代码 |
| Game Hacking Book Code | 《Game Hacking》一书的配套代码 |

---

## 工具链安装速查

### Windows 逆向环境

```powershell
# Python
winget install Python.Python.3.12
pip install frida-tools pymem pefile capstone keystone-engine unicorn UnityPy

# Visual Studio (C/C++)
winget install Microsoft.VisualStudio.2022.Community

# 工具
winget install Git.Git
winget install Kitware.CMake
winget install ProcessHacker.ProcessHacker

# Ghidra (需要 JDK 17+)
winget install Oracle.JDK.17
# 从 ghidra-sre.org 下载 Ghidra

# x64dbg
# 从 github.com/x64dbg/x64dbg/releases 下载
```

### Android 逆向环境

```bash
pip install frida-tools
winget install Google.PlatformTools  # ADB
# jadx: github.com/skylot/jadx/releases
```
