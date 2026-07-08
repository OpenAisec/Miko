# Miko

专注信息收集和探测的安全测试 Agent，为渗透测试和安全审计而生。

## ✨ 特性

- 🔍 **信息收集专精** - 内置 23+ 安全技能，覆盖子域发现、端口扫描、漏洞探测、敏感信息挖掘
- 🛠️ **预装安全工具** - 集成 subfinder、katana、fscan、gobuster、radare2 等 8 款专业工具
- 🤖 **多模型支持** - 兼容 DeepSeek、通义千问、Azure OpenAI 等主流 AI 模型
- 🖥️ **桌面应用** - 基于 Tauri 2 + React 构建的跨平台桌面客户端
- 📦 **开箱即用** - 便携版无需安装，解压即可运行

## 🚀 快速开始

### 下载便携版（推荐）

1. 前往 [Releases](https://github.com/OpenAisec/Miko/releases) 下载最新版 `Miko-portable-win-x64.zip`
2. 解压到任意**可写目录**（避免 C:\Program Files）
3. 双击 `miko.exe` 启动

### 首次配置

1. 打开设置 → API Keys
2. 添加你的 API Key（DeepSeek / 通义千问 / 其他）
3. 开始使用

## 🔧 从源码构建

### 前提条件

- [Bun](https://bun.sh/) >= 1.0
- [Rust](https://www.rust-lang.org/) (cargo >= 1.70)
- Windows: Visual Studio 2022 含 C++ 桌面开发工作负载

### 编译步骤

```powershell
# 克隆仓库
git clone https://github.com/OpenAisec/Miko.git
cd Miko

# 安装依赖
bun install
cd desktop
bun install
cd ..

# 构建便携版（推荐）
cd desktop
.\scripts\build-portable-win.ps1

# 产物位置
# desktop\build-artifacts\portable-win-x64\
```

### 其他平台

- **MSI 安装包**: `.\scripts\build-windows-x64.ps1`
- **macOS**: `bun run build:macos-arm64`

## 📚 内置技能（Skills）

Miko 预装 23 个安全测试技能，专注信息收集和探测阶段：

- **信息收集**: 子域发现、端口扫描、目录爆破、敏感路径探测
- **代码审计**: PHP 深度审计、敏感信息扫描、配置文件分析
- **漏洞探测**: XSS 检测、SQL 注入探测、参数污染分析
- **逆向分析**: 基于 radare2 的二进制分析工作流

完整列表见 [`data/skills/`](data/skills/)

## 🛠️ 内置工具（Tools）

| 工具 | 用途 |
|------|------|
| **subfinder** | 子域名发现 |
| **katana** | Web 爬虫与端点提取 |
| **fscan** | 内网扫描 |
| **gobuster** | 目录/DNS 爆破 |
| **ffuf** | Web Fuzzer |
| **gau** | 历史 URL 收集 |
| **dalfox** | XSS 扫描器 |
| **radare2** | 逆向工程框架 |

工具定义见 [`data/tools/`](data/tools/)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request。

## 🏢 关于

由 [OpenAisec](https://github.com/OpenAisec) 维护。
