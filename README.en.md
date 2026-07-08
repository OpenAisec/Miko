# Miko

A security testing agent focused on information gathering and reconnaissance, designed for penetration testing and security auditing.

## ✨ Features

- 🔍 **Reconnaissance Specialized** - 23+ built-in security skills covering subdomain discovery, port scanning, vulnerability detection, and sensitive information mining
- 🛠️ **Pre-installed Tools** - Integrated with 8 professional tools: subfinder, katana, fscan, gobuster, radare2, and more
- 🤖 **Multi-Model Support** - Compatible with DeepSeek, Qwen, Azure OpenAI, and other mainstream AI models
- 🖥️ **Desktop Application** - Cross-platform client built with Tauri 2 + React
- 📦 **Ready to Use** - Portable version requires no installation, just extract and run

## 🚀 Quick Start

### Download Portable Version (Recommended)

1. Go to [Releases](https://github.com/OpenAisec/Miko/releases) and download the latest `Miko-portable-win-x64.zip`
2. Extract to any **writable directory** (avoid C:\Program Files)
3. Double-click `miko.exe` to launch

### Initial Setup

1. Open Settings → API Keys
2. Add your API key (DeepSeek / Qwen / Others)
3. Start using

## 🔧 Building from Source

**For complete build guide with troubleshooting, see [BUILD.md](BUILD.md)**

### Quick Start

#### Prerequisites

- [Bun](https://bun.sh/) >= 1.0
- [Rust](https://www.rust-lang.org/) (cargo >= 1.80)
- Windows: Visual Studio 2022 with C++ Desktop Development workload

#### Build Steps

```powershell
# Clone repository
git clone https://github.com/OpenAisec/Miko.git
cd Miko

# Install dependencies (all three locations required)
# 1. Root directory
bun install

# 2. Desktop
cd desktop
bun install

# 3. Adapters
cd ..\adapters
bun install

# Return to desktop and build
cd ..\desktop
.\scripts\build-portable-win.ps1

# Output location
# desktop\build-artifacts\portable-win-x64\
```

### Other Platforms

- **MSI installer**: `.\scripts\build-windows-x64.ps1`
- **macOS**: `bun run build:macos-arm64`

## 📚 Built-in Skills

Miko comes with 23 security testing skills covering the full penetration testing lifecycle:

- **Information Gathering**: Subdomain discovery, port scanning, directory brute-forcing, sensitive path detection, fingerprinting
- **Code Auditing**: PHP deep audit, sensitive information scanning, configuration analysis, dependency vulnerability detection
- **Vulnerability Detection**: XSS detection, SQL injection probing, parameter pollution analysis, SSRF testing
- **Reverse Engineering**: Binary analysis workflows powered by radare2, decompilation, dynamic debugging
- **Mobile Security**: Android APK reverse engineering, permission analysis, component security auditing

Full list available in [`data/skills/`](data/skills/)

## 🛠️ Built-in Tools

| Tool | Purpose |
|------|---------|
| **subfinder** | Subdomain discovery |
| **katana** | Web crawler & endpoint extraction |
| **fscan** | Internal network scanning |
| **gobuster** | Directory/DNS brute-forcing |
| **ffuf** | Web fuzzer |
| **gau** | Historical URL collection |
| **dalfox** | XSS scanner |
| **radare2** | Reverse engineering framework |

Tool definitions in [`data/tools/`](data/tools/)

## 🤝 Contributing

Issues and Pull Requests are welcome.

## 🏢 About

Maintained by [OpenAisec](https://github.com/OpenAisec).
