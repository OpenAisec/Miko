# Miko

<p align="center">
  <img src="docs/images/logo.png" alt="Miko Logo" width="180">
</p>

A security testing agent focused on information gathering and reconnaissance, designed for penetration testing and security auditing.

Built on a **blackboard mechanism** for multi-round reconnaissance memory, with **exploration mode** for continuous deep-dive analysis, and a **focus system** ensuring complete coverage of every finding. **Exploration coverage is clearly visible** — you can direct the agent to expand attack surfaces horizontally or dive deep into specific breaches at any time. Supports **one-click session-to-project conversion** for seamless evolution from ad-hoc testing to full penetration projects.

<p align="center">
  <a href="https://github.com/OpenAisec/Miko/releases"><img src="https://img.shields.io/badge/⬇_Download_Portable-Windows-FF7A00?style=for-the-badge" alt="Download Portable"></a>
  &nbsp;
  <a href="BUILD.md"><img src="https://img.shields.io/badge/📖_Build_Guide-Guide-gray?style=for-the-badge" alt="Build Guide"></a>
</p>

## 📸 Screenshots

<table>
  <tr>
    <td align="center" width="33%"><img src="docs/images/探索链路.png" alt="Exploration Chain"><br><b>Exploration Chain & Blackboard</b></td>
    <td align="center" width="33%"><img src="docs/images/会话项目.png" alt="Session to Project"><br><b>Session to Project</b></td>
    <td align="center" width="33%" rowspan="2"><img src="docs/images/移动端.png" alt="Mobile" style="max-width:90%"><br><b>Mobile Adaptation</b></td>
  </tr>
  <tr>
    <td align="center" width="33%"><img src="docs/images/工具、skills等.png" alt="Tools Integration"><br><b>Tools & Skills Integration</b></td>
    <td align="center" width="33%"><img src="docs/images/项目管理.png" alt="Project Management"><br><b>Project Management</b></td>
  </tr>
</table>

---

## ✨ Features

- 🎯 **Focus System** - Lock onto targets for deep investigation, auto-track incomplete leads, ensure complete test coverage with visualized exploration progress
- 🗺️ **Coverage Control** - Switch between horizontal expansion (breadth-first) or vertical deep-dive (depth-first) anytime, with clear exploration paths
- 🧠 **Blackboard Mechanism** - Multi-turn dialogue preserves reconnaissance context, full memory of discoveries, reasoning, and actions to avoid redundant work
- 🔍 **Exploration Mode** - Auto-expand thinking from single breaches to complete attack surfaces, intelligently recommend next reconnaissance steps
- 📋 **Session to Project** - One-click conversion of temporary test dialogues into persistent projects, preserving all findings and workflows
- 🛠️ **Pre-installed Toolchain** - Integrated with subfinder, katana, fscan, gobuster, radare2, and 8 other tools
- 📚 **23+ Skill Library** - Covering information gathering, code auditing, vulnerability detection, and reverse engineering
- 🤖 **Multi-Model Support** - Compatible with DeepSeek, Qwen, Azure OpenAI, and other mainstream AI models
- 🖥️ **Desktop Application** - Cross-platform client built with Tauri 2 + React

## 🚀 Quick Start

### Download Portable Version (Recommended)

1. Go to [Releases](https://github.com/OpenAisec/Miko/releases) and download the latest `Miko-portable-win-x64.zip`
2. Extract to any **writable directory** (avoid C:\Program Files)
3. Double-click `miko.exe` to launch

### Initial Setup

1. Open Settings → API Keys
2. Add your API key (DeepSeek / Qwen / Others)
3. Start using

### Permission Mode Recommendations

`Accept edits` mainly auto-approves file edits. It does not skip all permission checks. Bash, MCP, network requests, sensitive path access, and similar operations may still go through the permission flow.

Exploration mode delegates real probing work to the `security-explore` sub-agent, which frequently uses Bash, Web tools, and MCP blackboard writes. For that reason, `Accept edits + Exploration mode` is not recommended; this combination may cause sub-agents to wait on permissions, time out, or appear unresponsive.

Recommended combination: in trusted projects and controlled testing environments, prefer `Allow all / Bypass permissions + Exploration mode`. For unknown environments or regular coding tasks, use `Ask permissions` or `Accept edits` instead.

### Miko Global Prompt

After initial setup, consider filling in **Miko Global Prompt** in Settings. This prompt is injected into the context of every conversation and is useful for long-term rules and safety boundaries.

Example:

```text
During testing, if you encounter sensitive operations such as create, update, delete, or modify, stop immediately and ask the user.
```

Even when using `Allow all / Bypass permissions + Exploration mode`, configuring a global prompt is recommended to constrain Miko's behavior. Note: the global prompt is a behavioral instruction, not the permission system itself; actual tool blocking still depends on the current permission mode.

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
