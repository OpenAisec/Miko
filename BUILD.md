# Miko 编译打包完全指南

本文档提供从零开始编译 Miko 便携版的详细步骤。

---

## 📋 前提条件

### 必需工具

| 工具 | 版本要求 | 下载地址 |
|------|---------|---------|
| **Bun** | >= 1.0 | https://bun.sh/ |
| **Rust** | >= 1.80 | https://rustup.rs/ |
| **Visual Studio 2022** | Build Tools | https://visualstudio.microsoft.com/downloads/ |

### Visual Studio 组件要求

安装 Visual Studio 2022 时，必须勾选以下组件：
- **使用 C++ 的桌面开发** (Desktop development with C++)
- MSVC v143 编译工具
- Windows 11 SDK

### 验证环境

打开 PowerShell，执行以下命令确认工具已安装：

```powershell
bun --version    # 应显示 1.x.x
rustc --version  # 应显示 1.80+ 或更高
cargo --version  # 应显示 1.80+ 或更高
```

---

## 🔨 编译步骤

### 第 1 步：克隆仓库

```powershell
git clone https://github.com/OpenAisec/Miko.git
cd Miko
```

### 第 2 步：安装依赖

项目有 3 个 `package.json`，需要分别安装依赖：

```powershell
# 根目录依赖
bun install

# Desktop 依赖
cd desktop
bun install

# Adapters 依赖
cd ..\adapters
bun install

# 返回根目录
cd ..
```

**预计耗时**：2-5 分钟（取决于网络速度）

### 第 3 步：设置环境变量（仅当前会话）

```powershell
# 如果 bun 和 cargo 不在系统 PATH，手动添加
$env:Path = "C:\Users\你的用户名\.cargo\bin;C:\Users\你的用户名\.bun\bin;$env:Path"

# 允许 PowerShell 执行脚本
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**注意**：将 `你的用户名` 替换为实际的 Windows 用户名。

### 第 4 步：执行打包脚本

```powershell
cd desktop
.\scripts\build-portable-win.ps1
```

**预计耗时**：10-20 分钟（首次编译会下载 Rust 依赖）

---

## 📦 产物位置

编译成功后，产物位于：

```
desktop\build-artifacts\portable-win-x64\
```

该目录包含：
- `miko.exe` - 主程序
- `CLAUDE_CONFIG_DIR\` - 数据目录
  - `data\skills\` - 23 个内置技能
  - `data\tools\` - 8 款安全工具（含二进制）
  - `data\agents\` - 8 个预置 Agent

### 测试产物

```powershell
cd desktop\build-artifacts\portable-win-x64
.\miko.exe
```

双击 `miko.exe` 应能正常启动桌面应用。

---

## ⚠️ 常见问题

### 问题 1：`bun: command not found`

**原因**：Bun 未安装或不在 PATH。

**解决**：
```powershell
# 安装 Bun
powershell -c "irm bun.sh/install.ps1 | iex"

# 重启 PowerShell，或手动添加到 PATH
$env:Path = "C:\Users\你的用户名\.bun\bin;$env:Path"
```

### 问题 2：`rustc: command not found`

**原因**：Rust 未安装。

**解决**：
```powershell
# 下载并运行 rustup-init.exe
# https://rustup.rs/

# 安装后重启 PowerShell
rustc --version  # 验证
```

### 问题 3：`error: failed to run custom build command`

**原因**：缺少 Visual Studio C++ 工作负载。

**解决**：
1. 运行 Visual Studio Installer
2. 修改现有安装
3. 勾选 "使用 C++ 的桌面开发"
4. 安装后重试编译

### 问题 4：`feature edition2024 is required`

**原因**：Rust 版本太旧（< 1.80）。

**解决**：
```powershell
rustup update stable
rustc --version  # 应显示 1.80+
```

### 问题 5：`resource path binaries\claude-sidecar-xxx.exe doesn't exist`

**原因**：Sidecar（CLI/Server 组件）编译失败。

**解决**：
```powershell
cd desktop
bun run build:sidecars

# 确认文件生成
dir src-tauri\binaries\claude-sidecar-*.exe
```

如果仍然失败，检查根目录依赖是否完整安装：
```powershell
cd ..
bun install --force
```

### 问题 6：编译过程中断或失败

**解决**：
1. 删除临时文件：
```powershell
Remove-Item desktop\src-tauri\target -Recurse -Force
Remove-Item desktop\dist -Recurse -Force
Remove-Item desktop\build-artifacts -Recurse -Force
```

2. 重新编译：
```powershell
cd desktop
.\scripts\build-portable-win.ps1
```

---

## 🔧 高级选项

### 仅编译 Sidecar（不打包桌面）

```powershell
cd desktop
bun run build:sidecars
```

产物：`desktop/src-tauri/binaries/claude-sidecar-*.exe`

### 构建 MSI 安装包（非便携版）

```powershell
cd desktop
.\scripts\build-windows-x64.ps1
```

产物：`desktop/src-tauri/target/release/bundle/msi/*.msi`

### 仅构建前端（不含 Tauri）

```powershell
cd desktop
bun run build
```

产物：`desktop/dist/`（静态网页）

---

## 📁 目录结构说明

```
Miko/
├── src/                    # 后端核心代码（Node.js）
├── desktop/                # 桌面客户端
│   ├── src/               # 前端代码（React）
│   ├── src-tauri/         # Tauri 壳（Rust）
│   ├── scripts/           # 构建脚本
│   └── sidecars/          # CLI/Server 入口
├── adapters/              # IM 适配器（Telegram/飞书等）
├── data/
│   ├── skills/            # 23 个内置技能
│   ├── tools/             # 工具定义 + 二进制
│   └── agents/            # 预置 Agent
└── BUILD.md               # 本文档
```

---

## 🚀 一键编译脚本（适用于已配置环境）

如果环境已正确配置（Bun、Rust、VS2022 都在 PATH），可以使用一键脚本：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; cd desktop; .\scripts\build-portable-win.ps1
```

---

## 🤝 贡献者提示

### 修改代码后重新编译

如果修改了以下内容，需要重新编译对应部分：

| 修改内容 | 重新编译命令 |
|---------|-------------|
| `src/` 后端代码 | `cd desktop && bun run build:sidecars` |
| `desktop/src/` 前端代码 | `cd desktop && bun run build` |
| `desktop/src-tauri/` Rust 代码 | 完整打包流程 |
| `data/skills/` 技能文件 | 无需重新编译，直接复制到产物 |

### 快速测试（开发模式）

```powershell
cd desktop
bun run dev  # 启动开发服务器，支持热重载
```

---

## 📞 获取帮助

- **Issue 反馈**：https://github.com/OpenAisec/Miko/issues
- **讨论区**：https://github.com/OpenAisec/Miko/discussions

编译遇到问题时，请附上：
1. 完整的错误日志
2. 操作系统版本（`winver` 查看）
3. 工具版本（`bun --version`、`rustc --version`）
