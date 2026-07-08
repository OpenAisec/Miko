# 工具台账 — 绿色二进制存放区

kimo 探索模式的外部安全工具，采用「绿色内置」策略：**只收免环境安装的单文件工具**（Go 静态二进制为主），随发布包分发，用户下载 kimo 即开箱即用。

## 目录结构

```
data/tools/
├── <id>.yaml              工具台账说明书（元数据：分类/用法/探测配置）
├── .status.json           探测状态缓存（自动生成，可重建，不入 git）
└── bin/
    ├── README.md          本文件
    ├── win/               Windows 二进制（*.exe）
    │   ├── nuclei.exe
    │   ├── ffuf.exe
    │   └── ...
    ├── linux/             Linux 二进制（无扩展名）
    └── darwin/            macOS 二进制（无扩展名）
```

**平台判定**（探测时自动）：`win32`→`win`，`darwin`→`darwin`，其余→`linux`。

## 命名规则（关键）

- 文件名 = yaml 里的 `bin` 字段值。例：`nuclei.yaml` 的 `bin: 'nuclei'` → 放 `win/nuclei.exe`（Windows）或 `linux/nuclei`（Linux）。
- Windows 探测查 `<bin>.exe` 和 `<bin>` 两种；Linux/macOS 只查 `<bin>`。
- 放错名字 = 探测查不到 = UI 显示"未装"。改名或改 yaml 的 `bin` 字段对齐。

## 探测机制（工具怎么算"已装"）

`toolProbeService` 对每个 `bundled: true` 的工具：
1. **优先**查 `bin/<platform>/<bin>[.exe]` 是否存在 → 有则「已装」（随包发，绕过系统 PATH）。
2. 内置目录没有 → 回退：有 `check` 命令就跑，否则 `which(bin)` 查系统 PATH（用户可能自己装了同名工具）。
3. 都没有 → 「未装」。

改动 bin 目录后，调 `POST /api/catalog/probe` 或 UI「重新探测」刷新状态。

## 怎么放二进制（运维方法）

以 Windows 为例，从各工具 GitHub release 下载对应平台包，解压出可执行文件放入 `bin/<platform>/`：

```bash
# 网络受限时走 GitHub 加速镜像（如 ghfast.top），拼在原 URL 前：
curl -sL -o bin/win/ffuf.exe "https://ghfast.top/https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip"
# zip/tar.gz 需解压提取 exe；单文件 exe 直接存
```

**注意事项**：
- **杀软误删**：fscan、部分红队工具会被 Windows Defender 判为恶意软件删除。需加信任目录白名单（`data/tools/bin/`），否则放进去即被删、探测显示"未装"。
- **平台不通用**：win/linux/darwin 二进制互不兼容，各平台单独放。发布时按目标平台打对应目录。
- **版本**：建议放各工具最新 stable release。

## 可移植性

- **二进制不入 git**（`.gitignore` 已排除 `bin/*/*`，仅保留 `.gitkeep` + 本 README）。体积大（单个几 MB~上百 MB），应随**发布包**分发，不进代码仓库。
- **目录结构入 git**（`.gitkeep` 占位），克隆后结构就在，放入二进制即用。
- **跨机部署**：用户拿到发布包 → `bin/<平台>/` 已含对应二进制 → 探测直接「已装」，无需任何安装步骤。这是「绿色内置」的核心价值。
- **增删工具**：加工具 = 加 `<id>.yaml`（`bundled: true` + `bin`）+ 放二进制；减 = 删两者。探测和 UI 自动反映。

## 当前内置清单（14 个 yaml，9 个已放二进制）

| 分类 | 工具 | 二进制状态 |
|------|------|-----------|
| web | nuclei, ffuf, gobuster, dalfox, katana | ✅ 已放（Go 单文件） |
| web | wafw00f | ⏳ 待放（Python，非 Go release） |
| asset | subfinder, gau, waybackurls, fscan | ✅ 已放 |
| binary | radare2, gdb, strings | ⏳ 待放（非标准 Go release：zip/mingw/sysinternals） |
| forensics | exiftool | ⏳ 待放（Perl 打包） |

> 待放的 5 个是非标准 Go release（依赖打包格式不同），需单独处理。已放的 9 个 Go 单文件工具「放入→探测→已装」链路已验证通过。
