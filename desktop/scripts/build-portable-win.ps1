<#
  build-portable-win.ps1 — 出一个 Windows 绿色便携版（非 MSI）。

  思路：编译出 release 散文件，拢成一个可拷走的目录，并在 exe 旁建
  CLAUDE_CONFIG_DIR\ 子目录 + app-mode.json(mode=portable)，让程序启动时
  determine_startup_portable_dir 命中便携模式 → 恒设 CLAUDE_CONFIG_DIR →
  数据/agents/skills/tools 全锚 exe 旁，复刻 dev 效果，绕开 MSI 默认安装态
  那些「未设 CLAUDE_CONFIG_DIR 而漏注入」的坑。

  内置 agents/skills/tools 预置进 <根>\CLAUDE_CONFIG_DIR\data\，三类资源同级，
  不依赖只读旁路。

  用法（PowerShell）：
    ./scripts/build-portable-win.ps1
  环境变量：
    SKIP_BUILD=1  跳过 tauri 编译（复用已有 release 散文件，只重组便携目录）
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktopDir = (Resolve-Path (Join-Path $scriptDir '..')).Path
$repoRoot = (Resolve-Path (Join-Path $desktopDir '..')).Path

$targetTriple = 'x86_64-pc-windows-msvc'
$releaseDir = Join-Path $desktopDir "src-tauri\target\$targetTriple\release"
$outDir = Join-Path $desktopDir 'build-artifacts\portable-win-x64'
$configDirName = 'CLAUDE_CONFIG_DIR'

function Write-Step { param([string]$m) Write-Host "[build-portable] $m" }

function Import-VsDevEnvironment {
  $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path $vswhere)) {
    throw '[build-portable] vswhere.exe not found. Install VS 2022 Build Tools (C++ workload).'
  }
  $installationPath = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
  if (-not $installationPath) { throw '[build-portable] Missing VC.Tools.x86.x64 workload.' }
  $vsDevCmd = Join-Path $installationPath 'Common7\Tools\VsDevCmd.bat'
  if (-not (Test-Path $vsDevCmd)) { throw "[build-portable] VsDevCmd.bat not found under $installationPath" }
  Write-Step "Importing MSVC env from $vsDevCmd"
  $env:VSCMD_SKIP_SENDTELEMETRY = '1'
  $envDump = & cmd.exe /d /s /c "`"$vsDevCmd`" -arch=x64 -host_arch=x64 >nul && set"
  if ($LASTEXITCODE -ne 0) { throw "[build-portable] VsDevCmd init failed (exit $LASTEXITCODE)" }
  foreach ($line in $envDump) {
    if ($line -match '^(.*?)=(.*)$') {
      [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
  }
}
function Ensure-ToolPath {
  $bunBin = Join-Path $env:USERPROFILE '.bun\bin'
  $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
  foreach ($d in @($bunBin, $cargoBin)) {
    if ((Test-Path $d) -and -not (($env:Path -split ';') -contains $d)) {
      $env:Path = "$d;$env:Path"
    }
  }
}

function Copy-Tree {
  param([string]$Src, [string]$Dst)
  if (-not (Test-Path $Src)) { throw "[build-portable] source missing: $Src" }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dst) | Out-Null
  Copy-Item -LiteralPath $Src -Destination $Dst -Recurse -Force
}

# ---------- 1. 编译 ----------
Ensure-ToolPath
Import-VsDevEnvironment

$bun = Join-Path $env:USERPROFILE '.bun\bin\bun.exe'
if (-not (Test-Path $bun)) { throw '[build-portable] bun.exe not found under ~/.bun/bin' }

if ($env:SKIP_BUILD -ne '1') {
  $env:CLAUDE_CODE_BUN_TARGET = 'bun-windows-x64'   # 绕过 baseline 运行时下载被墙
  $env:TAURI_ENV_TARGET_TRIPLE = $targetTriple

  Write-Step 'Building frontend + sidecars...'
  Push-Location $desktopDir
  try {
    & $bun run build
    if ($LASTEXITCODE -ne 0) { throw "[build-portable] frontend build failed (exit $LASTEXITCODE)" }
    & $bun run build:sidecars
    if ($LASTEXITCODE -ne 0) { throw "[build-portable] build:sidecars failed (exit $LASTEXITCODE)" }

    Write-Step 'Compiling Rust (tauri build --no-bundle)...'
    & bunx tauri build --target $targetTriple --no-bundle
    if ($LASTEXITCODE -ne 0) { throw "[build-portable] tauri build failed (exit $LASTEXITCODE)" }
  } finally {
    Pop-Location
  }
} else {
  Write-Step 'SKIP_BUILD=1 — reusing existing release artifacts.'
}
# ---------- 2. 组装便携目录 ----------
if (Test-Path $outDir) { Remove-Item -LiteralPath $outDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$exe = Join-Path $releaseDir 'miko.exe'
$sidecar = Join-Path $releaseDir 'claude-sidecar.exe'
foreach ($f in @($exe, $sidecar)) {
  if (-not (Test-Path $f)) { throw "[build-portable] missing built exe: $f (build first, do not SKIP_BUILD)" }
}
Write-Step 'Copying executables...'
Copy-Item -LiteralPath $exe -Destination (Join-Path $outDir 'miko.exe') -Force
Copy-Item -LiteralPath $sidecar -Destination (Join-Path $outDir 'claude-sidecar.exe') -Force

# 前端 H5：原样复制 release 下的 _up_ 树（含 _up_/dist），保持 resource_dir 相对结构。
Write-Step 'Copying frontend (_up_)...'
$upSrc = Join-Path $releaseDir '_up_'
if (Test-Path $upSrc) {
  Copy-Item -LiteralPath $upSrc -Destination (Join-Path $outDir '_up_') -Recurse -Force
} else {
  Write-Step 'WARN: release/_up_ not found — frontend may not load. Check select_h5_dist_dir.'
}

# resources（icon 等）
$resSrc = Join-Path $releaseDir 'resources'
if (Test-Path $resSrc) {
  Copy-Item -LiteralPath $resSrc -Destination (Join-Path $outDir 'resources') -Recurse -Force
}
# ---------- 3. 便携数据骨架 CLAUDE_CONFIG_DIR\ ----------
$portableCfg = Join-Path $outDir $configDirName
$portableData = Join-Path $portableCfg 'data'
New-Item -ItemType Directory -Force -Path $portableData | Out-Null

# app-mode.json → 触发 determine_startup_portable_dir 的便携判定
Write-Step 'Writing app-mode.json (portable)...'
[System.IO.File]::WriteAllText((Join-Path $portableCfg 'app-mode.json'), '{"mode":"portable"}', [System.Text.UTF8Encoding]::new($false))

# 内置 agents：只拷 protectedResources 白名单内的（过滤 test*/verification 之外的杂项）。
# 白名单与 src/server/services/protectedResources.ts 的 PROTECTED_AGENTS 对齐。
$builtinAgents = @(
  'security-explore', 'Explore', 'Plan', 'general-purpose',
  'verification', 'skill-creator-agent', 'skill-editor', 'statusline-setup'
)
$agentsSrc = Join-Path $repoRoot 'data\agents'
$agentsDst = Join-Path $portableData 'agents'
New-Item -ItemType Directory -Force -Path $agentsDst | Out-Null
Write-Step 'Preseeding built-in agents...'
foreach ($name in $builtinAgents) {
  $md = Join-Path $agentsSrc "$name.md"
  if (Test-Path $md) {
    Copy-Item -LiteralPath $md -Destination (Join-Path $agentsDst "$name.md") -Force
  } else {
    Write-Step "WARN: agent def missing in source: $name.md"
  }
}

# skills：全量拷（排除两个非真 skill 的产物目录）。
$skillsSrc = Join-Path $repoRoot 'data\skills'
$skillsDst = Join-Path $portableData 'skills'
$skillExclude = @('code-audit-workspace', 'php-deep-audit-workspace')
New-Item -ItemType Directory -Force -Path $skillsDst | Out-Null
Write-Step 'Preseeding skills...'
if (-not (Test-Path $skillsSrc)) {
  throw "[build-portable] source skills dir missing: $skillsSrc"
}

Get-ChildItem -LiteralPath $skillsSrc -Directory | ForEach-Object {
  if ($skillExclude -notcontains $_.Name) {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $skillsDst $_.Name) -Recurse -Force
  }
}

$copiedSkillDirs = @(Get-ChildItem -LiteralPath $skillsDst -Directory -ErrorAction SilentlyContinue)
if ($copiedSkillDirs.Count -eq 0) {
  throw "[build-portable] no skills were copied from $skillsSrc"
}

$invalidSkillDirs = @(
  $copiedSkillDirs | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $_.FullName 'SKILL.md'))
  }
)
if ($invalidSkillDirs.Count -gt 0) {
  $names = ($invalidSkillDirs | ForEach-Object { $_.Name }) -join ', '
  throw "[build-portable] copied skill directories missing SKILL.md: $names"
}

# tools：整目录拷（yaml + bin 二进制），便携态走同一份可写 data/tools。
$toolsSrc = Join-Path $repoRoot 'data\tools'
if (Test-Path $toolsSrc) {
  Write-Step 'Preseeding tools catalog + binaries...'
  Copy-Item -LiteralPath $toolsSrc -Destination (Join-Path $portableData 'tools') -Recurse -Force
}
# ---------- 4. 摘要 ----------
$agentCount = (Get-ChildItem -LiteralPath $agentsDst -Filter '*.md' -ErrorAction SilentlyContinue | Measure-Object).Count
$skillCount = (Get-ChildItem -LiteralPath $skillsDst -Directory -ErrorAction SilentlyContinue | Measure-Object).Count

Write-Host ''
Write-Step 'Portable build finished.'
Write-Step "Output: $outDir"
Write-Step "  miko.exe / claude-sidecar.exe"
Write-Step "  $configDirName\app-mode.json (mode=portable)"
Write-Step "  $configDirName\data\agents  ($agentCount built-in)"
Write-Step "  $configDirName\data\skills  ($skillCount)"
Write-Step "  $configDirName\data\tools   (catalog + bin)"
Write-Host ''
Write-Step 'Next: copy the whole folder somewhere writable and double-click miko.exe.'
Write-Step 'Verify: chat works / cwd not Administrator / security-explore starts / skills load.'

