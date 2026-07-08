/**
 * kimo Paths — 中心路径模块
 *
 * 所有配置和数据的「唯一真相源」。
 * 原则：无用户级全局目录，一切从工具自身的 data/ 目录读取。
 *
 * 路径优先级：
 *   1. setDataDir(dir) 显式设置
 *   2. KIMO_DATA_DIR 环境变量
 *   3. exe 所在目录/data（生产）
 *   4. cwd/data（开发回退）
 *
 * data/ 目录结构：
 *   skills/          技能
 *   agents/          Agent 定义
 *   commands/        命令
 *   workflows/       工作流
 *   output-styles/   输出样式
 *   rules/           规则
 *   mcp.json         MCP 服务器配置
 *   settings.json    全部设置
 *   providers.json   提供商列表
 *   oauth.json       OAuth 令牌
 *   desktop-ui.json  桌面端 UI 偏好
 *   keybindings.json 快捷键
 *   projects/        会话历史
 *   plugins/         插件
 *   cache/           缓存
 *   history.jsonl    全局历史
 *   plans/           计划文件
 *   file-history/    文件编辑历史
 *   scheduled_tasks.json 定时任务
 *   adapters.json    IM 适配器配置
 *   uploads/         上传附件
 *   backup/          配置备份
 *   runtime/         Python venv 等运行时
 *   .lock/           并发锁
 *   debug/           调试日志
 *   chrome/          Claude in Chrome
 *   telemetry/       遥测（可选）
 */

import { dirname, join } from 'path'
import { isInBundledMode } from './bundledMode.js'

// ─── data/ 根目录 ─────────────────────────────────────────────────────

let _dataDir: string | null = null

export function setDataDir(dir: string): void {
  _dataDir = dir
}

/**
 * 获取 data/ 根目录（唯一真相源）。
 *
 * 核心规则：解析出来的就是"数据目录本身"——包含 settings.json / projects/ /
 * security/ 的那一层。任何分支都不得二次追加子目录，调用方也不得在外面再拼。
 *
 * 路径优先级：
 *   1. setDataDir(dir)        显式设置（测试 / 编程调用），原样
 *   2. KIMO_DATA_ROOT         主变量，直接指数据目录，原样（不追加 /data）
 *   3. KIMO_DATA_DIR          legacy：指应用根，自动追加 /data（bin/kimo、adapters 兼容）
 *   4. CLAUDE_CONFIG_DIR      legacy：可移植目录，原样（打包桌面端、测试兼容）
 *   5. 打包模式               exe 所在目录/data（process.execPath 是 kimo 二进制本身）
 *   6. 开发模式               cwd/data（bun 运行源码时 execPath 是 bun.exe，
 *                             绝不能用它的目录，否则数据会写进 bun 安装目录）
 *
 * 注意：第 5 条仅在 Bun 编译的独立二进制（isInBundledMode）下成立。
 * KIMO_DATA_ROOT vs KIMO_DATA_DIR 的区别是历史教训：前者直接指数据目录，
 * 后者会 +/data。两者喂同一路径会落到不同目录，曾导致会话数据分裂。
 * 新代码与启动器一律优先用 KIMO_DATA_ROOT。
 */
export function getDataDir(): string {
  if (_dataDir) return _dataDir
  return resolveDataDirFromEnv(process.env)
}

/**
 * 纯函数：按给定 env 解析数据根，逻辑与 getDataDir() 完全一致（不含 setDataDir 覆盖）。
 * 抽出来是为了让启动自检能算出"CLI 子进程拿到这份 env 会解析到哪个根"，
 * 与 server 自身解析结果对比，零逻辑漂移。
 */
export function resolveDataDirFromEnv(env: NodeJS.ProcessEnv): string {
  if (env.KIMO_DATA_ROOT) return env.KIMO_DATA_ROOT
  if (env.KIMO_DATA_DIR) return join(env.KIMO_DATA_DIR, 'data')
  if (env.CLAUDE_CONFIG_DIR) return env.CLAUDE_CONFIG_DIR
  // 打包模式：process.execPath 是 kimo 独立二进制，其目录旁的 data/ 才是数据根
  if (isInBundledMode()) {
    try {
      return join(dirname(process.execPath), 'data')
    } catch {
      // ignore，落到开发回退
    }
  }
  // 开发模式：用 bun 运行源码，execPath 是 bun.exe，只能回退到当前工作目录
  return join(process.cwd(), 'data')
}

/**
 * 返回当前 data 根的解析来源（用于启动日志 / 自检）。
 * 不读 _dataDir 之外的副作用，纯判定优先级命中了哪条。
 */
export function getDataDirSource(): string {
  if (_dataDir) return 'setDataDir()'
  if (process.env.KIMO_DATA_ROOT) return 'KIMO_DATA_ROOT'
  if (process.env.KIMO_DATA_DIR) return 'KIMO_DATA_DIR(+/data)'
  if (process.env.CLAUDE_CONFIG_DIR) return 'CLAUDE_CONFIG_DIR'
  if (isInBundledMode()) return 'bundled-execPath'
  return 'cwd/data(dev)'
}

// ─── 通用子目录 ─────────────────────────────────────────────────────────

export function getSubDir(name: string): string {
  return join(getDataDir(), name)
}

// ─── 数据目录 ──────────────────────────────────────────────────────────

export function getSkillsDir(): string {
  return getSubDir('skills')
}

export function getAgentsDir(): string {
  return getSubDir('agents')
}

export function getCommandsDir(): string {
  return getSubDir('commands')
}

export function getWorkflowsDir(): string {
  return getSubDir('workflows')
}

export function getOutputStylesDir(): string {
  return getSubDir('output-styles')
}

export function getRulesDir(): string {
  return getSubDir('rules')
}

export function getAgentMemoryDir(): string {
  return getSubDir('agent-memory')
}

export function getWorktreesDir(): string {
  return getSubDir('worktrees')
}

export function getProjectsDir(): string {
  return getSubDir('projects')
}

export function getPluginsDir(): string {
  return getSubDir('plugins')
}

export function getCacheDir(): string {
  return getSubDir('cache')
}

export function getPlansDir(): string {
  return getSubDir('plans')
}

export function getFileHistoryDir(): string {
  return getSubDir('file-history')
}

export function getUploadsDir(): string {
  return getSubDir('uploads')
}

export function getRuntimeDir(): string {
  return getSubDir('runtime')
}

export function getBackupDir(): string {
  return getSubDir('backup')
}

export function getLockDir(): string {
  return getSubDir('.lock')
}

export function getDebugDir(): string {
  return getSubDir('debug')
}

export function getChromeDir(): string {
  return getSubDir('chrome')
}

// ─── 配置文件（文件路径） ───────────────────────────────────────────────

export function getMcpFile(): string {
  return getSubDir('mcp.json')
}

export function getSettingsFile(): string {
  return getSubDir('settings.json')
}

export function getProvidersFile(): string {
  return getSubDir('providers.json')
}

export function getOAuthFile(): string {
  return getSubDir('oauth.json')
}

export function getOpenAIOAuthFile(): string {
  return getSubDir('openai-oauth.json')
}

export function getDesktopUiFile(): string {
  return getSubDir('desktop-ui.json')
}

export function getKeybindingsFile(): string {
  return getSubDir('keybindings.json')
}

export function getScheduledTasksFile(): string {
  return getSubDir('scheduled_tasks.json')
}

export function getAdaptersFile(): string {
  return getSubDir('adapters.json')
}

export function getAdapterSessionsFile(): string {
  return getSubDir('adapter-sessions.json')
}

export function getHistoryFile(): string {
  return join(getDataDir(), 'history.jsonl')
}

export function getStatsCacheFile(): string {
  return join(getCacheDir(), 'stats-cache.json')
}

export function getChangelogCacheFile(): string {
  return join(getCacheDir(), 'changelog.md')
}

export function getCredentialsFile(): string {
  return join(getDataDir(), '.credentials.json')
}

export function getMagicDocsPromptFile(): string {
  return join(getDataDir(), 'magic-docs', 'prompt.md')
}

export function getTeamsDir(): string {
  return getSubDir('teams')
}

export function getTasksDir(): string {
  return getSubDir('tasks')
}

export function getSessionsDir(): string {
  return getSubDir('sessions')
}

export function getMcpNeedsAuthCacheFile(): string {
  return join(getCacheDir(), 'mcp-needs-auth-cache.json')
}

export function getUpdateLockFile(): string {
  return join(getDataDir(), '.update.lock')
}

export function getIdeDir(): string {
  return getSubDir('ide')
}

export function getTracesDir(): string {
  return getSubDir('traces')
}

export function getUsageDataDir(): string {
  return getSubDir('usage-data')
}

export function getLocalInstallerDir(): string {
  return getSubDir('local')
}

export function getShellSnapshotsDir(): string {
  return getSubDir('shell-snapshots')
}

export function getImDownloadsDir(): string {
  return getSubDir('im-downloads')
}

export function getCoWorkPluginsDir(): string {
  return getSubDir('cowork_plugins')
}

export function getProfileDir(): string {
  return getSubDir('profile')
}

export function getComputerUseConfigFile(): string {
  return getSubDir('computer-use-config.json')
}

// ─── 废弃兼容函数（供 Phase 2 过渡期使用） ────────────────────────────

/** @deprecated kimo 无用户级目录。返回 data/ 目录自身，待 Phase 3 删除调用方。 */
export function getUserConfigDir(): string {
  return getDataDir()
}

/** @deprecated kimo 无用户级目录。返回一个不存在的临时路径，扫描结果为 0。 */
export function getUserSkillsDir(): string {
  return join(getDataDir(), '.deprecated-user-skills')
}
