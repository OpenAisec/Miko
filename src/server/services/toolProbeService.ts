/**
 * Tool Probe Service —— 工具状态探测（已装/未装/版本），结果缓存到 data/tools/.status.json。
 *
 * 设计（[[工具生态-实施准备]] A3 修正）：
 *  - 不实时探（每次用都 spawn 太慢）；server 启动后**后台异步**探一次，不阻塞 banner。
 *  - 读视图（catalog 的 list/get）拿缓存 statusMap；缓存缺失则状态 = 未知（null）。
 *  - POST /api/catalog/probe 手动重探刷新。
 *  - .status.json 是缓存非真相源，删了能重建。
 *
 * 探测方式：跑工具 yaml 里的 check 命令（如 "ghidraRun --version"），exitCode===0 视为已装；
 * 顺手从 stdout/stderr 抓版本号。无 check 的工具不可探（installed 视为未知，不写缓存）。
 */

import { execa } from 'execa'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { which } from '../../utils/which.js'
import { getBuiltinToolsDir, getToolsDir, loadCatalog, type StatusMap, type ToolStatus } from './toolCatalogService.js'

const STATUS_FILE = '.status.json'
const USERPATHS_FILE = '.userpaths.json'
const PROBE_TIMEOUT_MS = 3_000

function statusFilePath(): string {
  return path.join(getToolsDir(), STATUS_FILE)
}

function userPathsFilePath(): string {
  return path.join(getToolsDir(), USERPATHS_FILE)
}

/** 用户为 requiresUserPath 工具配置的本机绝对路径（{ toolId: absPath }）。手动配、非自动生成。 */
export type UserPaths = Record<string, string>

/** 读用户路径配置；文件缺失/损坏返回空。 */
export async function readUserPaths(): Promise<UserPaths> {
  try {
    const text = await fs.readFile(userPathsFilePath(), 'utf-8')
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? (parsed as UserPaths) : {}
  } catch {
    return {}
  }
}

/** 写单个工具的用户路径（path 为空则清除该项）。 */
export async function setUserPath(toolId: string, absPath: string | null): Promise<void> {
  const current = await readUserPaths()
  if (absPath && absPath.trim()) {
    current[toolId] = absPath.trim()
  } else {
    delete current[toolId]
  }
  await fs.mkdir(getToolsDir(), { recursive: true })
  await fs.writeFile(userPathsFilePath(), JSON.stringify(current, null, 2), 'utf-8')
}

/** 从命令输出里抓第一个形如 1.2.3 / v11.0 的版本号；抓不到返回 undefined。 */
function extractVersion(text: string): string | undefined {
  const m = text.match(/\bv?(\d+\.\d+(?:\.\d+)?)/)
  return m ? m[1] : undefined
}

/**
 * 探一条工具：
 *  - 有 check：跑命令，exitCode===0=已装，顺手抓版本。
 *  - 无 check 但有 bin：用 which(bin) 做 PATH 存在性探测（比给每个工具瞎编 --version 稳，
 *    各工具版本 flag 语法不一，PATH 命中是最可靠的"装了没"信号）。
 *  - 两者都无：返回 null（不可探，状态未知）。
 */
/** 内置绿色二进制存放目录：<builtin_tools_dir>/bin/<platform>/。
 *  打包态指向 MSI 资源目录（只读），dev 态回退 data/tools/bin/<platform>/。 */
function bundledBinDir(): string {
  const platform = process.platform === 'win32' ? 'win' : process.platform === 'darwin' ? 'darwin' : 'linux'
  return path.join(getBuiltinToolsDir(), 'bin', platform)
}

/**
 * 查内置目录里有没有该工具二进制。命中返回文件路径，否则 null。
 *  - bundledEntry：yaml 显式声明的入口相对路径（相对 bin/<platform>/），用于解压成整目录的嵌套工具
 *    （如 radare2/bin/radare2.exe）。优先按它解析。
 *  - 否则回退：顶层扁平找 <bin>（win 下带 .exe 兜底），适配单文件工具（nuclei.exe）。
 */
async function findBundledBin(bin: string, bundledEntry?: string): Promise<string | null> {
  const dir = bundledBinDir()
  if (bundledEntry && bundledEntry.trim()) {
    const p = path.join(dir, bundledEntry.trim())
    try {
      const st = await fs.stat(p)
      if (st.isFile()) return p
    } catch {
      // 声明的入口不存在（该平台二进制未放入）→ 视为未命中
    }
    return null
  }
  const candidates = process.platform === 'win32' ? [`${bin}.exe`, bin] : [bin]
  for (const name of candidates) {
    const p = path.join(dir, name)
    try {
      const st = await fs.stat(p)
      if (st.isFile()) return p
    } catch {
      // try next
    }
  }
  return null
}

/**
 * 探一条工具：
 *  - bundled=true：优先查内置目录 data/tools/bin/<platform>/<bin>，命中即"已装"（随包发，绕过系统 PATH）；
 *    未命中再回退到下面的 check/PATH（用户也可能系统装了同名工具）。
 *  - 有 check：跑命令，exitCode===0=已装，顺手抓版本。
 *  - 无 check 但有 bin：用 which(bin) 做 PATH 存在性探测（比给每个工具瞎编 --version 稳，
 *    各工具版本 flag 语法不一，PATH 命中是最可靠的"装了没"信号）。
 *  - 都无：返回 null（不可探，状态未知）。
 */
async function probeOne(
  check: string | undefined,
  bin?: string,
  bundled?: boolean,
  requiresUserPath?: boolean,
  userPath?: string,
  bundledEntry?: string,
): Promise<ToolStatus | null> {
  if (bundled && bin && bin.trim()) {
    const found = await findBundledBin(bin.trim(), bundledEntry)
    // bundledPath 让 agent 拿到绝对路径调用（bin/<platform>/ 不在系统 PATH，裸命令会 not found）。
    if (found) return { installed: true, bundledPath: found }
    // 内置目录没有（二进制还没放入/该平台缺）→ 落到下面按系统装探测
  }
  // 第三态：用户配置本机路径（ghidra/IDA 等重型工具）。查路径存在性，不回退 PATH（它本就不在 PATH）。
  if (requiresUserPath) {
    if (userPath && userPath.trim()) {
      try {
        const st = await fs.stat(userPath.trim())
        return { installed: st.isFile() || st.isDirectory() }
      } catch {
        return { installed: false } // 配了但路径失效
      }
    }
    return { installed: false } // 需配置但未配
  }
  if (check && check.trim()) {
    try {
      const result = await execa(check, {
        shell: true,
        timeout: PROBE_TIMEOUT_MS,
        reject: false,
        stderr: 'pipe',
        stdout: 'pipe',
      })
      const installed = result.exitCode === 0
      const version = installed
        ? extractVersion(`${result.stdout ?? ''}\n${result.stderr ?? ''}`)
        : undefined
      return { installed, version }
    } catch {
      return { installed: false }
    }
  }
  if (bin && bin.trim()) {
    try {
      const found = await which(bin.trim())
      return { installed: !!found }
    } catch {
      return { installed: false }
    }
  }
  return null
}

/** 探全部工具（每条跑 check），写 .status.json，返回 statusMap。 */
export async function probeAll(): Promise<StatusMap> {
  const defs = await loadCatalog()
  const userPaths = await readUserPaths()
  const checkedAt = Date.now()
  const map: StatusMap = {}
  // 并发探测（工具间互不依赖）；超时各自 3s 兜底，整体不会卡死。
  await Promise.all(
    defs.map(async (d) => {
      const s = await probeOne(d.check, d.bin, d.bundled, d.requiresUserPath, userPaths[d.id], d.bundledEntry)
      if (s) map[d.id] = { ...s, checkedAt }
    }),
  )
  await writeStatus(map)
  return map
}

/** 读缓存 statusMap；文件缺失/损坏返回空（视为全未知）。 */
export async function readStatus(): Promise<StatusMap> {
  try {
    const text = await fs.readFile(statusFilePath(), 'utf-8')
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? (parsed as StatusMap) : {}
  } catch {
    return {}
  }
}

async function writeStatus(map: StatusMap): Promise<void> {
  try {
    await fs.mkdir(getToolsDir(), { recursive: true })
    await fs.writeFile(statusFilePath(), JSON.stringify(map, null, 2), 'utf-8')
  } catch (err) {
    console.warn(`[toolProbe] failed to write status cache: ${err instanceof Error ? err.message : String(err)}`)
  }
}

/** server 启动后调用：后台异步探一遍，不阻塞启动、不抛错。 */
export function probeAllInBackground(): void {
  void probeAll().catch((err) => {
    console.warn(`[toolProbe] background probe failed: ${err instanceof Error ? err.message : String(err)}`)
  })
}
