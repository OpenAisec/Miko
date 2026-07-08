/**
 * Tool Catalog Service —— 工具台账加载器（工具生态第三类资源，与 agent/skill 平级）。
 *
 * 真相源：data/tools/*.yaml，一工具一文件、平铺、文件名 = 工具 id（[[工具生态-实施准备]] A2）。
 * 本服务只管「定义」：扫目录 → 解析 → 内存索引 + 分层切片（list_categories / list_tools / get_tool）。
 * 「状态」（已装/未装）由 toolProbeService 管，作为可选 statusMap 注入到视图函数——本服务不跑子进程、不碰探测，
 * 保持纯加载、可单测。
 *
 * 分层切片对应 catalog-mcp 三方法（省 token，见方案 §五）：
 *   listCategories → Tier1 目录（每类计数+可用数）
 *   listTools(cat) → Tier2 章节（名+状态+short_description）
 *   getTool(id)    → Tier3 详情（整条 + 状态）
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { getDataDir } from '../../utils/kimoPaths.js'
import { parseYaml } from '../../utils/yaml.js'
import { BUILTIN_CATEGORIES } from './categories.js'

// ─── Types ───────────────────────────────────────────────────

export type ToolInvoke = 'cli' | 'mcp'

/** 一条工具台账（= 一个 data/tools/<id>.yaml）。 */
export type ToolDef = {
  id: string
  category: string
  name: string
  shortDescription: string
  description?: string
  invoke: ToolInvoke
  /** 探测命令（决定 ✅/❌）；缺省时若有 bin 则回退到 PATH 存在性检测。 */
  check?: string
  /** 工具的可执行名（如 sqlmap/ghidra）；无 check 时用 which(bin) 做 PATH 探测，比 --version 跨工具更稳。 */
  bin?: string
  /** 起手式（Tier3 给 agent）。 */
  usage?: string
  installHint?: string
  /** invoke=mcp 时填，复用 .mcp.json 已配置的 server 名。 */
  mcpServer?: string
  /** 内置随包发（受 PROTECTED_TOOLS 保护）；用户自加省略。 */
  builtin?: boolean
  /** 绿色二进制随 kimo 分发：探测优先查 data/tools/bin/<platform>/<bin>，命中即"已装"（无需系统 PATH）。 */
  bundled?: boolean
  /**
   * bundled 工具的入口相对路径（相对 data/tools/bin/<platform>/）。
   * 解压成整目录的工具（如 radare2 → radare2/bin/radare2.exe）用它显式指明入口 exe，
   * 否则加载器只会在顶层扁平找 <bin>.exe 而漏掉嵌套二进制。单文件工具（nuclei.exe）省略此字段。
   */
  bundledEntry?: string
  /** 靠用户配置本机路径（重型/商业工具如 ghidra/IDA）：探测查 .userpaths.json 里用户填的绝对路径，不内置、不查 PATH。 */
  requiresUserPath?: boolean
  /** requiresUserPath 时给用户的路径填写提示（如"ghidra 的 support/analyzeHeadless.bat"）。 */
  pathHint?: string
}

/** 探测状态（toolProbeService 产出，作为视图参数注入）。 */
export type ToolStatus = {
  installed: boolean
  version?: string
  checkedAt?: number
  /** bundled 命中时：探测到的二进制绝对路径。内置目录不在系统 PATH，agent 须用此全路径调。 */
  bundledPath?: string
}
export type StatusMap = Record<string, ToolStatus>

/** Tier1 目录项。 */
export type CategorySummary = {
  id: string
  label: string
  total: number
  available: number
}

/** Tier2 列表项（精简）。 */
export type ToolListItem = {
  id: string
  name: string
  category: string
  shortDescription: string
  invoke: ToolInvoke
  installed: boolean | null // null = 状态未知（未探测）
}

// ─── 加载 ────────────────────────────────────────────────────

const TOOLS_DIR = 'tools'

/**
 * 可写工具目录：data/tools（探测缓存 .status.json / 用户路径 .userpaths.json 落这里）。
 * dev 态也是台账 yaml 的所在。
 */
export function getToolsDir(): string {
  return path.join(getDataDir(), TOOLS_DIR)
}

/**
 * 只读内置台账目录：优先 KIMO_BUILTIN_TOOLS_DIR（打包态由 Tauri 指向 MSI 资源目录里的
 * tools/，含 yaml + bin 二进制），回退可写 data/tools（dev 态）。
 * 台账 yaml 扫描与 bundled 二进制定位走这里；可写状态文件仍走 getToolsDir()。
 */
export function getBuiltinToolsDir(): string {
  const envDir = process.env.KIMO_BUILTIN_TOOLS_DIR
  if (envDir && envDir.trim()) {
    return envDir.trim()
  }
  return getToolsDir()
}

let cache: ToolDef[] | null = null

/** 清缓存（文件增删/测试用）。 */
export function clearCatalogCache(): void {
  cache = null
}

/** 把一条 yaml 原始对象规整成 ToolDef；非法（缺 id/category）返回 null 并告警，不抛。 */
function coerceToolDef(raw: unknown, fileId: string): ToolDef | null {
  // 防御：YAML 的 `...`/`---` 是文档分隔符，裸写在值里会让 parser 返回多文档数组。
  // 取第一个对象元素并告警，避免 stray multi-doc 静默产出残缺记录。
  if (Array.isArray(raw)) {
    console.warn(`[toolCatalog] ${fileId}.yaml parsed as multi-document (stray '...'/'---'? quote such values); using first doc`)
    raw = raw.find((d) => d && typeof d === 'object' && !Array.isArray(d)) ?? null
  }
  if (!raw || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  const id = typeof o.id === 'string' && o.id.trim() ? o.id.trim() : fileId
  const category = typeof o.category === 'string' ? o.category.trim() : ''
  if (!category) {
    console.warn(`[toolCatalog] skip ${fileId}.yaml: missing category`)
    return null
  }
  const invoke: ToolInvoke = o.invoke === 'mcp' ? 'mcp' : 'cli'
  const shortDescription =
    typeof o.short_description === 'string'
      ? o.short_description
      : typeof o.description === 'string'
        ? o.description.split('\n')[0]!.slice(0, 100)
        : ''
  return {
    id,
    category,
    name: typeof o.name === 'string' ? o.name : id,
    shortDescription,
    description: typeof o.description === 'string' ? o.description : undefined,
    invoke,
    check: typeof o.check === 'string' ? o.check : undefined,
    bin: typeof o.bin === 'string' ? o.bin : undefined,
    usage: typeof o.usage === 'string' ? o.usage : undefined,
    installHint: typeof o.installHint === 'string' ? o.installHint : undefined,
    mcpServer: typeof o.mcpServer === 'string' ? o.mcpServer : undefined,
    builtin: o.builtin === true || undefined,
    bundled: o.bundled === true || undefined,
    bundledEntry: typeof o.bundledEntry === 'string' ? o.bundledEntry : undefined,
    requiresUserPath: o.requiresUserPath === true || undefined,
    pathHint: typeof o.pathHint === 'string' ? o.pathHint : undefined,
  }
}

/** 扫 builtin tools dir *.yaml → 解析 → 内存索引（缓存）。目录不存在视为空台账。 */
export async function loadCatalog(): Promise<ToolDef[]> {
  if (cache) return cache
  const dir = getBuiltinToolsDir()
  let entries: string[]
  try {
    entries = await fs.readdir(dir)
  } catch {
    cache = []
    return cache
  }
  const yamlFiles = entries.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
  const defs: ToolDef[] = []
  for (const file of yamlFiles) {
    const fileId = file.replace(/\.ya?ml$/, '')
    try {
      const text = await fs.readFile(path.join(dir, file), 'utf-8')
      const def = coerceToolDef(parseYaml(text), fileId)
      if (def) defs.push(def)
    } catch (err) {
      console.warn(`[toolCatalog] failed to parse ${file}: ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  defs.sort((a, b) => a.id.localeCompare(b.id))
  cache = defs
  return cache
}

// ─── 切片（catalog-mcp 三方法 + UI 全量） ──────────────────────

function isInstalled(status: StatusMap | undefined, id: string): boolean | null {
  if (!status) return null
  const s = status[id]
  return s ? s.installed : null
}

/** Tier1：按 category 聚合（只列有工具的类 + 顺序遵循 BUILTIN_CATEGORIES，未知类排后）。 */
export async function listCategories(status?: StatusMap): Promise<CategorySummary[]> {
  const defs = await loadCatalog()
  const order = new Map(BUILTIN_CATEGORIES.map((c, i) => [c.id, i]))
  const labelOf = new Map(BUILTIN_CATEGORIES.map((c) => [c.id, c.label]))
  const byCat = new Map<string, ToolDef[]>()
  for (const d of defs) {
    const arr = byCat.get(d.category) ?? []
    arr.push(d)
    byCat.set(d.category, arr)
  }
  const summaries: CategorySummary[] = []
  for (const [id, tools] of byCat) {
    summaries.push({
      id,
      label: labelOf.get(id) ?? id,
      total: tools.length,
      available: status ? tools.filter((t) => isInstalled(status, t.id) === true).length : 0,
    })
  }
  summaries.sort((a, b) => (order.get(a.id) ?? 999) - (order.get(b.id) ?? 999) || a.id.localeCompare(b.id))
  return summaries
}

/** Tier2：某 category 下的精简列表。 */
export async function listTools(category: string, status?: StatusMap): Promise<ToolListItem[]> {
  const defs = await loadCatalog()
  return defs
    .filter((d) => d.category === category)
    .map((d) => ({
      id: d.id,
      name: d.name,
      category: d.category,
      shortDescription: d.shortDescription,
      invoke: d.invoke,
      installed: isInstalled(status, d.id),
    }))
}

/** Tier3：单工具整条 + 状态。未找到返回 null。 */
export async function getTool(
  id: string,
  status?: StatusMap,
): Promise<(ToolDef & { installed: boolean | null; version?: string; bundledPath?: string }) | null> {
  const defs = await loadCatalog()
  const def = defs.find((d) => d.id === id)
  if (!def) return null
  const s = status?.[id]
  return { ...def, installed: s ? s.installed : null, version: s?.version, bundledPath: s?.bundledPath }
}

/** UI 全量：所有工具 + 状态（前端 Tools tab 用，不分层）。 */
export async function getAll(
  status?: StatusMap,
): Promise<Array<ToolDef & { installed: boolean | null; version?: string; bundledPath?: string }>> {
  const defs = await loadCatalog()
  return defs.map((d) => {
    const s = status?.[d.id]
    return { ...d, installed: s ? s.installed : null, version: s?.version, bundledPath: s?.bundledPath }
  })
}
