/**
 * Skills REST API
 *
 * GET /api/skills              — List all installed skills (metadata only)
 * GET /api/skills/detail       — Full skill data (tree + files)
 *       ?source=user&name=xxx
 */

import * as path from 'path'
import * as fs from 'fs/promises'
import { existsSync, mkdirSync, writeFileSync } from 'fs'
import { parseFrontmatter } from '../../utils/frontmatterParser.js'
import { getCwd } from '../../utils/cwd.js'
import {
  getSkillsDir,
  getUserSkillsDir,
} from '../../utils/kimoPaths.js'
import { clearInstalledPluginsCache } from '../../utils/plugins/installedPluginsManager.js'
import { clearPluginCache, loadAllPlugins, loadAllPluginsCacheOnly } from '../../utils/plugins/pluginLoader.js'
import { getSkillDirCommands } from '../../skills/loadSkillsDir.js'
import { isProtectedSkill } from '../services/protectedResources.js'
import { BUILTIN_CATEGORIES } from '../services/categories.js'
import { resetSettingsCache } from '../../utils/settings/settingsCache.js'
import type { LoadedPlugin } from '../../types/plugin.js'
import { ApiError, errorResponse } from '../middleware/errorHandler.js'

// ─── Types ───────────────────────────────────────────────────────────────────

type SkillMeta = {
  name: string
  displayName?: string
  description: string
  source: 'project' | 'plugin'
  userInvocable: boolean
  version?: string
  contentLength: number
  hasDirectory: boolean
  pluginName?: string
  /** 内置受保护 skill（A 档保护）—— 前端据此隐藏删除入口，删除 API 亦兜底拒绝。 */
  protected?: boolean
  /** 领域分类（web/audit/asset/mobile/binary/redteam/forensics/cloud/custom）。
   *  读 frontmatter.category，缺失兜底 'custom'。前端据此分组展示。 */
  category: string
}

type SkillSource = SkillMeta['source']

type FileTreeNode = {
  name: string
  path: string
  type: 'file' | 'directory'
  children?: FileTreeNode[]
}

type SkillFile = {
  path: string
  content: string
  language: string
  frontmatter?: Record<string, unknown>
  body?: string
  isEntry?: boolean
}

// ─── Constants ───────────────────────────────────────────────────────────────

const MAX_FILES = 50
const MAX_FILE_SIZE = 100 * 1024 // 100 KB
const SKIP_ENTRIES = new Set(['node_modules', '.git', '__pycache__', '.DS_Store'])

const LANG_MAP: Record<string, string> = {
  md: 'markdown', ts: 'typescript', tsx: 'typescript',
  js: 'javascript', jsx: 'javascript', json: 'json',
  yaml: 'yaml', yml: 'yaml', sh: 'bash', bash: 'bash',
  py: 'python', toml: 'toml', css: 'css', html: 'html',
  txt: 'text', xml: 'xml', sql: 'sql', rs: 'rust', go: 'go',
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function detectLanguage(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() || ''
  return LANG_MAP[ext] || 'text'
}

function normalizeFrontmatter(content: string, sourcePath?: string): {
  frontmatter: Record<string, unknown>
  body: string
} {
  const parsed = parseFrontmatter(content, sourcePath)
  return {
    frontmatter: parsed.frontmatter as Record<string, unknown>,
    body: parsed.content,
  }
}

function getRequestedCwd(url: URL): string {
  return url.searchParams.get('cwd') || getCwd()
}

async function loadSkillMeta(
  skillDir: string,
  skillName: string,
  source: SkillSource,
  pluginName?: string,
): Promise<SkillMeta | null> {
  const skillFile = path.join(skillDir, 'SKILL.md')
  try {
    const raw = await fs.readFile(skillFile, 'utf-8')
    const { frontmatter, body } = normalizeFrontmatter(raw, skillFile)

    const description =
      (frontmatter.description as string) ||
      body
        .split('\n')
        .find((l) => l.trim().length > 0)
        ?.trim() ||
      'No description'

    return {
      name: skillName,
      displayName: (frontmatter.name as string) || undefined,
      description,
      source,
      userInvocable: frontmatter['user-invocable'] !== false,
      version: frontmatter.version != null ? String(frontmatter.version) : undefined,
      contentLength: raw.length,
      hasDirectory: true,
      pluginName,
      protected: isProtectedSkill(skillName) || undefined,
      category:
        typeof frontmatter.category === 'string' && frontmatter.category.trim()
          ? frontmatter.category.trim()
          : 'custom',
    }
  } catch {
    return null
  }
}

async function buildFileTree(
  dirPath: string,
): Promise<{ tree: FileTreeNode[]; files: SkillFile[] }> {
  const tree: FileTreeNode[] = []
  const files: SkillFile[] = []
  let fileCount = 0

  async function walk(currentPath: string, nodes: FileTreeNode[]) {
    if (fileCount >= MAX_FILES) return

    let entries: import('fs').Dirent[]
    try {
      entries = await fs.readdir(currentPath, { withFileTypes: true })
    } catch {
      return
    }

    // directories first, then alphabetical
    entries.sort((a, b) => {
      if (a.isDirectory() !== b.isDirectory()) return a.isDirectory() ? -1 : 1
      return a.name.localeCompare(b.name)
    })

    for (const entry of entries) {
      if (fileCount >= MAX_FILES) break
      if (SKIP_ENTRIES.has(entry.name) || entry.name.startsWith('.')) continue

      const fullPath = path.join(currentPath, entry.name)
      const relPath = path.relative(dirPath, fullPath)

      if (entry.isDirectory()) {
        const node: FileTreeNode = {
          name: entry.name,
          path: relPath,
          type: 'directory',
          children: [],
        }
        nodes.push(node)
        await walk(fullPath, node.children!)
        if (node.children!.length === 0) delete node.children
      } else if (entry.isFile()) {
        nodes.push({ name: entry.name, path: relPath, type: 'file' })

        try {
          const stat = await fs.stat(fullPath)
          if (stat.size <= MAX_FILE_SIZE) {
            const content = await fs.readFile(fullPath, 'utf-8')
            const language = detectLanguage(entry.name)
            const isEntry = relPath === 'SKILL.md'

            if (isEntry && language === 'markdown') {
              const { frontmatter, body } = normalizeFrontmatter(content, fullPath)
              files.push({
                path: relPath,
                content: body,
                body,
                frontmatter,
                language,
                isEntry: true,
              })
            } else {
              files.push({
                path: relPath,
                content,
                language,
                isEntry: false,
              })
            }
            fileCount++
          }
        } catch {
          // skip unreadable files
        }
      }
    }
  }

  await walk(dirPath, tree)
  return { tree, files }
}

async function collectSkillsFromRoots(
  skillRoots: string[],
  source: SkillSource,
): Promise<SkillMeta[]> {
  const skills: SkillMeta[] = []
  const seenNames = new Set<string>()

  for (const root of skillRoots) {
    let entries: import('fs').Dirent[]
    try {
      entries = await fs.readdir(root, { withFileTypes: true })
    } catch {
      continue
    }

    for (const entry of entries) {
      if (
        (!entry.isDirectory() && !entry.isSymbolicLink()) ||
        entry.name.startsWith('.') ||
        seenNames.has(entry.name)
      ) {
        continue
      }

      const meta = await loadSkillMeta(path.join(root, entry.name), entry.name, source)
      if (!meta) continue

      seenNames.add(entry.name)
      skills.push(meta)
    }
  }

  return skills
}

async function resolveSkillDir(
  source: SkillSource,
  name: string,
  cwd: string,
): Promise<string | null> {
  const skillRoots =
    source === 'user'
      ? [getUserSkillsDir()]
      : source === 'project'
        ? [getSkillsDir()]
        : []

  for (const root of skillRoots) {
    const skillDir = path.join(root, name)
    try {
      const stat = await fs.stat(skillDir)
      if (stat.isDirectory()) {
        return skillDir
      }
    } catch {
      // Try the next candidate root.
    }
  }

  return null
}

type PluginSkillLocation = {
  skillDir: string
  pluginName: string
}

export type SkillSlashCommand = {
  name: string
  description: string
  argumentHint?: string
}

async function collectLegacySlashCommands(cwd: string): Promise<SkillSlashCommand[]> {
  const commands = await getSkillDirCommands(cwd)
  return commands
    .filter((command) =>
      command.type === 'prompt' &&
      command.loadedFrom === 'commands_DEPRECATED' &&
      command.userInvocable !== false &&
      !command.isHidden)
    .map((command) => ({
      name: command.name,
      description: command.description || '',
      ...(command.argumentHint ? { argumentHint: command.argumentHint } : {}),
    }))
}

function buildPluginSkillName(pluginName: string, skillDir: string): string {
  return `${pluginName}:${path.basename(skillDir)}`
}

async function collectPluginSkillDirectories(): Promise<Map<string, PluginSkillLocation>> {
  const locations = new Map<string, PluginSkillLocation>()

  let enabledPlugins: LoadedPlugin[]
  try {
    resetSettingsCache()
    clearInstalledPluginsCache()
    clearPluginCache('skills-api-external-plugin-state')

    const result = await loadAllPluginsCacheOnly()
    if (result.errors.some((error) => error.type === 'plugin-cache-miss')) {
      enabledPlugins = (await loadAllPlugins()).enabled
    } else {
      enabledPlugins = result.enabled
    }
  } catch {
    return locations
  }

  for (const plugin of enabledPlugins) {
    const candidateRoots = [plugin.skillsPath, ...(plugin.skillsPaths ?? [])]

    for (const root of candidateRoots) {
      if (!root) continue

      const directSkillFile = path.join(root, 'SKILL.md')
      try {
        const stat = await fs.stat(directSkillFile)
        if (stat.isFile()) {
          const name = buildPluginSkillName(plugin.name, root)
          if (!locations.has(name)) {
            locations.set(name, { skillDir: root, pluginName: plugin.name })
          }
          continue
        }
      } catch {
        // Fall through and inspect as a skills root.
      }

      let entries: import('fs').Dirent[]
      try {
        entries = await fs.readdir(root, { withFileTypes: true })
      } catch {
        continue
      }

      for (const entry of entries) {
        if (!entry.isDirectory() && !entry.isSymbolicLink()) continue

        const skillDir = path.join(root, entry.name)
        const skillFile = path.join(skillDir, 'SKILL.md')
        try {
          const stat = await fs.stat(skillFile)
          if (!stat.isFile()) continue
        } catch {
          continue
        }

        const name = buildPluginSkillName(plugin.name, skillDir)
        if (!locations.has(name)) {
          locations.set(name, { skillDir, pluginName: plugin.name })
        }
      }
    }
  }

  return locations
}

async function collectPluginSkills(): Promise<SkillMeta[]> {
  const locations = await collectPluginSkillDirectories()
  const skills: SkillMeta[] = []

  for (const [name, location] of locations) {
    const meta = await loadSkillMeta(
      location.skillDir,
      name,
      'plugin',
      location.pluginName,
    )
    if (meta) {
      skills.push(meta)
    }
  }

  return skills
}

async function collectAllSkills(cwd?: string, skillsDir?: string): Promise<SkillMeta[]> {
  const projectRoots = skillsDir ? [skillsDir] : [getSkillsDir()]

  const [projectSkills, pluginSkills] = await Promise.all([
    collectSkillsFromRoots(projectRoots, 'project'),
    collectPluginSkills(),
  ])

  const skills = [...projectSkills, ...pluginSkills]
  skills.sort((a, b) => a.name.localeCompare(b.name))
  return skills
}

export async function listSkillSlashCommands(cwd?: string): Promise<SkillSlashCommand[]> {
  const requestedCwd = cwd || getCwd()
  const [skills, legacyCommands] = await Promise.all([
    collectAllSkills(requestedCwd),
    collectLegacySlashCommands(requestedCwd),
  ])

  const byName = new Map<string, SkillSlashCommand>()

  for (const skill of skills) {
    if (!skill.userInvocable) continue
    byName.set(skill.name, {
      name: skill.name,
      description: skill.description || '',
    })
  }

  for (const command of legacyCommands) {
    if (!byName.has(command.name)) {
      byName.set(command.name, command)
    }
  }

  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name))
}

// ─── Skills Scan ─────────────────────────────────────────────────────────────

type SkillScanFile = { name: string; description: string; transport: string }

async function scanSkillsSource(req: Request): Promise<Response> {
  const body = await req.json().catch(() => { throw ApiError.badRequest('Invalid JSON body') }) as Record<string, unknown>
  const sourcePath = typeof body.path === 'string' ? body.path : ''
  if (!sourcePath) throw ApiError.badRequest('Missing "path"')

  const skills: SkillScanFile[] = []
  const skillsDir = path.join(sourcePath, 'skills')
  try {
    const entries = await fs.readdir(skillsDir, { withFileTypes: true })
    const dirs = entries.filter(e => e.isDirectory() && !e.name.startsWith('.'))
    for (const dir of dirs) {
      try {
        await fs.stat(path.join(skillsDir, dir.name, 'SKILL.md'))
        skills.push({ name: dir.name, description: 'skill', transport: 'markdown' })
      } catch { /* no SKILL.md */ }
    }
    const mdFiles = entries.filter(e => e.isFile() && e.name.endsWith('.md'))
    for (const f of mdFiles) {
      if (f.name === 'SKILL.md') continue
      skills.push({ name: f.name, description: '', transport: 'markdown' })
    }
  } catch { /* no skills dir */ }

  const results = skills.length > 0
    ? [{ name: 'skills/', sourceFile: skillsDir, servers: skills }]
    : []

  return Response.json({ sourcePath, results })
}

// ─── Skills Import ───────────────────────────────────────────────────────────

async function importSkills(req: Request): Promise<Response> {
  const body = await req.json().catch(() => { throw ApiError.badRequest('Invalid JSON body') }) as Record<string, unknown>
  const sourcePath = typeof body.sourcePath === 'string' ? body.sourcePath : ''
  const targetPath = typeof body.targetPath === 'string' ? body.targetPath : ''
  const files = Array.isArray(body.files) ? body.files as string[] : []

  if (!sourcePath || !targetPath || files.length === 0) {
    throw ApiError.badRequest('Missing "sourcePath", "targetPath" or "files"')
  }

  if (!existsSync(targetPath)) {
    mkdirSync(targetPath, { recursive: true })
  }

  const imported: string[] = []
  const errors: string[] = []

  for (const file of files) {
    try {
      const skillDir = path.join(sourcePath, file)
      const skillFile = path.join(skillDir, 'SKILL.md')
      try {
        await fs.stat(skillFile)
        const destDir = path.join(targetPath, file)
        if (!existsSync(destDir)) mkdirSync(destDir, { recursive: true })
        const content = await fs.readFile(skillFile, 'utf-8')
        writeFileSync(path.join(destDir, 'SKILL.md'), content, 'utf-8')
        imported.push(file)
      } catch {
        const src = path.join(sourcePath, file)
        const content = await fs.readFile(src, 'utf-8')
        writeFileSync(path.join(targetPath, file), content, 'utf-8')
        imported.push(file)
      }
    } catch (e) {
      errors.push(`${file}: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  return Response.json({ imported, errors })
}

// ─── Delete ───────────────────────────────────────────────────────────────────

async function deleteSkill(rawName: string, url: URL): Promise<Response> {
  // URL decode（Bun 的 url.pathname 不自动解码中文字符）
  const name = decodeURIComponent(rawName)
  // 防路径穿越
  if (name.includes('..') || name.includes('/') || name.includes('\\') || name.includes(':')) {
    throw ApiError.badRequest('Invalid skill name')
  }

  // 只允许删除 project 来源的 skill
  const source = url.searchParams.get('source')
  if (source !== 'project') {
    throw ApiError.badRequest('Only project skills can be deleted')
  }

  // 内置 skill 不可删（A 档保护）。data/skills 里的核心 skill 会被判成 project 来源，
  // 仅靠上面的 source 检查拦不住——名单守卫在此兜住。
  if (isProtectedSkill(name)) {
    throw ApiError.badRequest(`内置 Skill 不可删除：${name}`)
  }

  // 检查目录是否存在
  const skillsDir = getSkillsDir()
  const dirPath = path.join(skillsDir, name)
  const { existsSync, statSync } = await import('fs')
  if (!existsSync(dirPath) || !statSync(dirPath).isDirectory()) {
    throw ApiError.notFound(`Skill not found: ${name}`)
  }

  // 递归删除目录
  const { rmSync } = await import('fs')
  rmSync(dirPath, { recursive: true, force: true })

  // 清空缓存
  const { clearInstalledPluginsCache } = await import('../../utils/plugins/installedPluginsManager.js')
  clearInstalledPluginsCache()

  return Response.json({ ok: true })
}

// ─── Update category ────────────────────────────────────────────────────────

/**
 * PATCH /api/skills/:name/category  body { category }
 * 改写 project 来源 skill 的 SKILL.md frontmatter category 字段。
 * 逐行编辑（保留其余内容原样）：有 category 行则替换，无则在首个 --- 后插入。
 */
async function updateSkillCategory(rawName: string, req: Request): Promise<Response> {
  const name = decodeURIComponent(rawName)
  if (name.includes('..') || name.includes('/') || name.includes('\\') || name.includes(':')) {
    throw ApiError.badRequest('Invalid skill name')
  }

  const body = (await req.json().catch(() => {
    throw ApiError.badRequest('Invalid JSON body')
  })) as Record<string, unknown>
  const category = typeof body.category === 'string' ? body.category.trim() : ''
  if (!category) throw ApiError.badRequest('Missing "category"')
  if (!BUILTIN_CATEGORIES.some((c) => c.id === category)) {
    throw ApiError.badRequest(`Unknown category: ${category}`)
  }

  const skillFile = path.join(getSkillsDir(), name, 'SKILL.md')
  if (!existsSync(skillFile)) {
    throw ApiError.notFound(`Skill not found: ${name}`)
  }

  const raw = await fs.readFile(skillFile, 'utf-8')
  const nl = raw.includes('\r\n') ? '\r\n' : '\n'
  const lines = raw.split(/\r?\n/)

  // 找 frontmatter 边界（首行须为 ---，第二个 --- 为闭合）
  if (lines[0]?.trim() !== '---') {
    throw ApiError.badRequest('SKILL.md has no frontmatter')
  }
  let closeIdx = -1
  for (let i = 1; i < lines.length; i++) {
    if (lines[i]?.trim() === '---') {
      closeIdx = i
      break
    }
  }
  if (closeIdx === -1) throw ApiError.badRequest('SKILL.md frontmatter not closed')

  // 在 frontmatter 区间内找 category 行
  let catIdx = -1
  for (let i = 1; i < closeIdx; i++) {
    if (/^category:/.test(lines[i] ?? '')) {
      catIdx = i
      break
    }
  }
  if (catIdx !== -1) {
    lines[catIdx] = `category: ${category}`
  } else {
    lines.splice(1, 0, `category: ${category}`)
  }

  writeFileSync(skillFile, lines.join(nl), 'utf-8')
  return Response.json({ ok: true, name, category })
}

// ─── Router ──────────────────────────────────────────────────────────────────

export async function handleSkillsApi(
  req: Request,
  url: URL,
  segments: string[],
): Promise<Response> {
  try {
    const sub = segments[2]

    if (req.method === 'POST' && sub === 'scan-source') {
      return await scanSkillsSource(req)
    }

    if (req.method === 'POST' && sub === 'import') {
      return await importSkills(req)
    }

    // PATCH /api/skills/:name/category — 改写 skill 分类
    if (req.method === 'PATCH' && sub && segments[3] === 'category') {
      return await updateSkillCategory(sub, req)
    }

    // DELETE /api/skills/:name — 删除用户创建的 skill
    if (req.method === 'DELETE' && sub && !['scan-source', 'import', 'detail'].includes(sub)) {
      return await deleteSkill(sub, url)
    }

    if (req.method !== 'GET') {
      throw new ApiError(405, `Method ${req.method} not allowed`, 'METHOD_NOT_ALLOWED')
    }

    switch (sub) {
      case undefined:
        return await listSkills(url)
      case 'detail':
        return await getSkillDetail(url)
      default:
        throw ApiError.notFound(`Unknown skills endpoint: ${sub}`)
    }
  } catch (error) {
    return errorResponse(error)
  }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async function listSkills(url: URL): Promise<Response> {
  const cwd = getRequestedCwd(url)
  const skillsDir = url.searchParams.get('skillsDir') || undefined
  const skills = await collectAllSkills(cwd, skillsDir)
  return Response.json({ skills })
}

async function getSkillDetail(url: URL): Promise<Response> {
  const source = url.searchParams.get('source')
  const name = url.searchParams.get('name')
  const skillsDir = url.searchParams.get('skillsDir')

  if (!source || !name) {
    throw ApiError.badRequest('Missing required query parameters: source, name')
  }

  // Prevent path traversal
  if (name.includes('..') || name.includes('/') || name.includes('\\')) {
    throw ApiError.badRequest('Invalid skill name')
  }

  if (source !== 'user' && source !== 'project' && source !== 'plugin') {
    throw ApiError.badRequest(`Unsupported source: ${source}`)
  }

  const cwd = getRequestedCwd(url)

  // If skillsDir is provided, check it first for the skill directory
  if (skillsDir) {
    const candidate = path.join(skillsDir, name)
    try {
      const stat = await fs.stat(candidate)
      if (stat.isDirectory()) {
        const meta = await loadSkillMeta(candidate, name, 'project')
        if (meta) {
          const { tree, files } = await buildFileTree(candidate)
          return Response.json({ detail: { meta, tree, files, skillRoot: candidate } })
        }
      }
    } catch { /* not found in skillsDir, fall through */ }
  }

  const pluginLocations =
    source === 'plugin' ? await collectPluginSkillDirectories() : null

  const pluginLocation = pluginLocations?.get(name)
  const skillDir =
    source === 'plugin'
      ? pluginLocation?.skillDir ?? null
      : await resolveSkillDir(source, name, cwd)

  if (!skillDir) {
    throw ApiError.notFound(`Skill not found: ${name}`)
  }

  const meta = await loadSkillMeta(
    skillDir,
    name,
    source,
    pluginLocation?.pluginName,
  )
  if (!meta) {
    throw ApiError.notFound(`Skill missing SKILL.md: ${name}`)
  }

  const { tree, files } = await buildFileTree(skillDir)

  return Response.json({
    detail: { meta, tree, files, skillRoot: skillDir },
  })
}
