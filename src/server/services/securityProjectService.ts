/**
 * Security Project Service — 安全测试项目的 CRUD 与 Blackboard 持久化
 *
 * 项目数据存储在 data/security/ 目录下，与会话数据完全独立。
 * 每个项目包含：元信息、Blackboard（Facts/Intents/Hints）、发现汇总、关联会话。
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { getDataDir } from '../../utils/kimoPaths.js'
import { ApiError } from '../middleware/errorHandler.js'
import { readRecoverableJsonFile } from './recoverableJsonFile.js'
import type { Blackboard, Fact, Intent, Hint } from '../../agent/blackboard.js'
import { extractNodes } from './findingsExtractionService.js'
import type { ExploreNodeType, ExplorePhase, PriorNode } from './findingsExtractionService.js'
import * as boardStore from './boardStore.js'
// 分类常量已抽到共享模块（project/agent/skill/tool 四类资源共用）。
// re-export 保持本模块既有引用方（API/测试）的 import 路径不变。
import { BUILTIN_CATEGORIES, type CategoryDef, type ProjectCategory } from './categories.js'
export { BUILTIN_CATEGORIES }
export type { CategoryDef, ProjectCategory }

// ─── Types ───────────────────────────────────────────────────

export type ProjectPriority = 'P0' | 'P1' | 'P2' | 'P3' | 'P4'

export type ProjectStatus = 'active' | 'paused' | 'completed'

export type ProjectMeta = {
  id: string
  name: string
  target: string
  priority: ProjectPriority
  status: ProjectStatus
  goal: string
  /** 分类 id：内置（web/audit/…/custom）或自定义分类 id。 */
  category: string
  tags?: string[]
  sessionIds: string[]
  findingCount?: number
  createdAt: number
  updatedAt: number
}

export type ProjectFinding = {
  id: string
  title: string
  detail: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'unverified' | 'verified' | 'false_positive'
  location?: string
  evidence?: string
  sessionId: string
  intentId: string
  createdAt: number
}

export type SecurityProject = {
  meta: ProjectMeta
  board: Blackboard
  findings: ProjectFinding[]
}

/** intent 节点在黑板图里的状态（驱动调度循环）。 */
export type IntentGraphStatus = 'open' | 'running' | 'done' | 'failed'

/** 探索节点（统一模型）：D2 提炼与真黑板都产出这种节点，前端用同一棵树渲染。 */
export type ExploreNode = {
  id: string
  type: ExploreNodeType
  title: string
  parentId?: string
  phase?: ExplorePhase
  sessionId: string
  createdAt: number
  // 三槽：过程 / 证据 / 结论
  process?: string
  evidence?: string
  result?: string
  // type 相关可选字段
  assetKind?: string
  detail?: string
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status?: string
  location?: string
  payload?: string
  flag?: string
  // ── 黑板图语义（仅 intent 用，驱动调度循环）──
  /** open=待探, running=worker 探索中, done=探完(toFactId 指向产出), failed=探死 */
  graphStatus?: IntentGraphStatus
  /** 认领该 intent 的 worker 标识（防重复派） */
  claimedBy?: string
  /** 该 intent 从哪些 fact 派生（"为什么探这个"） */
  fromFactIds?: string[]
  /** 探完产出的 fact 节点 id（done 的标志） */
  toFactId?: string
  /** 产出该节点的探索子 agent id（路 A：探索树深链到 subagents/agent-{agentId}.jsonl） */
  agentId?: string
}

/** 用户随时注入的指导，下一轮被 worker 读到。 */
export type BoardHint = {
  id: string
  content: string
  createdAt: number
}

/** 黑板图快照：导给 worker 的整张图（worker 只读这个，不碰文件）。 */
export type BoardGraph = {
  goal: string
  target: string
  nodes: ExploreNode[]
  hints: BoardHint[]
}

/** 关联会话的真实摘要（D1：忠实展示会话，不再正则刮取伪造 board）。 */
export type SessionSummary = {
  sessionId: string
  title: string
  /** 工具调用次数（渗透动作数），用作"步骤数"。 */
  stepCount: number
  /** 最后一条 assistant 文本（渗透结论）截断摘要。 */
  conclusion: string
}

/**
 * 从一段文本里提取第一个 URL / host:port / IP 作为渗透目标。
 * 纯函数，便于单测。提取不到返回 null。
 */
export function extractTargetFromText(text: string): string | null {
  if (!text) return null
  const url = text.match(/https?:\/\/[^\s"'）)]+/i)?.[0]
  if (url) return url.replace(/[.,;。，]+$/, '')
  const hostPort = text.match(/\b[a-z0-9.-]+\.[a-z]{2,}(?::\d{2,5})?\b/i)?.[0]
  if (hostPort) return hostPort
  const ipPort = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?\b/)?.[0]
  if (ipPort) return ipPort
  return null
}

/** target 是否像一个真实目标（含 . / : 且足够长），否则视为占位需要推导。 */
export function isMeaningfulTarget(target: string): boolean {
  const t = (target ?? '').trim()
  if (t.length < 3) return false
  return /[.:/]/.test(t)
}

// ─── Projects index ─────────────────────────────────────────

type ProjectsIndex = {
  projects: ProjectMeta[]
  /** 用户自定义分类（内置分类不存这里，见 BUILTIN_CATEGORIES）。 */
  categories?: CategoryDef[]
}

/** 把任意文本转成 URL 安全的分类 id（仅 ASCII 字母数字+连字符）。
 *  纯中文/无 ASCII 字母数字的 label → 用随机 token 兜底（label 仍保留原文显示）。 */
function slugifyCategoryId(label: string): string {
  const base = label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return base || `cat-${crypto.randomUUID().slice(0, 8)}`
}

const SECURITY_DIR = 'security'
const PROJECTS_INDEX = 'projects.json'

function getSecurityDir(): string {
  return path.join(getDataDir(), SECURITY_DIR)
}

function getProjectDir(projectId: string): string {
  return path.join(getSecurityDir(), projectId)
}

// ─── Service ────────────────────────────────────────────────

export class SecurityProjectService {
  /** 迁移兼容：旧项目 meta 无 category 时默认 custom（同黑板旧节点默认 done 思路，零迁移脚本）。 */
  private normalizeMeta(meta: ProjectMeta): ProjectMeta {
    if (!meta.category) return { ...meta, category: 'custom' }
    return meta
  }

  async listProjects(): Promise<ProjectMeta[]> {
    const index = await this.readIndex()
    return index.projects.map((m) => this.normalizeMeta(m))
  }

  async getProject(projectId: string): Promise<SecurityProject | null> {
    const projectDir = getProjectDir(projectId)
    try {
      await fs.stat(projectDir)
    } catch {
      return null
    }

    const [meta, board, findings] = await Promise.all([
      this.readJson<ProjectMeta>(projectDir, 'meta.json'),
      this.readJson<Blackboard>(projectDir, 'board.json'),
      this.readJson<ProjectFinding[]>(projectDir, 'findings.json'),
    ])

    if (!meta) return null

    return {
      meta: this.normalizeMeta(meta),
      board: board ?? { facts: [], intents: [], hints: [], closedIntentIds: [] },
      findings: findings ?? [],
    }
  }

  async createProject(input: {
    name: string
    target: string
    priority: ProjectPriority
    category?: string
    tags?: string[]
    sessionIds?: string[]
  }): Promise<ProjectMeta> {
    const projectId = crypto.randomUUID()
    const projectDir = getProjectDir(projectId)
    const sessionIds = input.sessionIds ?? []

    await fs.mkdir(projectDir, { recursive: true })
    await fs.mkdir(path.join(projectDir, 'memory'), { recursive: true })

    // target 推导：传入的 target 像占位符（"1" 之类）时，从关联会话里抽真实 URL/host/IP。
    let target = input.target
    if (!isMeaningfulTarget(target)) {
      for (const sid of sessionIds) {
        const derived = await this.deriveTargetFromSession(sid)
        if (derived) {
          target = derived
          break
        }
      }
    }

    const meta: ProjectMeta = {
      id: projectId,
      name: input.name,
      target,
      priority: input.priority,
      status: 'active',
      goal: `发现 ${target} 的所有高危漏洞，覆盖所有可访问入口`,
      category: input.category ?? 'custom',
      ...(input.tags && input.tags.length > 0 ? { tags: input.tags } : {}),
      sessionIds,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    // D1：board / findings 初始为空，是诚实状态。不再用正则刮取伪造数据。
    // 结构化发现由 D2（findingsExtractionService）后续填充。
    const board: Blackboard = {
      facts: [],
      intents: [],
      hints: [],
      closedIntentIds: [],
    }

    await Promise.all([
      this.writeJson(projectDir, 'meta.json', meta),
      this.writeJson(projectDir, 'board.json', board),
      this.writeJson(projectDir, 'findings.json', []),
      this.writeJson(projectDir, 'sessions.json', sessionIds),
      this.addToIndex(meta),
    ])

    return meta
  }

  async updateProject(projectId: string, updates: Partial<ProjectMeta>): Promise<void> {
    const project = await this.getProject(projectId)
    if (!project) throw ApiError.notFound('Project not found')

    const updated: ProjectMeta = {
      ...project.meta,
      ...updates,
      id: project.meta.id,   // id 不可改
      updatedAt: Date.now(),
    }

    await this.writeJson(getProjectDir(projectId), 'meta.json', updated)
    await this.updateIndex(projectId, updated)
  }

  async deleteProject(projectId: string): Promise<void> {
    const projectDir = getProjectDir(projectId)
    try {
      await fs.stat(projectDir)
    } catch {
      throw ApiError.notFound('Project not found')
    }

    await fs.rm(projectDir, { recursive: true, force: true })
    await this.removeFromIndex(projectId)
  }

  // ─── Categories (注册表) ─────────────────────────────────

  /** 全部分类 = 内置 + 自定义（去重，内置在前）。 */
  async getCategories(): Promise<CategoryDef[]> {
    const index = await this.readIndex()
    const custom = (index.categories ?? []).filter((c) => !BUILTIN_CATEGORIES.some((b) => b.id === c.id))
    return [...BUILTIN_CATEGORIES, ...custom]
  }

  /** 新增自定义分类。label 去重生成 id；返回新建（或同 id 已存在）的定义。 */
  async addCategory(input: { label: string; color: string }): Promise<CategoryDef> {
    const label = input.label.trim()
    if (!label) throw ApiError.badRequest('label is required')

    const index = await this.readIndex()
    const existing = index.categories ?? []
    const taken = new Set([...BUILTIN_CATEGORIES.map((c) => c.id), ...existing.map((c) => c.id)])

    let id = slugifyCategoryId(label)
    if (taken.has(id)) {
      let n = 2
      while (taken.has(`${id}-${n}`)) n++
      id = `${id}-${n}`
    }

    const def: CategoryDef = { id, label, color: input.color }
    await this.writeIndex({ ...index, categories: [...existing, def] })
    return def
  }

  /** 删除自定义分类。内置不可删；删除时把占用该分类的项目重置为 custom。 */
  async removeCategory(categoryId: string): Promise<void> {
    if (BUILTIN_CATEGORIES.some((c) => c.id === categoryId)) {
      throw ApiError.badRequest('cannot delete a builtin category')
    }
    const index = await this.readIndex()
    const existing = index.categories ?? []
    if (!existing.some((c) => c.id === categoryId)) {
      throw ApiError.notFound('Category not found')
    }

    // 占用该分类的项目重置为 custom（索引 + 各自 meta.json）。
    const reassigned = index.projects.map((p) =>
      p.category === categoryId ? { ...p, category: 'custom', updatedAt: Date.now() } : p,
    )
    await Promise.all(
      reassigned
        .filter((p, i) => p !== index.projects[i])
        .map((p) => this.writeJson(getProjectDir(p.id), 'meta.json', p)),
    )

    await this.writeIndex({
      projects: reassigned,
      categories: existing.filter((c) => c.id !== categoryId),
    })
  }

  // ─── Blackboard ──────────────────────────────────────────

  async getBoard(projectId: string): Promise<Blackboard | null> {
    return this.readJson<Blackboard>(getProjectDir(projectId), 'board.json')
  }

  async updateBoard(projectId: string, board: Blackboard): Promise<void> {
    await this.writeJson(getProjectDir(projectId), 'board.json', board)
  }

  // ─── Findings ──────────────────────────────────────────

  async addFinding(projectId: string, finding: ProjectFinding): Promise<void> {
    const findings = await this.readJson<ProjectFinding[]>(getProjectDir(projectId), 'findings.json') ?? []
    findings.push(finding)
    await this.writeJson(getProjectDir(projectId), 'findings.json', findings)
  }

  async getFindings(projectId: string): Promise<ProjectFinding[]> {
    return await this.readJson<ProjectFinding[]>(getProjectDir(projectId), 'findings.json') ?? []
  }

  // ─── Sessions ──────────────────────────────────────────

  async linkSession(projectId: string, sessionId: string): Promise<void> {
    const projectDir = getProjectDir(projectId)
    const sessions = await this.readJson<string[]>(projectDir, 'sessions.json') ?? []
    if (!sessions.includes(sessionId)) {
      sessions.push(sessionId)
      await this.writeJson(projectDir, 'sessions.json', sessions)
    }
    // also update meta
    const meta = await this.readJson<ProjectMeta>(projectDir, 'meta.json')
    if (meta && !meta.sessionIds.includes(sessionId)) {
      meta.sessionIds.push(sessionId)
      meta.updatedAt = Date.now()
      await this.writeJson(projectDir, 'meta.json', meta)
      await this.updateIndex(projectId, meta)
    }
  }

  // ─── Session summaries (D1：忠实展示会话，不伪造 board) ──────

  /**
   * 读取一个关联会话的真实摘要：标题、工具调用步骤数、最后一条 assistant 结论。
   * 直接解析原始 JSONL，不依赖任何正则"猜漏洞"。会话不存在时返回 null。
   */
  async getSessionSummary(sessionId: string): Promise<SessionSummary | null> {
    const content = await this.readSessionFile(sessionId)
    if (!content) return null

    const lines = content.split('\n').filter(Boolean)
    let title = ''
    let customTitle = ''
    let stepCount = 0
    let lastAssistantText = ''

    for (const line of lines) {
      try {
        const entry = JSON.parse(line)
        if (entry.type === 'custom-title' && typeof entry.customTitle === 'string') {
          customTitle = entry.customTitle
          continue
        }
        if (entry.type === 'ai-title' && typeof entry.aiTitle === 'string') {
          title = entry.aiTitle
          continue
        }
        const message = entry.message
        if (!message) continue

        if (entry.type === 'assistant' && message.role === 'assistant' && Array.isArray(message.content)) {
          for (const block of message.content) {
            if (block.type === 'tool_use') stepCount += 1
            if (block.type === 'text' && typeof block.text === 'string' && block.text.trim()) {
              lastAssistantText = block.text
            }
          }
        }
      } catch {
        // skip malformed lines
      }
    }

    const resolvedTitle = customTitle || title || `会话 ${sessionId.slice(0, 8)}`
    const conclusion = lastAssistantText.trim().slice(0, 600)

    return { sessionId, title: resolvedTitle, stepCount, conclusion }
  }

  /** 批量取关联会话摘要（详情页用）。读不到的会话跳过。 */
  async getSessionSummaries(sessionIds: string[]): Promise<SessionSummary[]> {
    const out: SessionSummary[] = []
    for (const id of sessionIds) {
      const s = await this.getSessionSummary(id)
      if (s) out.push(s)
    }
    return out
  }

  /**
   * 从关联会话推导真实渗透目标（标题或首条 user 消息里的 URL/host/IP）。
   * 推导不到返回 null。
   */
  async deriveTargetFromSession(sessionId: string): Promise<string | null> {
    const content = await this.readSessionFile(sessionId)
    if (!content) return null

    const lines = content.split('\n').filter(Boolean)
    for (const line of lines) {
      try {
        const entry = JSON.parse(line)
        if ((entry.type === 'custom-title' && entry.customTitle) || (entry.type === 'ai-title' && entry.aiTitle)) {
          const t = extractTargetFromText(entry.customTitle || entry.aiTitle)
          if (t) return t
        }
        const message = entry.message
        if (entry.type === 'user' && message?.role === 'user') {
          const c = message.content
          const text = typeof c === 'string' ? c
            : Array.isArray(c) ? c.map((b: any) => b.text || '').join(' ') : ''
          const t = extractTargetFromText(text)
          if (t) return t
        }
      } catch {
        // skip malformed lines
      }
    }
    return null
  }

  // ─── D2：LLM 提炼结构化发现 ──────────────────────────────

  /**
   * 把一个会话的 assistant 文本拼成提炼用的 transcript（只取结论性文本，控制 token）。
   * 读不到返回空串。
   */
  private async buildTranscriptForExtraction(sessionId: string): Promise<string> {
    const content = await this.readSessionFile(sessionId)
    if (!content) return ''

    const parts: string[] = []
    for (const line of content.split('\n').filter(Boolean)) {
      try {
        const entry = JSON.parse(line)
        const message = entry.message
        if (entry.type === 'assistant' && message?.role === 'assistant' && Array.isArray(message.content)) {
          for (const block of message.content) {
            if (block.type === 'text' && typeof block.text === 'string' && block.text.trim()) {
              parts.push(block.text)
            }
          }
        }
      } catch {
        // skip malformed lines
      }
    }
    return parts.join('\n\n')
  }

  /**
   * 对项目所有关联会话跑 LLM 节点提炼，合并写入 nodes.json，
   * 并从 finding 类节点派生 findings.json（向后兼容现有发现展示），同步 meta.findingCount。
   * 失败/无 provider 时 extractNodes 返回空，本方法静默结束、不抛错。
   * 调用方应 fire-and-forget（不阻塞 API 响应）。
   */
  async extractFindingsForProject(projectId: string, providerId?: string | null): Promise<void> {
    const project = await this.getProject(projectId)
    if (!project) return

    // 读上一版节点，作为增量精炼基线 + id 复用来源。
    const prevNodes = await this.getNodes(projectId)
    const prevById = new Map(prevNodes.map((n) => [n.id, n]))
    // 按会话分组上一版（基线按会话喂给 LLM）。
    const prevBySession = new Map<string, ExploreNode[]>()
    for (const n of prevNodes) {
      if (!prevBySession.has(n.sessionId)) prevBySession.set(n.sessionId, [])
      prevBySession.get(n.sessionId)!.push(n)
    }
    // 上一版"标题(同会话) → id"，用于复用 id 防止树跳动。
    const titleToPrevId = new Map<string, string>()
    for (const n of prevNodes) titleToPrevId.set(`${n.sessionId}::${n.title.trim().toLowerCase()}`, n.id)

    const allNodes: ExploreNode[] = []
    for (const sessionId of project.meta.sessionIds) {
      // 主会话 assistant 文本（基础素材）。
      let transcript = await this.buildTranscriptForExtraction(sessionId)

      // 黑板会话：把该会话的结构化黑板节点（路 A，agent 边探边写，带 graphStatus/agentId/三槽）
      // 作为**额外素材**附加给 LLM——黑板是更丰富的输入，不替代提炼，让 LLM 综合时有更好的依据。
      const sessionBoardDir = path.join(getSecurityDir(), '_sessions', sessionId)
      const boardNodes = await boardStore.getNodes(sessionBoardDir)
      if (boardNodes.length > 0) {
        const boardText = boardNodes
          .map((n) => {
            const fields = [
              `[${n.type}] ${n.title}`,
              n.severity ? `severity=${n.severity}` : '',
              n.result ? `结论: ${n.result}` : '',
              n.process ? `过程: ${n.process}` : '',
              n.evidence ? `证据: ${n.evidence}` : '',
              n.payload ? `payload: ${n.payload}` : '',
              n.flag ? `flag: ${n.flag}` : '',
            ].filter(Boolean)
            return fields.join(' | ')
          })
          .join('\n')
        transcript = `${transcript}\n\n## 该会话的黑板（agent 边探边写的结构化探索记录，作为权威素材）\n${boardText}`
      }

      if (!transcript.trim()) continue

      // 构建该会话的上一版基线（用父标题表达父子，避免 id 漂移）。
      const sessionPrev = prevBySession.get(sessionId) ?? []
      const priorNodes: PriorNode[] = sessionPrev.map((n) => ({
        title: n.title,
        type: n.type,
        parentTitle: n.parentId ? prevById.get(n.parentId)?.title : undefined,
        status: n.status,
        severity: n.severity,
        result: n.result,
      }))

      const extracted = await extractNodes(transcript, providerId, priorNodes)
      if (extracted.length === 0) {
        // 本次提炼空：保留该会话上一版节点，绝不删减。
        for (const n of sessionPrev) allNodes.push(n)
        continue
      }

      // key → 真 id：标题在上一版出现过就复用旧 id（树不跳），否则新 id。
      const keyToId = new Map<string, string>()
      for (const n of extracted) {
        const reuse = titleToPrevId.get(`${sessionId}::${n.title.trim().toLowerCase()}`)
        keyToId.set(n.key, reuse ?? crypto.randomUUID())
      }

      for (const n of extracted) {
        const node: ExploreNode = {
          id: keyToId.get(n.key)!,
          type: n.type,
          title: n.title,
          sessionId,
          createdAt: prevById.get(keyToId.get(n.key)!)?.createdAt ?? Date.now(),
        }
        if (n.parentKey && keyToId.has(n.parentKey)) node.parentId = keyToId.get(n.parentKey)
        if (n.phase) node.phase = n.phase
        if (n.assetKind) node.assetKind = n.assetKind
        if (n.detail) node.detail = n.detail
        if (n.process) node.process = n.process
        if (n.result) node.result = n.result
        if (n.severity) node.severity = n.severity
        if (n.status) node.status = n.status
        if (n.location) node.location = n.location
        if (n.payload) node.payload = n.payload
        if (n.evidence) node.evidence = n.evidence
        if (n.flag) node.flag = n.flag
        allNodes.push(node)
      }
    }

    // 从 finding 类节点派生 findings.json（保持现有发现 tab/计数可用），按标题去重。
    const seen = new Set<string>()
    const findings: ProjectFinding[] = []
    for (const n of allNodes) {
      if (n.type !== 'finding') continue
      const key = n.title.toLowerCase().slice(0, 60)
      if (seen.has(key)) continue
      seen.add(key)
      const detailParts = [n.result || n.detail, n.payload ? `payload: ${n.payload}` : '', n.flag ? `flag: ${n.flag}` : '']
        .filter(Boolean)
      findings.push({
        id: n.id,
        title: n.title,
        detail: detailParts.join(' · '),
        severity: n.severity ?? 'info',
        status: (n.status as ProjectFinding['status']) ?? 'unverified',
        location: n.location,
        evidence: n.evidence,
        sessionId: n.sessionId,
        intentId: '',
        createdAt: n.createdAt,
      })
    }

    const projectDir = getProjectDir(projectId)
    await this.writeJson(projectDir, 'nodes.json', allNodes)
    await this.writeJson(projectDir, 'findings.json', findings)
    const meta = await this.readJson<ProjectMeta>(projectDir, 'meta.json')
    if (meta) {
      meta.findingCount = findings.length
      meta.updatedAt = Date.now()
      await this.writeJson(projectDir, 'meta.json', meta)
      await this.updateIndex(projectId, meta)
    }
  }

  /**
   * 读项目的探索节点（详情页树视图用）。委托 boardStore（dir-keyed 核心）。
   * 旧 intent 无 graphStatus 默认 done 的兼容逻辑在 boardStore 内。
   */
  async getNodes(projectId: string): Promise<ExploreNode[]> {
    return boardStore.getNodes(getProjectDir(projectId))
  }

  private async writeNodes(projectId: string, nodes: ExploreNode[]): Promise<void> {
    await this.writeJson(getProjectDir(projectId), 'nodes.json', nodes)
  }

  // ─── 黑板图语义（驱动调度循环；唯一写入者是 server）委托 boardStore ──────────

  /** 读 Hint 列表。 */
  async getHints(projectId: string): Promise<BoardHint[]> {
    return boardStore.getHints(getProjectDir(projectId))
  }

  /** 用户注入一条 Hint。 */
  async addHint(projectId: string, content: string): Promise<BoardHint> {
    try {
      return await boardStore.addHint(getProjectDir(projectId), content)
    } catch (e) {
      throw ApiError.badRequest(e instanceof Error ? e.message : 'hint content required')
    }
  }

  /** 读整张黑板图（goal + target + nodes + hints）。委托 boardStore，goal/target 取自 meta。 */
  async getGraph(projectId: string): Promise<BoardGraph | null> {
    const project = await this.getProject(projectId)
    if (!project) return null
    return boardStore.getGraph(getProjectDir(projectId), project.meta.goal, project.meta.target)
  }

  /** 导出 worker 可读的图快照（纯文本）。委托 boardStore。 */
  async exportGraphSnapshot(projectId: string): Promise<string> {
    const project = await this.getProject(projectId)
    if (!project) return ''
    return boardStore.exportGraphSnapshot(getProjectDir(projectId), project.meta.goal, project.meta.target)
  }

  /** Bootstrap 产出：写无 parent 的根 fact/finding/asset 节点。委托 boardStore。 */
  async addRootFact(
    projectId: string,
    fact: Omit<ExploreNode, 'id' | 'type' | 'createdAt'> & { type?: 'fact' | 'finding' | 'asset' },
  ): Promise<ExploreNode> {
    return boardStore.addRootFact(getProjectDir(projectId), fact)
  }

  /** Reason 产出：批量写入 open intent。委托 boardStore。 */
  async addIntents(
    projectId: string,
    intents: Array<{ title: string; fromFactIds?: string[]; phase?: ExplorePhase; parentId?: string }>,
  ): Promise<ExploreNode[]> {
    return boardStore.addIntents(getProjectDir(projectId), intents)
  }

  /** 派 Explore 前认领：open → running。委托 boardStore。 */
  async claimIntent(projectId: string, intentId: string, worker: string): Promise<boolean> {
    return boardStore.claimIntent(getProjectDir(projectId), intentId, worker)
  }

  /** Explore 回写：running → done，写产出 fact 并连边。委托 boardStore。 */
  async completeIntent(
    projectId: string,
    intentId: string,
    fact: Omit<ExploreNode, 'id' | 'type' | 'createdAt'> & { type?: 'fact' | 'finding' },
  ): Promise<ExploreNode | null> {
    return boardStore.completeIntent(getProjectDir(projectId), intentId, fact)
  }

  /** Explore 探死：running → failed，记原因。委托 boardStore。 */
  async failIntent(projectId: string, intentId: string, reason: string): Promise<boolean> {
    return boardStore.failIntent(getProjectDir(projectId), intentId, reason)
  }

  // ─── Session content extraction ────────────────────────

  /**
   * @deprecated D1 起不再用于写 board——它用正则猜漏洞，会把用户提问当 intent、
   * 漏掉 thinking/tool_result，导致"0 发现 / 100% 覆盖"的假数据。
   * 方法体暂保留仅供 D2（findingsExtractionService）复用其会话遍历逻辑，
   * 任何路径都不应再调用它去写 board / findings。
   *
   * Scan linked session files and extract findings + board entries.
   * Session files are stored in data/projects/{project_dir}/{sessionId}.jsonl.
   */
  async populateFromSessions(projectId: string): Promise<void> {
    const project = await this.getProject(projectId)
    if (!project) return

    const projectDir = getProjectDir(projectId)
    const findings: ProjectFinding[] = []
    const intents: import('../../agent/blackboard.js').Intent[] = []
    const facts: import('../../agent/blackboard.js').Fact[] = []

    for (const sessionId of project.meta.sessionIds) {
      const content = await this.readSessionFile(sessionId)
      if (!content) continue

      const lines = content.split('\n').filter(Boolean)
      for (const line of lines) {
        try {
          const entry = JSON.parse(line)
          const type = entry.type
          const message = entry.message
          if (!message) continue

          // assistant text messages — potential findings
          if (type === 'assistant' && message.role === 'assistant') {
            const contentBlocks = message.content
            if (!Array.isArray(contentBlocks)) continue

            for (const block of contentBlocks) {
              if (block.type === 'text' && block.text) {
                const text = block.text as string
                // look for vulnerability-like patterns
                const vulnPatterns = [
                  /高危|CRITICAL|CRIT|严重/i,
                  /中危|HIGH/i,
                  /SQL注入|XSS|SSRF|命令注入|文件上传|权限绕过|注入/i,
                  /vulnerability|injection|bypass|exploit/i,
                ]
                const matched = vulnPatterns.some((p) => p.test(text))
                if (matched && text.length > 20) {
                  const severity = text.match(/高危|CRITICAL|CRIT/i) ? 'critical'
                    : text.match(/中危|HIGH/i) ? 'high'
                    : 'medium'
                  const title = text.slice(0, 80).replace(/\n/g, ' ').trim()
                  findings.push({
                    id: crypto.randomUUID(),
                    title: title.length > 80 ? title.slice(0, 80) + '...' : title,
                    detail: text.slice(0, 300),
                    severity: severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
                    status: 'unverified',
                    sessionId,
                    intentId: '',
                    createdAt: Date.parse(entry.timestamp) || Date.now(),
                  })
                }
              }
            }
          }

          // user messages — create intents
          if (type === 'user' && message.role === 'user') {
            const content = message.content
            const text = typeof content === 'string' ? content
              : Array.isArray(content) ? content.map((c: any) => c.text || '').join(' ') : ''
            if (text && text.length > 10 && !text.includes('tool_result') && !text.includes('tool_use')) {
              const cleanText = text.replace(/<[^>]+>/g, '').trim()
              if (cleanText.length > 10) {
                intents.push({
                  id: crypto.randomUUID(),
                  description: cleanText.slice(0, 120),
                  status: 'completed',
                  createdBy: 'user',
                  createdAt: Date.parse(entry.timestamp) || Date.now(),
                })
              }
            }
          }
        } catch {
          // skip malformed lines
        }
      }
    }

    // deduplicate findings by title
    const seen = new Set<string>()
    const uniqueFindings = findings.filter((f) => {
      const key = f.title.toLowerCase().slice(0, 40)
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })

    await Promise.all([
      this.writeJson(projectDir, 'findings.json', uniqueFindings),
      this.writeJson(projectDir, 'board.json', {
        facts,
        intents,
        hints: [],
        closedIntentIds: [],
      }),
    ])

    // update finding count in meta
    project.meta.findingCount = uniqueFindings.length
    project.meta.updatedAt = Date.now()
    await this.writeJson(projectDir, 'meta.json', project.meta)
    await this.updateIndex(projectId, project.meta)
  }

  /**
   * Find and read a session JSONL file by session ID across all project directories.
   */
  private async readSessionFile(sessionId: string): Promise<string | null> {
    const projectsDir = path.join(getDataDir(), 'projects')
    try {
      const entries = await fs.readdir(projectsDir, { withFileTypes: true })
      for (const entry of entries) {
        if (!entry.isDirectory()) continue
        const filePath = path.join(projectsDir, entry.name, `${sessionId}.jsonl`)
        try {
          return await fs.readFile(filePath, 'utf-8')
        } catch {
          // file not found in this directory, try next
        }
      }
    } catch {
      // projects dir not found
    }
    return null
  }

  // ─── Internal ──────────────────────────────────────────

  private async readIndex(): Promise<ProjectsIndex> {
    const filePath = path.join(getSecurityDir(), PROJECTS_INDEX)
    const result = await readRecoverableJsonFile<ProjectsIndex>({
      filePath,
      label: 'security projects',
      defaultValue: { projects: [] },
      normalize: (v) => v as ProjectsIndex,
    })
    return result ?? { projects: [] }
  }

  private async writeIndex(index: ProjectsIndex): Promise<void> {
    const filePath = path.join(getSecurityDir(), PROJECTS_INDEX)
    await fs.mkdir(getSecurityDir(), { recursive: true })
    await fs.writeFile(filePath, JSON.stringify(index, null, 2), 'utf-8')
  }

  private async addToIndex(meta: ProjectMeta): Promise<void> {
    const index = await this.readIndex()
    index.projects.push(meta)
    await this.writeIndex(index)
  }

  private async updateIndex(projectId: string, meta: ProjectMeta): Promise<void> {
    const index = await this.readIndex()
    const idx = index.projects.findIndex(p => p.id === projectId)
    if (idx !== -1) {
      index.projects[idx] = meta
    }
    await this.writeIndex(index)
  }

  private async removeFromIndex(projectId: string): Promise<void> {
    const index = await this.readIndex()
    const next = index.projects.filter(p => p.id !== projectId)
    if (next.length !== index.projects.length) {
      await this.writeIndex({ ...index, projects: next })
    }
  }

  private async readJson<T>(dir: string, file: string): Promise<T | null> {
    try {
      const raw = await fs.readFile(path.join(dir, file), 'utf-8')
      return JSON.parse(raw) as T
    } catch {
      return null
    }
  }

  private async writeJson(dir: string, file: string, data: unknown): Promise<void> {
    await fs.writeFile(path.join(dir, file), JSON.stringify(data, null, 2), 'utf-8')
  }
}

export const securityProjectService = new SecurityProjectService()
