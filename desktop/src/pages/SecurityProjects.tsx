import { useEffect, useMemo, useState } from 'react'
import { useSecurityStore } from '../stores/securityStore'
import { useSessionStore } from '../stores/sessionStore'
import { ConfirmDialog } from '../components/shared/ConfirmDialog'
import type { CategoryDef, ExploreNode, Hint, ProjectMeta, ProjectStatus, SecurityProject, SessionSummary } from '../api/security'

// ─── Helpers ────────────────────────────────────────────────

/** 内置分类兜底元数据（注册表未加载时用）。 */
const BUILTIN_CAT_META: Record<string, { label: string; color: string }> = {
  web: { label: 'Web 渗透', color: '#6c5ce7' },
  audit: { label: '代码审计', color: '#45aaf2' },
  asset: { label: '资产收集', color: '#2ed573' },
  mobile: { label: '移动端', color: '#ffa502' },
  binary: { label: '二进制', color: '#ff4757' },
  custom: { label: '自定义', color: 'var(--color-text-tertiary)' },
}

/** 新分类配色盘（添加自定义分类时轮选）。 */
const CATEGORY_PALETTE = ['#6c5ce7', '#45aaf2', '#2ed573', '#ffa502', '#ff4757', '#e84393', '#00cec9', '#fdcb6e', '#a29bfe', '#10b981']
const DEFAULT_CAT_COLOR = '#6c5ce7'

type CatMeta = (id?: string) => { label: string; color: string }

/** 用注册表 + 兜底解析分类元数据。注册表未加载时回退内置常量。 */
function makeCatMeta(categories: CategoryDef[]): CatMeta {
  const map = new Map<string, { label: string; color: string }>()
  for (const c of categories) map.set(c.id, { label: c.label, color: c.color })
  return (id?: string) => {
    const key = id ?? 'custom'
    return map.get(key) ?? BUILTIN_CAT_META[key] ?? { label: key || '自定义', color: 'var(--color-text-tertiary)' }
  }
}

const PHASE_ORDER = ['recon', 'asset', 'probe', 'exploit', 'post', 'other'] as const
const PHASE_LABEL: Record<string, string> = {
  recon: '侦察', asset: '资产', probe: '探测', exploit: '利用', post: '后渗透', other: '其它',
}

type TreeNode = ExploreNode & { children: TreeNode[] }

/** 把扁平节点按 parentId 建成树（仅同会话内 parent 有效）。返回顶层节点。 */
function buildForest(nodes: ExploreNode[]): TreeNode[] {
  const map = new Map<string, TreeNode>()
  for (const n of nodes) map.set(n.id, { ...n, children: [] })
  const roots: TreeNode[] = []
  for (const n of nodes) {
    const tn = map.get(n.id)!
    const parent = n.parentId ? map.get(n.parentId) : undefined
    if (parent) parent.children.push(tn)
    else roots.push(tn)
  }
  return roots
}

/** 按 phase 分组顶层节点，只返回有内容的 phase，按固定顺序。 */
function groupByPhase(roots: TreeNode[]): { phase: string; label: string; nodes: TreeNode[] }[] {
  const buckets = new Map<string, TreeNode[]>()
  for (const r of roots) {
    const p = r.phase && PHASE_LABEL[r.phase] ? r.phase : 'other'
    if (!buckets.has(p)) buckets.set(p, [])
    buckets.get(p)!.push(r)
  }
  return PHASE_ORDER.filter((p) => buckets.has(p)).map((p) => ({ phase: p, label: PHASE_LABEL[p]!, nodes: buckets.get(p)! }))
}

function countByType(nodes: ExploreNode[], type: ExploreNode['type']): number {
  return nodes.filter((n) => n.type === type).length
}

/** 严重度排序权重：critical 最前，info 最后。 */
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
function severityRank(s?: string): number {
  return SEVERITY_RANK[(s ?? 'info').toLowerCase()] ?? 5
}

/** 展平一棵 TreeNode（含自身和所有后代），用于分组摘要计数。 */
function flatten(node: TreeNode): ExploreNode[] {
  return [node, ...node.children.flatMap(flatten)]
}

function statusChipClass(s: string): string {
  if (s === 'active') return 'bg-[var(--color-success-container)] text-[var(--color-success)]'
  if (s === 'paused') return 'bg-[var(--color-warning-container)] text-[var(--color-warning)]'
  return 'bg-[var(--color-surface-container-high)] text-[var(--color-text-tertiary)]'
}

function statusLabelCN(s: string): string {
  return { active: '进行中', paused: '已暂停', completed: '已完成' }[s] ?? s
}

function severityColor(s: string): string {
  const v = s.toLowerCase()
  if (v === 'critical') return 'var(--color-error)'
  if (v === 'high') return 'var(--color-warning)'
  if (v === 'medium') return '#e6a817'
  if (v === 'low') return 'var(--color-info)'
  return 'var(--color-text-tertiary)'
}

function severityClass(s: string): string {
  const v = s.toLowerCase()
  if (v === 'critical') return 'bg-[var(--color-error-container)] text-[var(--color-error)]'
  if (v === 'high') return 'bg-[var(--color-warning-container)] text-[var(--color-warning)]'
  return 'bg-[var(--color-surface-container-high)] text-[var(--color-text-tertiary)]'
}

/** intent 图语义状态 → 展示标签+徽标样式。优先用 graphStatus（真黑板），回退旧 status。 */
function intentGraphMeta(node: ExploreNode): { label: string; chip: string } {
  const gs = node.graphStatus ?? (node.status === 'completed' ? 'done' : node.status === 'exploring' ? 'running' : node.status === 'failed' ? 'failed' : 'open')
  switch (gs) {
    case 'running':
      return { label: '探索中', chip: 'bg-[var(--color-warning-container)] text-[var(--color-warning)]' }
    case 'done':
      return { label: '探完', chip: 'bg-[var(--color-success-container)] text-[var(--color-success)]' }
    case 'failed':
      return { label: '探死', chip: 'bg-[var(--color-surface-container-high)] text-[var(--color-text-tertiary)]' }
    default:
      return { label: '待探', chip: 'bg-[var(--color-surface-container-high)] text-[var(--color-text-tertiary)]' }
  }
}

/** intent 是否未完成（待探/探索中），用于 Intents 计数。 */
function isOpenIntent(node: ExploreNode): boolean {
  const gs = node.graphStatus ?? (node.status === 'completed' ? 'done' : node.status === 'failed' ? 'failed' : 'open')
  return gs === 'open' || gs === 'running'
}

function formatTime(ts: number): string {
  if (!ts) return ''
  const d = new Date(ts)
  return `${d.getMonth() + 1}月${d.getDate()}日`
}

// ─── Create form ────────────────────────────────────────────

function CreateForm({
  onCancel,
  onCreate,
  busy,
  categories,
  defaultCategory,
}: {
  onCancel: () => void
  onCreate: (data: { name: string; target: string; priority: string; category: string; sessionIds: string[] }) => void
  busy: boolean
  categories: CategoryDef[]
  defaultCategory?: string
}) {
  const sessions = useSessionStore((s) => s.sessions)
  const [name, setName] = useState('')
  const [target, setTarget] = useState('')
  const [category, setCategory] = useState<string>(defaultCategory && defaultCategory !== 'all' ? defaultCategory : 'web')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  function toggleSession(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // target 可空：关联了会话时由后端从会话推导（避免占位垃圾）。
  const canSubmit = name.trim().length > 0 && (target.trim().length > 0 || selectedIds.size > 0) && !busy

  return (
    <div className="mx-3 mb-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-container-low)] p-3">
      <div className="flex flex-col gap-2">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="项目名称"
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:border-[var(--color-border-focus)]"
        />
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="目标（URL / IP / 路径，关联会话时可留空自动推导）"
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:border-[var(--color-border-focus)]"
        />
        <div className="flex flex-wrap gap-1.5">
          {categories.map((c) => (
            <button
              key={c.id}
              onClick={() => setCategory(c.id)}
              className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${
                category === c.id
                  ? 'bg-[var(--color-brand)] text-white'
                  : 'bg-[var(--color-surface-container-high)] text-[var(--color-text-tertiary)]'
              }`}
            >
              <span className="inline-block h-2 w-2 rounded-sm" style={{ background: category === c.id ? '#fff' : c.color }} />
              {c.label}
            </button>
          ))}
        </div>

        {sessions.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-medium text-[var(--color-text-tertiary)]">
              关联会话（已选 {selectedIds.size}）
            </div>
            <div className="flex max-h-32 flex-col gap-0.5 overflow-y-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-1">
              {sessions.map((s) => (
                <button
                  key={s.id}
                  onClick={() => toggleSession(s.id)}
                  className={`flex items-center gap-2 rounded px-2 py-1.5 text-left text-xs transition-colors ${
                    selectedIds.has(s.id)
                      ? 'bg-[var(--color-brand)]/10 text-[var(--color-text-primary)]'
                      : 'text-[var(--color-text-tertiary)] hover:bg-[var(--color-surface-hover)]'
                  }`}
                >
                  <span
                    className={`inline-flex h-3.5 w-3.5 items-center justify-center rounded border ${
                      selectedIds.has(s.id)
                        ? 'border-[var(--color-brand)] bg-[var(--color-brand)]'
                        : 'border-[var(--color-border)]'
                    }`}
                  >
                    {selectedIds.has(s.id) && (
                      <svg viewBox="0 0 12 12" fill="none" className="h-3 w-3">
                        <path d="M3 6l2 2 4-4" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    )}
                  </span>
                  <span className="flex-1 truncate">{s.title || '未命名会话'}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="flex gap-2">
          <button
            onClick={onCancel}
            className="flex-1 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
          >
            取消
          </button>
          <button
            onClick={() => onCreate({ name: name.trim(), target: target.trim(), priority: 'P2', category, sessionIds: Array.from(selectedIds) })}
            disabled={!canSubmit}
            className="flex-1 rounded-lg bg-[var(--color-brand)] px-3 py-2 text-sm font-medium text-white disabled:opacity-40"
          >
            创建
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Left rail: category + status navigation ────────────────

function CategoryRail({
  categories,
  projects,
  catFilter,
  statusFilter,
  onCatFilter,
  onStatusFilter,
  onAddCategory,
  onRemoveCategory,
  busy,
}: {
  categories: CategoryDef[]
  projects: ProjectMeta[]
  catFilter: string
  statusFilter: ProjectStatus | 'all'
  onCatFilter: (c: string) => void
  onStatusFilter: (s: ProjectStatus | 'all') => void
  onAddCategory: (label: string, color: string) => void
  onRemoveCategory: (def: CategoryDef) => void
  busy: boolean
}) {
  const [adding, setAdding] = useState(false)
  const [label, setLabel] = useState('')
  const [color, setColor] = useState(DEFAULT_CAT_COLOR)

  const catCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const p of projects) m[p.category || 'custom'] = (m[p.category || 'custom'] ?? 0) + 1
    return m
  }, [projects])
  const statusCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const p of projects) m[p.status] = (m[p.status] ?? 0) + 1
    return m
  }, [projects])

  function submitAdd() {
    const t = label.trim()
    if (!t) return
    onAddCategory(t, color)
    setLabel('')
    setColor(DEFAULT_CAT_COLOR)
    setAdding(false)
  }

  const railBtn = (active: boolean) =>
    `flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
      active ? 'bg-[var(--color-surface-hover)] text-[var(--color-text-primary)]' : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]'
    }`

  return (
    <div className="flex h-full w-[230px] flex-shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface-sidebar)]">
      <div className="px-3 pb-1 pt-3 text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-tertiary)]">分类</div>
      <div className="flex-1 overflow-y-auto px-1.5 pb-3">
        {/* 全部 */}
        <button onClick={() => onCatFilter('all')} className={railBtn(catFilter === 'all')}>
          <span className="h-2 w-2 flex-shrink-0 rounded-sm bg-[var(--color-text-tertiary)]" />
          全部
          <span className="ml-auto rounded-full bg-[var(--color-surface-container-low)] px-2 py-0.5 text-[11px] text-[var(--color-text-tertiary)]">{projects.length}</span>
        </button>
        {/* 各分类 */}
        {categories.map((c) => (
          <div key={c.id} className="group/cat relative">
            <button onClick={() => onCatFilter(c.id)} className={railBtn(catFilter === c.id)}>
              <span className="h-2 w-2 flex-shrink-0 rounded-sm" style={{ background: c.color }} />
              <span className="truncate">{c.label}</span>
              <span className="ml-auto rounded-full bg-[var(--color-surface-container-low)] px-2 py-0.5 text-[11px] text-[var(--color-text-tertiary)]">{catCounts[c.id] ?? 0}</span>
            </button>
            {!c.builtin && (
              <button
                onClick={() => onRemoveCategory(c)}
                disabled={busy}
                title="删除分类"
                className="absolute right-1.5 top-1/2 hidden -translate-y-1/2 rounded p-1 text-[var(--color-text-tertiary)] hover:bg-[var(--color-error-container)] hover:text-[var(--color-error)] group-hover/cat:block"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-3 w-3"><path d="M6 6l12 12M18 6L6 18" strokeLinecap="round" /></svg>
              </button>
            )}
          </div>
        ))}
        {/* 添加分类 */}
        {adding ? (
          <div className="mx-1 mt-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container-low)] p-2">
            <input
              autoFocus
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.nativeEvent.isComposing) submitAdd(); if (e.key === 'Escape') setAdding(false) }}
              placeholder="分类名称"
              className="w-full rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-sm outline-none focus:border-[var(--color-brand)]"
            />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {CATEGORY_PALETTE.map((p) => (
                <button key={p} onClick={() => setColor(p)} className={`h-4 w-4 rounded-sm ${color === p ? 'ring-2 ring-offset-1 ring-offset-[var(--color-surface-container-low)] ring-[var(--color-text-primary)]' : ''}`} style={{ background: p }} />
              ))}
            </div>
            <div className="mt-2 flex gap-1.5">
              <button onClick={() => setAdding(false)} className="flex-1 rounded border border-[var(--color-border)] py-1 text-xs text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]">取消</button>
              <button onClick={submitAdd} disabled={busy || !label.trim()} className="flex-1 rounded bg-[var(--color-brand)] py-1 text-xs font-medium text-white disabled:opacity-40">添加</button>
            </div>
          </div>
        ) : (
          <button onClick={() => setAdding(true)} className="mt-1 flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm text-[var(--color-text-tertiary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-secondary)]">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-3.5 w-3.5"><path d="M12 5v14M5 12h14" strokeLinecap="round" /></svg>
            添加分类
          </button>
        )}

        <div className="px-1.5 pb-1 pt-4 text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-tertiary)]">状态</div>
        {(['active', 'paused', 'completed'] as ProjectStatus[]).map((s) => (
          <button key={s} onClick={() => onStatusFilter(statusFilter === s ? 'all' : s)} className={railBtn(statusFilter === s)}>
            <span className="h-1.5 w-1.5 flex-shrink-0 rounded-full" style={{ background: s === 'active' ? 'var(--color-success)' : s === 'paused' ? 'var(--color-warning)' : 'var(--color-text-tertiary)' }} />
            {statusLabelCN(s)}
            <span className="ml-auto rounded-full bg-[var(--color-surface-container-low)] px-2 py-0.5 text-[11px] text-[var(--color-text-tertiary)]">{statusCounts[s] ?? 0}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

// ─── Card + browse view (topbar + grid) ─────────────────────

function ProjectCard({ project, catMeta, onSelect }: { project: ProjectMeta; catMeta: CatMeta; onSelect: () => void }) {
  const cm = catMeta(project.category)
  const st = project.status
  const stColor = st === 'active' ? 'var(--color-success)' : st === 'paused' ? 'var(--color-warning)' : 'var(--color-text-tertiary)'
  return (
    <button
      onClick={onSelect}
      className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 text-left transition-colors hover:border-[var(--color-brand)]"
    >
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-[15px] font-semibold text-[var(--color-text-primary)]">{project.name}</span>
        {typeof project.findingCount === 'number' && project.findingCount > 0 ? (
          <span className="flex-shrink-0 rounded bg-[var(--color-error-container)] px-2 py-0.5 text-[10px] font-semibold text-[var(--color-error)]">{project.findingCount} 发现</span>
        ) : (
          <span className="flex-shrink-0 rounded bg-[var(--color-surface-container-high)] px-2 py-0.5 text-[10px] font-semibold text-[var(--color-text-tertiary)]">暂无发现</span>
        )}
      </div>
      <div className="mt-1.5 truncate font-mono text-xs text-[var(--color-text-tertiary)]">{project.target || '—'}</div>

      <div className="mt-3 flex items-center gap-5 border-t border-[var(--color-border)] pt-3">
        <div>
          <div className="text-[17px] font-bold tabular-nums text-[var(--color-text-primary)]">{project.findingCount ?? 0}</div>
          <div className="text-[10px] text-[var(--color-text-tertiary)]">发现</div>
        </div>
        <div>
          <div className="text-[17px] font-bold tabular-nums text-[var(--color-text-primary)]">{project.sessionIds.length}</div>
          <div className="text-[10px] text-[var(--color-text-tertiary)]">会话</div>
        </div>
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
        {(project.tags ?? []).slice(0, 3).map((t) => (
          <span key={t} className="rounded bg-[var(--color-surface-container-low)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-secondary)]">{t}</span>
        ))}
        <span className="rounded bg-[var(--color-surface-container-low)] px-1.5 py-0.5 text-[10px]" style={{ color: cm.color }}>● {cm.label}</span>
      </div>

      <div className="mt-2.5 flex items-center gap-1.5 text-[11px] text-[var(--color-text-tertiary)]">
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: stColor }} />
        {statusLabelCN(st)} · 更新 {formatTime(project.updatedAt)}
      </div>
    </button>
  )
}

type SortKey = 'recent' | 'name' | 'findings'
const SORT_LABEL: Record<SortKey, string> = { recent: '最近活跃', name: '名称', findings: '发现数' }

function BrowseView({
  projects,
  categories,
  catMeta,
  catFilter,
  statusFilter,
  query,
  onQuery,
  loading,
  error,
  onSelect,
  onNewProject,
  showForm,
  onCancelForm,
  onCreate,
  creating,
}: {
  projects: ProjectMeta[]
  categories: CategoryDef[]
  catMeta: CatMeta
  catFilter: string
  statusFilter: ProjectStatus | 'all'
  query: string
  onQuery: (q: string) => void
  loading: boolean
  error: string | null
  onSelect: (id: string) => void
  onNewProject: () => void
  showForm: boolean
  onCancelForm: () => void
  onCreate: (data: { name: string; target: string; priority: string; category: string; sessionIds: string[] }) => void
  creating: boolean
}) {
  const [sort, setSort] = useState<SortKey>('recent')
  const [sortOpen, setSortOpen] = useState(false)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const list = projects.filter((p) => {
      if (catFilter !== 'all' && (p.category || 'custom') !== catFilter) return false
      if (statusFilter !== 'all' && p.status !== statusFilter) return false
      if (q && !(p.name.toLowerCase().includes(q) || p.target.toLowerCase().includes(q) || (p.tags ?? []).some((t) => t.toLowerCase().includes(q)))) return false
      return true
    })
    const sorted = [...list]
    if (sort === 'recent') sorted.sort((a, b) => b.updatedAt - a.updatedAt)
    else if (sort === 'name') sorted.sort((a, b) => a.name.localeCompare(b.name))
    else sorted.sort((a, b) => (b.findingCount ?? 0) - (a.findingCount ?? 0))
    return sorted
  }, [projects, catFilter, statusFilter, query, sort])

  // 按分类分组（custom + 自定义都进各自组；分类顺序跟注册表）。
  const grouped = useMemo(() => {
    const order = categories.map((c) => c.id)
    const buckets = new Map<string, ProjectMeta[]>()
    for (const p of filtered) {
      const c = p.category || 'custom'
      if (!buckets.has(c)) buckets.set(c, [])
      buckets.get(c)!.push(p)
    }
    const keys = [...buckets.keys()].sort((a, b) => {
      const ia = order.indexOf(a), ib = order.indexOf(b)
      return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib)
    })
    return keys.map((c) => ({ cat: c, items: buckets.get(c)! }))
  }, [filtered, categories])

  return (
    <div className="flex min-w-0 flex-1 flex-col">
      {/* 顶栏 */}
      <div className="flex items-center gap-2.5 border-b border-[var(--color-border)] px-5 py-3">
        <div className="flex max-w-[320px] flex-1 items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container-low)] px-3 py-1.5">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-3.5 w-3.5 text-[var(--color-text-tertiary)]"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" strokeLinecap="round" /></svg>
          <input value={query} onChange={(e) => onQuery(e.target.value)} placeholder="搜索项目名 / 目标 / 标签" className="flex-1 bg-transparent text-sm outline-none placeholder:text-[var(--color-text-tertiary)]" />
        </div>
        <div className="relative">
          <button onClick={() => setSortOpen((v) => !v)} className="flex items-center gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container-low)] px-2.5 py-1.5 text-xs text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]">
            排序：{SORT_LABEL[sort]} ▾
          </button>
          {sortOpen && (
            <div className="absolute left-0 top-full z-10 mt-1 w-32 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] py-1 shadow-lg">
              {(Object.keys(SORT_LABEL) as SortKey[]).map((k) => (
                <button key={k} onClick={() => { setSort(k); setSortOpen(false) }} className={`block w-full px-3 py-1.5 text-left text-xs hover:bg-[var(--color-surface-hover)] ${sort === k ? 'text-[var(--color-brand)]' : 'text-[var(--color-text-secondary)]'}`}>{SORT_LABEL[k]}</button>
              ))}
            </div>
          )}
        </div>
        <div className="flex-1" />
        <button onClick={onNewProject} className="rounded-lg bg-[var(--color-brand)] px-3.5 py-1.5 text-sm font-semibold text-white hover:opacity-90">+ 新建项目</button>
      </div>

      {/* 主体 */}
      <div className="flex-1 overflow-y-auto px-5 py-5">
        {showForm && (
          <div className="mb-5 max-w-md">
            <CreateForm categories={categories} defaultCategory={catFilter} onCancel={onCancelForm} onCreate={onCreate} busy={creating} />
          </div>
        )}
        {loading && projects.length === 0 ? (
          <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-3.5">
            {[0, 1, 2, 3].map((i) => <div key={i} className="h-[150px] animate-pulse rounded-xl bg-[var(--color-surface-container-high)]" />)}
          </div>
        ) : error && projects.length === 0 ? (
          <div className="py-16 text-center text-sm text-[var(--color-error)]">{error}</div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center text-sm text-[var(--color-text-tertiary)]">{projects.length === 0 ? '还没有安全项目，点右上「新建项目」开始。' : '没有匹配的项目'}</div>
        ) : (
          grouped.map(({ cat, items }) => (
            <div key={cat} className="mb-6">
              <div className="mb-3 flex items-center gap-2 text-xs font-bold text-[var(--color-text-secondary)]">
                <span className="h-2.5 w-2.5 rounded-sm" style={{ background: catMeta(cat).color }} />
                {catMeta(cat).label} ({items.length})
                <span className="ml-1 h-px flex-1 bg-[var(--color-border)]" />
              </div>
              <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-3.5">
                {items.map((p) => <ProjectCard key={p.id} project={p} catMeta={catMeta} onSelect={() => onSelect(p.id)} />)}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ─── Detail header + actions ─────────────────────────────────

function EditProjectModal({
  project,
  categories,
  onClose,
  onSave,
  busy,
}: {
  project: SecurityProject
  categories: CategoryDef[]
  onClose: () => void
  onSave: (updates: { name: string; category: string; status: ProjectStatus }) => void
  busy: boolean
}) {
  const [name, setName] = useState(project.meta.name)
  const [category, setCategory] = useState(project.meta.category)
  const [status, setStatus] = useState<ProjectStatus>(project.meta.status)

  function handleSave() {
    const trimmed = name.trim()
    if (!trimmed) return
    onSave({ name: trimmed, category, status })
  }

  const canSave = name.trim() && !busy

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <div className="w-full max-w-md rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 text-base font-semibold text-[var(--color-text-primary)]">编辑项目</div>

        <div className="flex flex-col gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-[var(--color-text-secondary)]">项目名称</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="项目名称"
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container-low)] px-3 py-2 text-sm outline-none focus:border-[var(--color-brand)]"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-[var(--color-text-secondary)]">分类</label>
            <div className="flex flex-wrap gap-1.5">
              {categories.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setCategory(c.id)}
                  className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${
                    category === c.id
                      ? 'bg-[var(--color-brand)] text-white'
                      : 'bg-[var(--color-surface-container-high)] text-[var(--color-text-tertiary)]'
                  }`}
                >
                  <span className="inline-block h-2 w-2 rounded-sm" style={{ background: category === c.id ? '#fff' : c.color }} />
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-[var(--color-text-secondary)]">状态</label>
            <div className="flex gap-2">
              {(['active', 'paused', 'completed'] as ProjectStatus[]).map((s) => (
                <button
                  key={s}
                  onClick={() => setStatus(s)}
                  className={`flex-1 rounded-lg border px-3 py-2 text-xs font-medium ${
                    status === s
                      ? 'border-[var(--color-brand)] bg-[var(--color-brand)]/10 text-[var(--color-brand)]'
                      : 'border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]'
                  }`}
                >
                  {statusLabelCN(s)}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-4 flex gap-2">
          <button
            onClick={onClose}
            className="flex-1 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
          >
            取消
          </button>
          <button
            onClick={handleSave}
            disabled={!canSave}
            className="flex-1 rounded-lg bg-[var(--color-brand)] px-3 py-2 text-sm font-medium text-white disabled:opacity-40"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

function DetailHeader({
  project,
  busy,
  categories,
  catMeta,
  onBack,
  onEdit,
  onSetStatus,
  onRefresh,
  onDelete,
}: {
  project: SecurityProject
  busy: boolean
  categories: CategoryDef[]
  catMeta: CatMeta
  onBack: () => void
  onEdit: (updates: { name: string; category: string; status: ProjectStatus }) => void
  onSetStatus: (status: ProjectStatus) => void
  onRefresh: () => void
  onDelete: () => void
}) {
  const { meta } = project
  const nextStatus: ProjectStatus = meta.status === 'active' ? 'paused' : 'active'
  const toggleLabel = meta.status === 'active' ? '暂停' : '继续'
  const [showEdit, setShowEdit] = useState(false)

  function handleSave(updates: { name: string; category: string; status: ProjectStatus }) {
    onEdit(updates)
    setShowEdit(false)
  }

  return (
    <>
      <div className="border-b border-[var(--color-border)] px-6 py-4">
        <button
          onClick={onBack}
          className="mb-3 inline-flex items-center gap-1 text-xs font-medium text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)]"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-3.5 w-3.5"><path d="M15 6l-6 6 6 6" strokeLinecap="round" strokeLinejoin="round" /></svg>
          返回项目列表
        </button>
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-lg font-semibold text-[var(--color-text-primary)]">{meta.name}</span>
              <span className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold bg-[var(--color-surface-container-high)] text-[var(--color-text-secondary)]">
                <span className="inline-block h-1.5 w-1.5 rounded-sm" style={{ background: catMeta(meta.category).color }} />
                {catMeta(meta.category).label}
              </span>
            <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${statusChipClass(meta.status)}`}>{statusLabelCN(meta.status)}</span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-[var(--color-text-secondary)]">
            <span><span className="text-[var(--color-text-tertiary)]">target</span> {meta.target}</span>
            <span className="text-[var(--color-border-strong)]">·</span>
            <span><span className="text-[var(--color-text-tertiary)]">created</span> {formatTime(meta.createdAt)}</span>
          </div>
          {meta.goal && <div className="mt-1.5 text-xs text-[var(--color-text-tertiary)]">{meta.goal}</div>}
        </div>
        <div className="flex flex-shrink-0 items-center gap-2">
          <button
            onClick={() => setShowEdit(true)}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)] disabled:opacity-40"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-3.5 w-3.5">
              <path d="M17 3l4 4-10 10H7v-4L17 3z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            编辑
          </button>
          <button
            onClick={() => onSetStatus(nextStatus)}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)] disabled:opacity-40"
          >
            {toggleLabel}
          </button>
          <button
            onClick={onRefresh}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)] disabled:opacity-40"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-3.5 w-3.5">
              <path d="M21 12a9 9 0 1 1-3-6.7M21 4v5h-5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            刷新
          </button>
          <button
            onClick={onDelete}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-error)] hover:bg-[var(--color-error-container)] disabled:opacity-40"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-3.5 w-3.5">
              <path d="M4 7h16M9 7V5h6v2M7 7l1 13h8l1-13" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            删除
          </button>
        </div>
      </div>
    </div>

    {showEdit && (
      <EditProjectModal
        project={project}
        categories={categories}
        onClose={() => setShowEdit(false)}
        onSave={handleSave}
        busy={busy}
      />
    )}
  </>
  )
}

// ─── Node tree row (recursive) + detail drawer ──────────────

function nodeStatusIcon(node: ExploreNode) {
  if (node.type === 'finding') {
    return <span className="mt-0.5 inline-block h-2.5 w-2.5 flex-shrink-0 rounded-full" style={{ background: severityColor(node.severity ?? 'info') }} />
  }
  if (node.type === 'intent') {
    const gs = node.graphStatus ?? (node.status === 'completed' ? 'done' : node.status === 'exploring' ? 'running' : node.status === 'failed' ? 'failed' : 'open')
    const dot =
      gs === 'running' ? 'bg-[var(--color-warning)]'
      : gs === 'done' ? 'bg-[var(--color-success)]'
      : 'bg-[var(--color-text-tertiary)]'
    return <span className={`mt-0.5 inline-block h-2.5 w-2.5 flex-shrink-0 rounded-full ${dot}`} />
  }
  if (node.type === 'asset') {
    return <span className="mt-0.5 inline-block h-2.5 w-2.5 flex-shrink-0 rounded-[3px] border border-[var(--color-border-strong)]" />
  }
  return <span className="mt-0.5 inline-block h-2.5 w-2.5 flex-shrink-0 rounded-full bg-[var(--color-success)]" />
}

/** 节点是否有可在抽屉展开的深度内容（有才可点）。 */
function hasDepth(node: ExploreNode): boolean {
  return Boolean(node.process || node.evidence || node.result || node.payload || node.flag || (node.detail && node.detail.length > 40))
}

function NodeRow({ node, depth, selectedId, onSelect }: { node: TreeNode; depth: number; selectedId: string | null; onSelect: (n: ExploreNode) => void }) {
  const clickable = hasDepth(node)
  // 树里副标题：结论优先，其次位置/补充
  const subtitle = node.result || node.location || node.detail
  return (
    <>
      <button
        onClick={() => clickable && onSelect(node)}
        disabled={!clickable}
        className={`flex w-full items-start gap-2.5 rounded-lg py-2 pr-2 text-left transition-colors ${
          node.id === selectedId ? 'bg-[var(--color-brand)]/10' : clickable ? 'hover:bg-[var(--color-surface-hover)]' : ''
        } ${clickable ? 'cursor-pointer' : 'cursor-default'}`}
        style={{ paddingLeft: `${8 + depth * 18}px` }}
      >
        {nodeStatusIcon(node)}
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2">
            <span className="truncate text-sm text-[var(--color-text-primary)]">{node.title}</span>
            {node.type === 'finding' && node.severity && (
              <span className={`flex-shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${severityClass(node.severity)}`}>{node.severity.toUpperCase()}</span>
            )}
            {node.type === 'intent' && (() => {
              const m = intentGraphMeta(node)
              return <span className={`flex-shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold ${m.chip}`}>{m.label}</span>
            })()}
          </span>
          {subtitle && (
            <span className="mt-0.5 block truncate text-xs text-[var(--color-text-tertiary)]">{subtitle}</span>
          )}
        </span>
        {clickable && (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="mt-1 h-3.5 w-3.5 flex-shrink-0 text-[var(--color-text-tertiary)]"><path d="M9 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" /></svg>
        )}
      </button>
      {node.children.map((c) => (
        <NodeRow key={c.id} node={c} depth={depth + 1} selectedId={selectedId} onSelect={onSelect} />
      ))}
    </>
  )
}

function NodeDetailDrawer({ node, onClose }: { node: ExploreNode | null; onClose: () => void }) {
  if (!node) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-center">
        <div className="text-xs text-[var(--color-text-tertiary)]">点击左侧探索节点查看详情</div>
      </div>
    )
  }
  const rows: [string, string | undefined][] = [
    ['位置', node.location],
    ['状态', node.type === 'intent' ? intentGraphMeta(node).label : node.status],
    ['来源', node.sessionId ? `会话 ${node.sessionId.slice(0, 8)}` : undefined],
  ].filter(([, v]) => v) as [string, string][]

  // 三槽 code 块：有就显示
  const blocks: [string, string | undefined][] = [
    ['过程', node.process || node.payload],
    ['证据', node.evidence],
    ['结论', [node.result, node.flag ? `flag: ${node.flag}` : ''].filter(Boolean).join('\n') || undefined],
  ].filter(([, v]) => v) as [string, string][]

  return (
    <div className="flex h-full flex-col overflow-y-auto p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          {node.type === 'finding' && node.severity && (
            <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${severityClass(node.severity)}`}>{node.severity.toUpperCase()}</span>
          )}
          <span className="text-sm font-semibold text-[var(--color-text-primary)]">{node.title}</span>
        </div>
        <button onClick={onClose} className="flex-shrink-0 rounded p-1 text-[var(--color-text-tertiary)] hover:bg-[var(--color-surface-hover)]">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-4 w-4"><path d="M6 6l12 12M18 6L6 18" strokeLinecap="round" /></svg>
        </button>
      </div>

      {rows.length > 0 && (
        <div className="mt-3 flex flex-col gap-2">
          {rows.map(([k, v]) => (
            <div key={k} className="text-xs text-[var(--color-text-tertiary)]"><span>{k}</span> <span className="text-[var(--color-text-primary)]">{v}</span></div>
          ))}
        </div>
      )}

      {node.detail && !node.result && <div className="mt-3 text-xs leading-relaxed text-[var(--color-text-secondary)]">{node.detail}</div>}

      {blocks.map(([label, content]) => (
        <div key={label} className="mt-3">
          <div className="mb-1 text-xs font-medium text-[var(--color-text-tertiary)]">{label}</div>
          <pre className="whitespace-pre-wrap rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container-low)] px-3 py-2 font-mono text-[11px] leading-relaxed text-[var(--color-text-secondary)]">{content}</pre>
        </div>
      ))}

      {blocks.length === 0 && rows.length === 0 && (
        <div className="mt-6 text-center text-xs text-[var(--color-text-tertiary)]">该节点暂无更多详情</div>
      )}
    </div>
  )
}

// ─── Hint area (作战地图：用户注入指导) ──────────────────────

function HintArea({ hints, onAddHint, busy }: { hints: Hint[]; onAddHint: (content: string) => void; busy: boolean }) {
  const [draft, setDraft] = useState('')
  const [open, setOpen] = useState(false)

  function submit() {
    const text = draft.trim()
    if (!text) return
    onAddHint(text)
    setDraft('')
  }

  return (
    <div className="mb-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-3 py-2 text-left"
      >
        <span className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
          Hint
          <span className="text-[var(--color-text-tertiary)]">{hints.length} 条指导</span>
        </span>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={`h-3.5 w-3.5 text-[var(--color-text-tertiary)] transition-transform ${open ? 'rotate-90' : ''}`}>
          <path d="M9 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <div className="border-t border-[var(--color-border)] px-3 py-2.5">
          {hints.length > 0 && (
            <ul className="mb-2.5 flex flex-col gap-1.5">
              {hints.map((h) => (
                <li key={h.id} className="flex items-start gap-2 text-sm text-[var(--color-text-secondary)]">
                  <span className="mt-1.5 inline-block h-1.5 w-1.5 flex-shrink-0 rounded-full bg-[var(--color-brand)]" />
                  <span className="min-w-0 flex-1">
                    <span className="block">{h.content}</span>
                    <span className="mt-0.5 block text-[11px] text-[var(--color-text-tertiary)]">{formatTime(h.createdAt)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
          <div className="flex gap-2">
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.nativeEvent.isComposing) submit()
              }}
              placeholder="给本项目注入一条指导，引导后续探索方向"
              className="min-w-0 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-brand)] focus:outline-none"
            />
            <button
              onClick={submit}
              disabled={busy || !draft.trim()}
              className="flex-shrink-0 rounded-lg bg-[var(--color-brand)] px-3 py-1.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-40"
            >
              注入
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Detail body: stats + tabs ───────────────────────────────

function DetailBody({ project, sessionSummaries, nodes, hints, isExtracting, busy, onAddHint }: { project: SecurityProject; sessionSummaries: SessionSummary[]; nodes: ExploreNode[]; hints: Hint[]; isExtracting: boolean; busy: boolean; onAddHint: (content: string) => void }) {
  const { meta, findings } = project
  const [tab, setTab] = useState<'explore' | 'findings' | 'sessions'>('explore')
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)

  const forest = useMemo(() => groupByPhase(buildForest(nodes)), [nodes])
  const selectedNode = useMemo(() => nodes.find((n) => n.id === selectedNodeId) ?? null, [nodes, selectedNodeId])
  // 发现 tab 用 finding 节点（有完整三槽），按严重度排序。
  const findingNodes = useMemo(
    () => nodes.filter((n) => n.type === 'finding').sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
    [nodes],
  )

  // stat：删 Coverage（无总攻击面基准）。Assets = 探索广度，比覆盖率诚实。
  const stats = [
    { k: 'Findings', v: countByType(nodes, 'finding') || findings.length, d: '已记录发现' },
    { k: 'Intents', v: nodes.filter((n) => n.type === 'intent' && isOpenIntent(n)).length, d: '待探方向' },
    { k: 'Assets', v: countByType(nodes, 'asset'), d: '探索资产' },
    { k: 'Sessions', v: meta.sessionIds.length, d: '关联会话' },
  ]

  return (
    <>
      <div className="grid grid-cols-4 border-b border-[var(--color-border)]">
        {stats.map((s, i) => (
          <div key={s.k} className={`px-6 py-3.5 ${i < 3 ? 'border-r border-[var(--color-border)]' : ''}`}>
            <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">{s.k}</div>
            <div className="mt-1.5 text-xl font-bold tabular-nums text-[var(--color-text-primary)]">{s.v}</div>
            <div className="mt-0.5 text-xs text-[var(--color-text-tertiary)]">{s.d}</div>
          </div>
        ))}
      </div>

      <div className="flex gap-6 border-b border-[var(--color-border)] px-6">
        {([
          ['explore', '探索脉络', nodes.length],
          ['findings', '发现汇总', findingNodes.length || findings.length],
          ['sessions', '关联会话', meta.sessionIds.length],
        ] as const).map(([key, label, count]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`relative py-3.5 text-sm font-medium ${
              tab === key ? 'text-[var(--color-text-primary)]' : 'text-[var(--color-text-tertiary)] hover:text-[var(--color-text-secondary)]'
            }`}
          >
            {label}
            <span className="ml-1 text-[var(--color-text-tertiary)]">{count}</span>
            {tab === key && <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-t bg-[var(--color-brand)]" />}
          </button>
        ))}
      </div>

      {/* 探索脉络：左树 + 右详情抽屉 */}
      {tab === 'explore' && (
        <div className="flex min-h-0 flex-1">
          <div className="min-w-0 flex-1 overflow-y-auto px-4 py-4">
            <HintArea hints={hints} onAddHint={onAddHint} busy={busy} />
            {nodes.length === 0 ? (
              isExtracting ? (
                <div className="flex flex-col items-center gap-3 py-12 text-center">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-5 w-5 animate-spin text-[var(--color-brand)]">
                    <path d="M21 12a9 9 0 1 1-6.2-8.5" strokeLinecap="round" />
                  </svg>
                  <div className="text-sm text-[var(--color-text-secondary)]">正在从关联会话提炼探索脉络…</div>
                  <div className="text-xs text-[var(--color-text-tertiary)]">由模型分析过程，稍候自动显示</div>
                </div>
              ) : (
                <div className="py-12 text-center text-sm text-[var(--color-text-tertiary)]">
                  暂无探索数据。关联会话后将自动提炼出探索脉络，或点击上方「刷新」。
                </div>
              )
            ) : (
              <div className="flex flex-col gap-4">
                {forest.map((g) => (
                  <div key={g.phase}>
                    <div className="mb-1 flex items-center gap-2 px-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
                      {g.label}
                      <span className="text-[var(--color-text-tertiary)]">
                        {countByType(g.nodes.flatMap(flatten), 'asset')} 资产 · {countByType(g.nodes.flatMap(flatten), 'finding')} 发现
                      </span>
                    </div>
                    {g.nodes.map((n) => (
                      <NodeRow key={n.id} node={n} depth={0} selectedId={selectedNodeId} onSelect={(node) => setSelectedNodeId(node.id)} />
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="w-[320px] flex-shrink-0 overflow-y-auto border-l border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
            <NodeDetailDrawer node={selectedNode} onClose={() => setSelectedNodeId(null)} />
          </div>
        </div>
      )}

      {tab === 'findings' && (
        <div className="flex min-h-0 flex-1">
          <div className="min-w-0 flex-1 overflow-y-auto px-4 py-4">
            {findingNodes.length === 0 ? (
              isExtracting ? (
                <div className="flex flex-col items-center gap-3 py-12 text-center">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-5 w-5 animate-spin text-[var(--color-brand)]">
                    <path d="M21 12a9 9 0 1 1-6.2-8.5" strokeLinecap="round" />
                  </svg>
                  <div className="text-sm text-[var(--color-text-secondary)]">正在提炼结构化发现…</div>
                </div>
              ) : (
                <div className="py-12 text-center text-sm text-[var(--color-text-tertiary)]">
                  暂无结构化发现。可在「探索脉络」查看过程，或点击上方「刷新」重新提炼。
                </div>
              )
            ) : (
              <div className="flex flex-col gap-2">
                {findingNodes.map((f) => (
                  <button
                    key={f.id}
                    onClick={() => setSelectedNodeId(f.id)}
                    className={`flex w-full items-start gap-3 rounded-lg border border-l-[3px] px-3 py-2.5 text-left transition-colors ${
                      f.id === selectedNodeId ? 'bg-[var(--color-brand)]/10 border-[var(--color-brand)]' : 'border-[var(--color-border)] hover:bg-[var(--color-surface-hover)]'
                    }`}
                    style={{ borderLeftColor: severityColor(f.severity ?? 'info') }}
                  >
                    <span className={`flex-shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${severityClass(f.severity ?? 'info')}`}>{(f.severity ?? 'info').toUpperCase()}</span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <span className="truncate text-sm font-medium text-[var(--color-text-primary)]">{f.title}</span>
                        {f.status && <span className="flex-shrink-0 text-[10px] text-[var(--color-text-tertiary)]">{f.status}</span>}
                      </span>
                      {(f.result || f.location) && (
                        <span className="mt-0.5 block truncate text-xs text-[var(--color-text-tertiary)]">{f.result || f.location}</span>
                      )}
                    </span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="mt-1 h-3.5 w-3.5 flex-shrink-0 text-[var(--color-text-tertiary)]"><path d="M9 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" /></svg>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="w-[320px] flex-shrink-0 overflow-y-auto border-l border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
            <NodeDetailDrawer node={selectedNode} onClose={() => setSelectedNodeId(null)} />
          </div>
        </div>
      )}

      {tab === 'sessions' && (
        <div className="flex-1 overflow-y-auto px-6 py-4">
          {sessionSummaries.length === 0 ? (
            <div className="py-12 text-center text-sm text-[var(--color-text-tertiary)]">
              暂无关联会话。在会话里完成测试后，把会话关联到本项目即可在此查看过程与结论。
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              {sessionSummaries.map((s) => (
                <div key={s.sessionId} className="rounded-xl border border-[var(--color-border)] p-3.5">
                  <div className="flex items-center gap-2">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-4 w-4 flex-shrink-0 text-[var(--color-text-tertiary)]">
                      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                    <span className="min-w-0 flex-1 truncate text-sm font-semibold text-[var(--color-text-primary)]">{s.title}</span>
                    <span className="flex-shrink-0 text-xs text-[var(--color-text-tertiary)]">{s.stepCount} 步</span>
                  </div>
                  {s.conclusion ? (
                    <div className="mt-2 whitespace-pre-wrap rounded-lg bg-[var(--color-surface-container-low)] px-3 py-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">
                      {s.conclusion}
                    </div>
                  ) : (
                    <div className="mt-2 text-xs text-[var(--color-text-tertiary)]">该会话暂无结论文本</div>
                  )}
                  <div className="mt-2 font-mono text-[11px] text-[var(--color-text-tertiary)]">{s.sessionId}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </>
  )
}

// ─── Detail panel (handles empty / loading / error) ─────────

function DetailPanel({
  selectedId,
  project,
  sessionSummaries,
  nodes,
  hints,
  isExtracting,
  loading,
  error,
  busy,
  categories,
  catMeta,
  onBack,
  onEdit,
  onRetry,
  onSetStatus,
  onRefresh,
  onDelete,
  onAddHint,
}: {
  selectedId: string | null
  project: SecurityProject | null
  sessionSummaries: SessionSummary[]
  nodes: ExploreNode[]
  hints: Hint[]
  isExtracting: boolean
  loading: boolean
  error: string | null
  busy: boolean
  categories: CategoryDef[]
  catMeta: CatMeta
  onBack: () => void
  onEdit: (updates: { name: string; category: string; status: ProjectStatus }) => void
  onRetry: () => void
  onSetStatus: (status: ProjectStatus) => void
  onRefresh: () => void
  onDelete: () => void
  onAddHint: (content: string) => void
}) {
  if (!selectedId) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="max-w-xs text-center">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" className="mx-auto h-10 w-10 text-[var(--color-text-tertiary)]">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div className="mt-3 text-sm font-medium text-[var(--color-text-secondary)]">选择一个安全项目</div>
          <div className="mt-1 text-xs text-[var(--color-text-tertiary)]">从左侧列表选择项目查看探索脉络与发现，或新建一个项目。</div>
        </div>
      </div>
    )
  }

  if (loading && !project) {
    return (
      <div className="flex flex-1 flex-col gap-4 p-6">
        <div className="h-16 animate-pulse rounded-xl bg-[var(--color-surface-container-high)]" />
        <div className="h-20 animate-pulse rounded-xl bg-[var(--color-surface-container-high)]" />
        <div className="h-64 animate-pulse rounded-xl bg-[var(--color-surface-container-high)]" />
      </div>
    )
  }

  if (error && !project) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="text-center">
          <div className="text-sm text-[var(--color-error)]">{error}</div>
          <button
            onClick={onRetry}
            className="mt-3 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)]"
          >
            重试
          </button>
        </div>
      </div>
    )
  }

  if (!project) return <div className="flex-1" />

  return (
    <div className={`flex min-w-0 flex-1 flex-col ${loading ? 'opacity-60 transition-opacity' : ''}`}>
      <DetailHeader project={project} busy={busy} categories={categories} catMeta={catMeta} onBack={onBack} onEdit={onEdit} onSetStatus={onSetStatus} onRefresh={onRefresh} onDelete={onDelete} />
      <DetailBody project={project} sessionSummaries={sessionSummaries} nodes={nodes} hints={hints} isExtracting={isExtracting} busy={busy} onAddHint={onAddHint} />
    </div>
  )
}

// ─── SecurityProjects (workspace shell) ──────────────────────

export function SecurityProjects() {
  const {
    projects,
    categories,
    selectedProjectId,
    selectedProject,
    sessionSummaries,
    nodes,
    hints,
    isProjectsLoading,
    isDetailLoading,
    isExtracting,
    isMutating,
    listError,
    detailError,
    fetchProjects,
    fetchCategories,
    addCategory,
    removeCategory,
    selectProject,
    clearSelection,
    reloadSelected,
    createProject,
    updateProject,
    deleteProject,
    refreshProject,
    addHint,
  } = useSecurityStore()

  const [pendingDelete, setPendingDelete] = useState<{ id: string; name: string } | null>(null)
  const [pendingCatDelete, setPendingCatDelete] = useState<CategoryDef | null>(null)
  const [catFilter, setCatFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<ProjectStatus | 'all'>('all')
  const [query, setQuery] = useState('')
  const [showForm, setShowForm] = useState(false)

  // 注册表解析器：内置兜底 + 自定义。
  const catMeta = useMemo(() => makeCatMeta(categories.length ? categories : []), [categories])

  useEffect(() => {
    fetchProjects()
    fetchCategories()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function handleCreate(data: { name: string; target: string; priority: string; category: string; sessionIds: string[] }) {
    setShowForm(false)
    await createProject(data)
  }

  function handleEdit(updates: { name: string; category: string; status: ProjectStatus }) {
    if (selectedProjectId) void updateProject(selectedProjectId, updates)
  }

  function handleSetStatus(status: ProjectStatus) {
    if (selectedProjectId) void updateProject(selectedProjectId, { status })
  }

  function handleRefresh() {
    if (selectedProjectId) void refreshProject(selectedProjectId)
  }

  function handleAddHint(content: string) {
    if (selectedProjectId) void addHint(selectedProjectId, content)
  }

  async function confirmDelete() {
    if (!pendingDelete) return
    await deleteProject(pendingDelete.id)
    setPendingDelete(null)
  }

  async function confirmCatDelete() {
    if (!pendingCatDelete) return
    const removingId = pendingCatDelete.id
    await removeCategory(removingId)
    if (catFilter === removingId) setCatFilter('all')
    setPendingCatDelete(null)
  }

  const inDetail = selectedProjectId !== null

  return (
    <div className="flex h-full min-h-0 w-full">
      <CategoryRail
        categories={categories}
        projects={projects}
        catFilter={catFilter}
        statusFilter={statusFilter}
        onCatFilter={(c) => { setCatFilter(c); if (inDetail) clearSelection() }}
        onStatusFilter={(s) => { setStatusFilter(s); if (inDetail) clearSelection() }}
        onAddCategory={(label, color) => void addCategory(label, color)}
        onRemoveCategory={(def) => setPendingCatDelete(def)}
        busy={isMutating}
      />

      {inDetail ? (
        <DetailPanel
          selectedId={selectedProjectId}
          project={selectedProject}
          sessionSummaries={sessionSummaries}
          nodes={nodes}
          hints={hints}
          isExtracting={isExtracting}
          loading={isDetailLoading}
          error={detailError}
          busy={isMutating}
          categories={categories}
          catMeta={catMeta}
          onBack={() => clearSelection()}
          onEdit={handleEdit}
          onRetry={() => void reloadSelected()}
          onSetStatus={handleSetStatus}
          onRefresh={handleRefresh}
          onAddHint={handleAddHint}
          onDelete={() => {
            if (selectedProject) setPendingDelete({ id: selectedProject.meta.id, name: selectedProject.meta.name })
          }}
        />
      ) : (
        <BrowseView
          projects={projects}
          categories={categories}
          catMeta={catMeta}
          catFilter={catFilter}
          statusFilter={statusFilter}
          query={query}
          onQuery={setQuery}
          loading={isProjectsLoading}
          error={listError}
          onSelect={(id) => void selectProject(id)}
          onNewProject={() => setShowForm((v) => !v)}
          showForm={showForm}
          onCancelForm={() => setShowForm(false)}
          onCreate={handleCreate}
          creating={isMutating}
        />
      )}

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={confirmDelete}
        title="删除安全项目"
        body={`确定删除「${pendingDelete?.name ?? ''}」？项目的黑板、发现与关联记录将被移除，此操作不可撤销。`}
        confirmLabel="删除"
        cancelLabel="取消"
        confirmVariant="danger"
        loading={isMutating}
      />

      <ConfirmDialog
        open={pendingCatDelete !== null}
        onClose={() => setPendingCatDelete(null)}
        onConfirm={confirmCatDelete}
        title="删除分类"
        body={`确定删除分类「${pendingCatDelete?.label ?? ''}」？使用该分类的项目会被重置为「自定义」，项目本身不会删除。`}
        confirmLabel="删除"
        cancelLabel="取消"
        confirmVariant="danger"
        loading={isMutating}
      />
    </div>
  )
}
