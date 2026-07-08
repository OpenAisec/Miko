import { useEffect, useMemo, useState } from 'react'
import { useCatalogStore } from '../../stores/catalogStore'
import type { ToolDef } from '../../api/catalog'

/** 分类 id → 中文标签 + 顺序（镜像后端 BUILTIN_CATEGORIES）。 */
const CATEGORY_META: Record<string, { label: string; order: number }> = {
  web: { label: 'Web 渗透', order: 0 },
  audit: { label: '代码审计', order: 1 },
  asset: { label: '资产收集', order: 2 },
  mobile: { label: '移动端', order: 3 },
  binary: { label: '二进制', order: 4 },
  redteam: { label: '红队·横向', order: 5 },
  forensics: { label: '取证·隐写', order: 6 },
  cloud: { label: '云·容器', order: 7 },
  custom: { label: '自定义', order: 8 },
}

function catLabel(id: string): string {
  return CATEGORY_META[id]?.label ?? id
}

/** 探测状态徽标。 */
function StatusBadge({ installed, version }: { installed: boolean | null; version?: string }) {
  if (installed === true) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-success-container)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-on-success-container,#1b5e20)]">
        <span className="material-symbols-outlined text-[12px]">check_circle</span>
        已装{version ? ` ${version}` : ''}
      </span>
    )
  }
  if (installed === false) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-[var(--color-border)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-tertiary)]">
        <span className="material-symbols-outlined text-[12px]">cancel</span>
        未装
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-dashed border-[var(--color-border)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-tertiary)]">
      未知
    </span>
  )
}

function ToolCard({ tool, onDelete }: { tool: ToolDef; onDelete: (t: ToolDef) => void }) {
  const { setToolPath, clearToolPath } = useCatalogStore()
  const [editingPath, setEditingPath] = useState(false)
  const [pathInput, setPathInput] = useState(tool.userPath ?? '')
  const [saving, setSaving] = useState(false)
  const needsPath = tool.requiresUserPath === true

  return (
    <div className="group rounded-xl border border-transparent px-3 py-3 transition-all hover:border-[var(--color-border-focus)] hover:bg-[var(--color-surface-hover)]">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)]">
          {tool.invoke === 'mcp' ? 'cable' : 'terminal'}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-[var(--color-text-primary)] break-all">{tool.name}</span>
            {needsPath ? (
              tool.installed === true ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-success-container)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-on-success-container,#1b5e20)]">
                  <span className="material-symbols-outlined text-[12px]">check_circle</span>已配置
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-full border border-dashed border-[var(--color-border)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-tertiary)]">
                  未配置
                </span>
              )
            ) : (
              <StatusBadge installed={tool.installed} version={tool.version} />
            )}
            <span className="rounded-full bg-[var(--color-surface-container-high)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-tertiary)]">
              {tool.invoke === 'mcp' ? 'MCP' : 'CLI'}
            </span>
            {tool.bundled && (
              <span className="rounded-full bg-[var(--color-brand)]/12 px-2 py-0.5 text-[10px] font-medium text-[var(--color-brand)]">
                内置
              </span>
            )}
            {needsPath && (
              <span className="rounded-full bg-[var(--color-surface-container-high)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-tertiary)]">
                需配置
              </span>
            )}
          </div>
          <p className="mt-1 text-xs leading-5 text-[var(--color-text-secondary)] break-words">{tool.shortDescription}</p>
          {tool.usage && (
            <p className="mt-1 font-mono text-[11px] leading-5 text-[var(--color-text-tertiary)] break-all">{tool.usage}</p>
          )}
          {/* requiresUserPath 工具：显示当前路径 + 设置入口 */}
          {needsPath && !editingPath && tool.userPath && (
            <p className="mt-1 font-mono text-[11px] leading-5 text-[var(--color-text-tertiary)] break-all">
              路径：{tool.userPath}
            </p>
          )}
          {needsPath && !editingPath && (
            <button
              onClick={() => { setPathInput(tool.userPath ?? ''); setEditingPath(true) }}
              className="mt-1.5 inline-flex items-center gap-1 rounded-lg border border-[var(--color-border)] px-2 py-1 text-[11px] text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)]"
            >
              <span className="material-symbols-outlined text-[14px]">folder_open</span>
              {tool.userPath ? '修改路径' : '设置路径'}
            </button>
          )}
          {needsPath && editingPath && (
            <div className="mt-2 flex flex-col gap-1.5">
              {tool.pathHint && (
                <p className="text-[11px] leading-4 text-[var(--color-text-tertiary)]">{tool.pathHint}</p>
              )}
              <input
                value={pathInput}
                onChange={(e) => setPathInput(e.target.value)}
                placeholder="填本机可执行/脚本的绝对路径"
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 font-mono text-[11px] text-[var(--color-text-primary)] focus:border-[var(--color-brand)] focus:outline-none"
              />
              <div className="flex items-center gap-2">
                <button
                  disabled={saving || !pathInput.trim()}
                  onClick={async () => {
                    setSaving(true)
                    try { await setToolPath(tool.id, pathInput.trim()); setEditingPath(false) }
                    catch (e) { alert(e instanceof Error ? e.message : '设置失败') }
                    finally { setSaving(false) }
                  }}
                  className="rounded-lg bg-[var(--color-brand)] px-3 py-1 text-[11px] font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-40"
                >
                  {saving ? '保存中…' : '保存'}
                </button>
                <button
                  onClick={() => setEditingPath(false)}
                  className="rounded-lg border border-[var(--color-border)] px-3 py-1 text-[11px] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
                >
                  取消
                </button>
                {tool.userPath && (
                  <button
                    onClick={async () => { await clearToolPath(tool.id); setEditingPath(false) }}
                    className="rounded-lg px-3 py-1 text-[11px] text-[var(--color-error)] hover:bg-[var(--color-error-container)]"
                  >
                    清除
                  </button>
                )}
              </div>
            </div>
          )}
          {tool.installed === false && tool.bundled && (
            <p className="mt-1 text-[11px] leading-5 text-[var(--color-text-tertiary)] break-words">
              内置二进制未就位（该平台 data/tools/bin/ 下缺文件，随发布包补齐）
            </p>
          )}
          {tool.installed === false && !tool.bundled && !needsPath && tool.installHint && (
            <p className="mt-1 text-[11px] leading-5 text-[var(--color-text-tertiary)] break-words">
              安装：{tool.installHint}
            </p>
          )}
        </div>
        {!tool.protected && (
          <button
            onClick={() => onDelete(tool)}
            className="shrink-0 inline-flex items-center rounded-lg px-2 py-1 text-[var(--color-error)] opacity-0 transition-opacity hover:bg-[var(--color-error-container)] group-hover:opacity-100"
            aria-label="删除工具"
          >
            <span className="material-symbols-outlined text-[16px]">delete</span>
          </button>
        )}
      </div>
    </div>
  )
}

export function ToolsSettings() {
  const { tools, isLoading, isProbing, error, fetchTools, probe, removeTool } = useCatalogStore()
  const [pendingDelete, setPendingDelete] = useState<ToolDef | null>(null)
  // 折叠状态：存已展开的 category id。默认全折叠（工具多，全展开太长）。
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const toggleCat = (cat: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(cat) ? next.delete(cat) : next.add(cat)
      return next
    })

  useEffect(() => {
    void fetchTools()
  }, [fetchTools])

  const grouped = useMemo(() => {
    const map: Record<string, ToolDef[]> = {}
    for (const t of tools) (map[t.category] ??= []).push(t)
    return map
  }, [tools])

  const sortedCats = useMemo(
    () =>
      Object.keys(grouped).sort(
        (a, b) => (CATEGORY_META[a]?.order ?? 99) - (CATEGORY_META[b]?.order ?? 99) || a.localeCompare(b),
      ),
    [grouped],
  )

  const availableCount = useMemo(() => tools.filter((t) => t.installed === true).length, [tools])

  return (
    <div className="flex flex-col gap-4 min-w-0">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-[var(--color-text-primary)]">工具台账</h3>
          <p className="mt-1 text-xs leading-5 text-[var(--color-text-tertiary)]">
            探索模式下 agent 可查询的外部安全工具。共 {tools.length} 个，{availableCount} 个本机已装。
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            onClick={() => setExpanded((prev) => (prev.size === sortedCats.length ? new Set() : new Set(sortedCats)))}
            className="inline-flex items-center gap-1 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)]"
          >
            <span className="material-symbols-outlined text-[16px]">
              {expanded.size === sortedCats.length && sortedCats.length > 0 ? 'unfold_less' : 'unfold_more'}
            </span>
            {expanded.size === sortedCats.length && sortedCats.length > 0 ? '全部收起' : '全部展开'}
          </button>
          <button
            onClick={() => void probe()}
            disabled={isProbing}
            className="inline-flex items-center gap-1 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
          >
            <span className={`material-symbols-outlined text-[16px] ${isProbing ? 'animate-spin' : ''}`}>refresh</span>
            {isProbing ? '探测中…' : '重新探测'}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-[var(--color-error)] bg-[var(--color-error-container)] px-4 py-3 text-sm text-[var(--color-on-error-container)]">
          {error}
        </div>
      )}

      {isLoading && tools.length === 0 ? (
        <div className="text-sm text-[var(--color-text-tertiary)] px-1 py-8 text-center">加载中…</div>
      ) : tools.length === 0 ? (
        <div className="text-sm text-[var(--color-text-tertiary)] px-1 py-8 text-center">
          暂无工具。台账目录 data/tools/ 为空。
        </div>
      ) : (
        sortedCats.map((cat) => {
          const group = grouped[cat]!
          const avail = group.filter((t) => t.installed === true).length
          const isOpen = expanded.has(cat)
          return (
            <section
              key={cat}
              className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden min-w-0"
            >
              <button
                type="button"
                onClick={() => toggleCat(cat)}
                className="flex w-full items-center gap-2 px-5 py-4 text-left transition-colors hover:bg-[var(--color-surface-hover)] bg-[var(--color-surface-container-low)]"
              >
                <span
                  className={`material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)] transition-transform ${isOpen ? 'rotate-90' : ''}`}
                >
                  chevron_right
                </span>
                <h4 className="text-sm font-semibold text-[var(--color-text-primary)]">{catLabel(cat)}</h4>
                <span className="text-xs text-[var(--color-text-tertiary)]">{group.length} 个</span>
                {avail > 0 && (
                  <span className="rounded-full bg-[var(--color-success-container)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-on-success-container,#1b5e20)]">
                    {avail} 可用
                  </span>
                )}
              </button>
              {isOpen && (
                <div className="flex flex-col p-2 border-t border-[var(--color-border)]">
                  {group.map((tool) => (
                    <ToolCard key={tool.id} tool={tool} onDelete={setPendingDelete} />
                  ))}
                </div>
              )}
            </section>
          )
        })
      )}

      {pendingDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={() => setPendingDelete(null)}>
          <div
            className="w-[min(420px,90vw)] rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="text-sm font-semibold text-[var(--color-text-primary)]">删除工具「{pendingDelete.name}」？</div>
            <p className="mt-1 text-xs leading-5 text-[var(--color-text-tertiary)]">
              将删除台账文件 data/tools/{pendingDelete.id}.yaml。不影响本机已安装的工具本身。
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                onClick={() => setPendingDelete(null)}
                className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
              >
                取消
              </button>
              <button
                onClick={async () => {
                  const id = pendingDelete.id
                  setPendingDelete(null)
                  try {
                    await removeTool(id)
                  } catch (e) {
                    alert(e instanceof Error ? e.message : '删除失败')
                  }
                }}
                className="rounded-lg bg-[var(--color-error)] px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
              >
                确认删除
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
