import { useState, useEffect, useRef } from 'react'
import { securityApi, type SessionBoardSnapshot } from '../../api/security'

/**
 * 会话级黑板面板（路 A：黑板归会话，会话视图内实时看它生长）。
 * 轮询 /sessions/:sid/board，有内容才显示。可折叠。只读展示，不写。
 */
const POLL_MS = 4000

function severityColor(s?: string): string {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'var(--color-error)'
    case 'high': return 'var(--color-warning)'
    case 'medium': return '#e6a817'
    case 'low': return 'var(--color-info)'
    default: return 'var(--color-text-tertiary)'
  }
}

function intentDot(status: string): string {
  switch (status) {
    case 'running': return 'bg-[var(--color-warning)]'
    case 'done': return 'bg-[var(--color-success)]'
    case 'failed': return 'bg-[var(--color-text-tertiary)]'
    default: return 'bg-[var(--color-text-tertiary)]'
  }
}

function intentLabel(status: string): string {
  return { open: '待探', running: '探索中', done: '探完', failed: '探死' }[status] ?? status
}

export function SessionBoardPanel({ sessionId }: { sessionId: string }) {
  const [snap, setSnap] = useState<SessionBoardSnapshot | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    let alive = true
    const poll = async () => {
      try {
        const s = await securityApi.getSessionBoard(sessionId)
        if (alive) setSnap(s)
      } catch {
        // 轮询失败不打断，下一拍重试
      }
    }
    void poll()
    timer.current = setInterval(poll, POLL_MS)
    return () => {
      alive = false
      if (timer.current) clearInterval(timer.current)
    }
  }, [sessionId])

  // 无快照 / 空黑板（未开测试模式或还没产出）→ 不显示
  const hasContent = !!snap && (snap.facts.length > 0 || snap.intents.length > 0 || snap.hints.length > 0)
  if (!hasContent) return null

  const findings = snap!.facts.filter((f) => f.type === 'finding')
  const assetsFacts = snap!.facts.filter((f) => f.type !== 'finding')

  return (
    <div className="shrink-0 border-b border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
      <button
        onClick={() => setCollapsed((v) => !v)}
        className="flex w-full items-center gap-2 px-4 py-2 text-left"
      >
        <span className="material-symbols-outlined text-[14px] text-[var(--color-error)]">security</span>
        <span className="text-[11px] font-bold uppercase tracking-widest text-[var(--color-text-secondary)]">黑板</span>
        <span className="text-[11px] text-[var(--color-text-tertiary)]">
          {findings.length} 发现 · {snap!.intents.length} 方向 · {assetsFacts.length} 事实
        </span>
        <span className={`material-symbols-outlined ml-auto text-[14px] text-[var(--color-text-tertiary)] transition-transform ${collapsed ? '' : 'rotate-180'}`}>
          expand_more
        </span>
      </button>

      {!collapsed && (
        <div className="max-h-[220px] overflow-y-auto px-4 pb-3">
          {snap!.target && (
            <div className="mb-2 text-[11px] text-[var(--color-text-tertiary)]">
              <span className="text-[var(--color-text-secondary)]">目标</span> {snap!.target}
            </div>
          )}

          {findings.length > 0 && (
            <div className="mb-2">
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">发现</div>
              {findings.map((f) => (
                <div key={f.id} className="flex items-start gap-2 py-0.5">
                  <span className="mt-1 inline-block h-2 w-2 flex-shrink-0 rounded-full" style={{ background: severityColor(f.severity) }} />
                  <span className="min-w-0 flex-1">
                    <span className="text-xs text-[var(--color-text-primary)]">{f.title}</span>
                    {f.result && <span className="block truncate text-[11px] text-[var(--color-text-tertiary)]">{f.result}</span>}
                  </span>
                </div>
              ))}
            </div>
          )}

          {snap!.intents.length > 0 && (
            <div className="mb-2">
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">探索方向</div>
              {snap!.intents.map((it) => (
                <div key={it.id} className="flex items-center gap-2 py-0.5">
                  <span className={`inline-block h-2 w-2 flex-shrink-0 rounded-full ${intentDot(it.status)}`} />
                  <span className="truncate text-xs text-[var(--color-text-primary)]">{it.title}</span>
                  <span className="ml-auto flex-shrink-0 text-[10px] text-[var(--color-text-tertiary)]">{intentLabel(it.status)}</span>
                </div>
              ))}
            </div>
          )}

          {assetsFacts.length > 0 && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">事实 / 资产</div>
              {assetsFacts.map((f) => (
                <div key={f.id} className="truncate py-0.5 text-xs text-[var(--color-text-secondary)]">{f.title}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
