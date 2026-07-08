import { useState, useEffect } from 'react'
import { securityApi, type SessionBoardSnapshot } from '../../api/security'
import { ExplorationTree } from '../topology/ExplorationTree'

/**
 * 会话级黑板面板（方案 A：保留原列表 + 思维链路图抽屉）
 * - 折叠时：顶部横条（X发现·Y意图统计）
 * - 展开时：220px 高列表区（发现/意图/事实分类列表）
 * - 列表顶部「查看链路图」按钮 → 打开右侧 800px 抽屉
 * - 思维链路图：树状递归组件，位置固定，按阶段分组
 * - 手动刷新（不再自动轮询）
 */

function severityClass(s?: string): string {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'bg-red-100 text-red-700'
    case 'high': return 'bg-orange-100 text-orange-700'
    case 'medium': return 'bg-amber-100 text-amber-700'
    case 'low': return 'bg-blue-100 text-blue-700'
    default: return 'bg-slate-100 text-slate-600'
  }
}

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

function intentStatusLabel(status: string): string {
  return intentLabel(status)
}

export function SessionBoardDrawer({ sessionId }: { sessionId: string }) {
  const [snap, setSnap] = useState<SessionBoardSnapshot | null>(null)
  const [collapsed, setCollapsed] = useState(false) // 横条折叠/展开（控制列表显示）
  const [topologyOpen, setTopologyOpen] = useState(false) // 链路图抽屉打开/关闭
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [drawerWidth, setDrawerWidth] = useState(800) // 抽屉宽度（可调节）
  const [isResizing, setIsResizing] = useState(false) // 是否正在调整大小

  // 首次加载黑板数据
  useEffect(() => {
    let alive = true
    const poll = async () => {
      try {
        const s = await securityApi.getSessionBoard(sessionId)
        if (alive) setSnap(s)
      } catch {
        // 首次加载失败不阻塞
      }
    }
    void poll()
    return () => {
      alive = false
    }
  }, [sessionId])

  // 手动刷新
  const handleRefresh = async () => {
    try {
      const s = await securityApi.getSessionBoard(sessionId)
      setSnap(s)
    } catch (err) {
      console.error('刷新黑板失败', err)
    }
  }

  // 拖拽调整抽屉宽度
  const handleMouseDown = (e: React.MouseEvent) => {
    e.preventDefault()
    setIsResizing(true)
  }

  useEffect(() => {
    if (!isResizing) return

    const handleMouseMove = (e: MouseEvent) => {
      // 从右边缘算起，鼠标 X 位置决定宽度
      const newWidth = window.innerWidth - e.clientX
      // 限制宽度：最小 400px，最大 80% 窗口宽度
      const clampedWidth = Math.max(400, Math.min(newWidth, window.innerWidth * 0.8))
      setDrawerWidth(clampedWidth)
    }

    const handleMouseUp = () => {
      setIsResizing(false)
    }

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
    }
  }, [isResizing])

  // 测试模式已开（goal 有值）或已有节点 → 显示黑板区域。
  // 仅靠节点数会导致"刚开测试模式、agent 还没写"时整个区域消失。
  const hasContent = !!snap && (
    (snap.goal?.trim().length ?? 0) > 0 ||
    snap.facts.length > 0 || snap.intents.length > 0 || snap.hints.length > 0
  )
  if (!hasContent) return null

  const findings = snap!.facts.filter((f) => f.type === 'finding')
  const assetsFacts = snap!.facts.filter((f) => f.type !== 'finding')

  // 选中节点详情
  const selectedNode = selectedNodeId
    ? snap!.facts.find((f) => f.id === selectedNodeId) || snap!.intents.find((it) => it.id === selectedNodeId)
    : null

  return (
    <>
      {/* 顶部横条 */}
      <div className="shrink-0 border-b border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
        <button
          onClick={() => setCollapsed((v) => !v)}
          className="flex w-full items-center gap-2 px-4 py-2 text-left hover:bg-[var(--color-surface-hover)]"
        >
          <span className="material-symbols-outlined text-[14px] text-[var(--color-error)]">security</span>
          <span className="text-[11px] font-bold uppercase tracking-widest text-[var(--color-text-secondary)]">黑板</span>
          <span className="text-[11px] text-[var(--color-text-tertiary)]">
            {findings.length} 发现 · {snap!.intents.length} 意图 · {assetsFacts.length} 事实
          </span>
          <span className={`material-symbols-outlined ml-auto text-[14px] text-[var(--color-text-tertiary)] transition-transform ${collapsed ? '' : 'rotate-180'}`}>
            expand_more
          </span>
        </button>

        {/* 展开时显示原列表内容（220px 高） */}
        {!collapsed && (
          <div className="max-h-[220px] overflow-y-auto px-4 pb-3">
            {/* 顶部按钮区域 */}
            <div className="mb-3 pt-2 flex items-center gap-2">
              <button
                onClick={handleRefresh}
                className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container)] px-3 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] transition-colors"
                title="刷新黑板数据"
              >
                <span className="material-symbols-outlined text-[16px]">refresh</span>
                <span>刷新</span>
              </button>
              <button
                onClick={() => setTopologyOpen(true)}
                className="flex items-center gap-2 rounded-lg border border-[var(--color-brand)] bg-[var(--color-brand)]/10 px-3 py-2 text-sm font-medium text-[var(--color-brand)] hover:bg-[var(--color-brand)]/20 transition-colors"
              >
                <span className="material-symbols-outlined text-[16px]">account_tree</span>
                <span>查看链路图</span>
              </button>
            </div>

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

      {/* 思维链路图抽屉（可调节宽度，从右侧滑入） */}
      {topologyOpen && (
        <div
          className="fixed top-0 right-0 bottom-0 border-l border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl flex flex-col z-50 animate-slide-in"
          style={{ width: `${drawerWidth}px` }}
        >
          {/* 左侧拖拽分割线 */}
          <div
            className="absolute left-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-blue-500 transition-colors group"
            onMouseDown={handleMouseDown}
          >
            <div className="absolute left-0 top-0 bottom-0 w-4 -ml-1.5" />
          </div>

          {/* 抽屉顶栏 */}
          <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-3 bg-slate-800">
            <span className="text-sm font-bold text-slate-100">探索链路图</span>
            <button
              onClick={() => {
                setTopologyOpen(false)
                setSelectedNodeId(null)
              }}
              className="text-slate-400 hover:text-slate-100 text-xl leading-none transition-colors"
            >
              ×
            </button>
          </div>

          {/* 链路图区（65%）。min-h-0 解开 flex 子项默认 min-height:auto，
              让它尊重 65% 份额、把溢出交给内层 ExplorationTree 的 overflow-y-auto 滚动，
              而不是被内容撑到全高、把下方详情区顶出抽屉底边。 */}
          <div className="flex-[65] min-h-0 overflow-hidden border-b border-slate-700 bg-slate-900">
            <ExplorationTree snapshot={snap!} onSelectNode={setSelectedNodeId} className="w-full h-full" />
          </div>

          {/* 节点详情面板（35%）。同样 min-h-0，详情长时自身独立滚动。 */}
          <div className="flex-[35] min-h-0 overflow-y-auto p-4 bg-slate-900">
            {selectedNode ? (
              <NodeDetail node={selectedNode} />
            ) : (
              <div className="text-xs text-slate-400 text-center py-12">点击节点查看详情</div>
            )}
          </div>
        </div>
      )}

      {/* 挤压会话区（链路图打开时） */}
      {topologyOpen && (
        <style>{`
          [data-testid="active-session-chat-column"] {
            margin-right: ${drawerWidth}px !important;
            transition: margin-right 0.1s ease-out;
          }
          @keyframes slide-in {
            from { transform: translateX(100%); }
            to { transform: translateX(0); }
          }
          .animate-slide-in {
            animation: slide-in 0.3s ease-out;
          }
        `}</style>
      )}
    </>
  )
}

/** 节点详情子组件 */
function NodeDetail({ node }: { node: any }) {
  const isFact = 'severity' in node
  const isIntent = 'status' in node
  const isFinding = isFact && node.type === 'finding'

  const typeLabel = isFinding ? '发现' : isIntent ? '意图' : '事实'

  return (
    <div className="space-y-4">
      {/* 节点类型和状态标签 */}
      <div className="flex items-center gap-2">
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-700 text-slate-300">
          {typeLabel}
        </span>
        {isFinding && node.severity && (
          <span className={`px-2 py-0.5 rounded text-xs font-bold ${severityClass(node.severity)}`}>
            {node.severity.toUpperCase()}
          </span>
        )}
        {isIntent && (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-600/20 text-amber-400">
            {intentStatusLabel(node.status)}
          </span>
        )}
      </div>

      {/* 节点标题 */}
      <div className="text-base font-bold text-slate-100 leading-tight">{node.title}</div>

      {/* 节点结果 */}
      {node.result && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-3">
          <div className="text-slate-400 text-[10px] font-semibold uppercase tracking-wide mb-1.5">结果</div>
          <div className="text-sm text-slate-200 leading-relaxed">{node.result}</div>
        </div>
      )}

      {/* 查看 transcript 链接 */}
      {isFinding && (
        <div className="pt-3 border-t border-slate-700">
          <a href="#" className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
            <span className="material-symbols-outlined text-[16px]">open_in_new</span>
            <span>查看探索子 agent 完整 transcript</span>
          </a>
        </div>
      )}
    </div>
  )
}
