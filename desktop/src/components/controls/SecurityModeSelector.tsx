import { useState, useRef, useEffect } from 'react'
import { useChatStore } from '../../stores/chatStore'
import { useTabStore } from '../../stores/tabStore'
import { ActionDialog } from '../shared/ActionDialog'

/**
 * 探索模式（黑板）开关。挂在会话工具栏。
 * 黑板归会话——开启即进黑板模式，不强制先选项目（事后可沉淀成项目）。
 * 通用探索思路（安全测试只是用途之一，也可用于代码审计/调研/分析等）。
 * 可选填目标（不填则 agent 从对话推导）。开启 = 探索子 agent 对目标完全跳过权限，故走确认弹窗。
 */
type Props = { compact?: boolean }

export function SecurityModeSelector({ compact = false }: Props = {}) {
  const setSessionSecurityMode = useChatStore((s) => s.setSessionSecurityMode)
  const activeTabId = useTabStore((s) => s.activeTabId)

  // 从 store 读取当前会话的探索模式状态
  const session = useChatStore((s) =>
    activeTabId ? s.sessions[activeTabId] : null
  )
  const enabled = session?.securityModeEnabled || false
  const currentTarget = session?.securityModeTarget || ''

  const [open, setOpen] = useState(false)
  const [inputTarget, setInputTarget] = useState('')  // 输入框的临时状态
  const [confirming, setConfirming] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      const t = e.target as Node
      if (ref.current && !ref.current.contains(t) && !menuRef.current?.contains(t)) setOpen(false)
    }
    const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onEsc)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onEsc)
    }
  }, [open])

  function applyEnable() {
    if (!activeTabId) return
    setSessionSecurityMode(activeTabId, true, { target: inputTarget.trim() || undefined })
    setOpen(false)
    setConfirming(false)
    setInputTarget('')  // 清空输入框
  }

  function disable() {
    if (!activeTabId) return
    setSessionSecurityMode(activeTabId, false)
    setOpen(false)
  }

  const buttonClass = compact
    ? 'h-8 w-8 justify-center rounded-full p-0'
    : 'gap-1.5 rounded-full px-2.5 py-1.5 text-xs'

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        aria-haspopup="menu"
        aria-expanded={open}
        title={enabled ? '探索模式已开启' : '探索模式'}
        className={`flex items-center font-medium transition-colors ${buttonClass} ${
          enabled
            ? 'bg-[var(--color-error-container)] text-[var(--color-error)]'
            : 'bg-[var(--color-surface-container-low)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]'
        }`}
      >
        <span className="material-symbols-outlined text-[14px]">travel_explore</span>
        {!compact && (
          <>
            <span>{enabled ? '探索中' : '探索模式'}</span>
            <span className="material-symbols-outlined text-[12px]">expand_more</span>
          </>
        )}
      </button>

      {open && (
        <div
          ref={menuRef}
          role="menu"
          className="absolute left-0 bottom-full mb-2 w-[320px] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-container-lowest)] py-2 shadow-[var(--shadow-dropdown)] z-50"
        >
          <div className="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-[var(--color-outline)]">
            探索模式（黑板）
          </div>

          {enabled ? (
            <div className="px-4 py-2">
              <div className="text-sm text-[var(--color-text-primary)]">本会话已进入黑板模式</div>
              <div className="mt-0.5 text-xs text-[var(--color-text-tertiary)]">
                agent 边探边写黑板，对目标完全跳过权限。
              </div>
              {currentTarget && (
                <div className="mt-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container)] px-2.5 py-1.5 text-xs text-[var(--color-text-secondary)]">
                  目标：{currentTarget}
                </div>
              )}
              <button
                onClick={disable}
                className="mt-2.5 w-full rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)]"
              >
                关闭探索模式
              </button>
            </div>
          ) : (
            <div className="px-4 py-2">
              <div className="text-xs text-[var(--color-text-tertiary)]">
                开启后 agent 在本会话自主探索目标，边探边写黑板。先开探索，事后可沉淀成项目。
              </div>
              <label className="mt-2.5 block text-[11px] font-semibold text-[var(--color-text-secondary)]">
                目标（可选，不填则从对话推导）
              </label>
              <input
                value={inputTarget}
                onChange={(e) => setInputTarget(e.target.value)}
                placeholder="目标 URL / 路径 / 主题…"
                className="mt-1 w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-brand)] focus:outline-none"
              />
              <button
                onClick={() => { setOpen(false); setConfirming(true) }}
                className="mt-2.5 w-full rounded-lg bg-[var(--color-brand)] px-3 py-1.5 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                开启探索模式
              </button>
            </div>
          )}
        </div>
      )}

      <ActionDialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title="开启探索模式"
        width={420}
        body={(
          <div className="space-y-3">
            <p className="text-xs font-medium text-[var(--color-error)]">
              开启后，本会话的 agent 将以黑板模式自主探索目标，完全跳过权限确认。
            </p>
            <p className="text-xs leading-relaxed text-[var(--color-text-secondary)]">
              仅在你有授权的目标上使用。会话将重启以进入黑板模式。
            </p>
            {inputTarget.trim() && (
              <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-container)] px-3 py-2 text-xs text-[var(--color-text-primary)]">
                {inputTarget.trim()}
              </div>
            )}
          </div>
        )}
        actions={[
          { label: '取消', onClick: () => setConfirming(false), variant: 'secondary' },
          { label: '开启', onClick: applyEnable, variant: 'danger' },
        ]}
      />
    </div>
  )
}
