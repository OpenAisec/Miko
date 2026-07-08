import { Check, Copy, GitFork } from 'lucide-react'
import { useTranslation } from '../../i18n'
import { useSettingsStore } from '../../stores/settingsStore'
import { formatExactMessageTimestamp, formatMessageTimestamp } from '../../lib/formatMessageTimestamp'
import { CopyButton } from '../shared/CopyButton'

export type MessageBranchAction = {
  label: string
  loading?: boolean
  onBranch: () => void
}

type Props = {
  copyText?: string
  copyLabel: string
  branchAction?: MessageBranchAction
  align?: 'start' | 'end'
  timestamp?: number
}

export function MessageActionBar({
  copyText,
  copyLabel,
  branchAction,
  align = 'start',
  timestamp,
}: Props) {
  const t = useTranslation()
  const locale = useSettingsStore((state) => state.locale)
  const hasCopy = Boolean(copyText?.trim())
  const timeLabel = typeof timestamp === 'number'
    ? formatMessageTimestamp(timestamp, t, locale)
    : ''
  const exactTimeLabel = typeof timestamp === 'number'
    ? formatExactMessageTimestamp(timestamp, locale)
    : ''

  if (!hasCopy && !branchAction) return null

  return (
    <div
      data-message-actions
      data-align={align}
      className={`pointer-events-none mt-2 flex h-7 w-full opacity-0 transition-opacity duration-150 group-hover:pointer-events-auto group-hover:opacity-100 group-focus-within:pointer-events-auto group-focus-within:opacity-100 ${
        align === 'end' ? 'justify-end' : 'justify-start'
      }`}
    >
      <div className="flex min-h-7 items-center gap-1.5">
        {hasCopy ? (
          <CopyButton
            text={copyText!}
            label={copyLabel}
            displayLabel={<Copy size={13} strokeWidth={2.2} aria-hidden="true" />}
            displayCopiedLabel={<Check size={13} strokeWidth={2.4} aria-hidden="true" />}
            onPointerUp={(event) => event.currentTarget.blur()}
            className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-transparent bg-transparent text-[var(--color-text-tertiary)] transition-colors hover:border-[var(--color-brand)]/30 hover:bg-[var(--color-surface-container-low)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-brand)]/35"
          />
        ) : null}
        {branchAction ? (
          <button
            type="button"
            onClick={branchAction.onBranch}
            disabled={branchAction.loading}
            aria-label={branchAction.label}
            title={branchAction.label}
            onPointerUp={(event) => event.currentTarget.blur()}
            className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-transparent bg-transparent text-[var(--color-text-tertiary)] transition-colors hover:border-[var(--color-brand)]/30 hover:bg-[var(--color-surface-container-low)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-brand)]/35 disabled:cursor-wait disabled:opacity-60"
          >
            <GitFork size={13} strokeWidth={2.2} aria-hidden="true" />
          </button>
        ) : null}
        {timeLabel ? (
          <span
            className="ml-1 inline-flex items-center text-[11px] font-medium tabular-nums text-[var(--color-text-tertiary)]"
            title={exactTimeLabel || timeLabel}
          >
            {timeLabel}
          </span>
        ) : null}
      </div>
    </div>
  )
}
