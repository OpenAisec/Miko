import { useEffect } from 'react'
import { useTranslation } from '../../i18n'
import { MarkdownRenderer } from '../markdown/MarkdownRenderer'
import { isTauriRuntime } from '../../lib/desktopRuntime'
import { useUpdateStore } from '../../stores/updateStore'

export function UpdateChecker() {
  const t = useTranslation()
  const status = useUpdateStore((s) => s.status)
  const availableVersion = useUpdateStore((s) => s.availableVersion)
  const releaseNotes = useUpdateStore((s) => s.releaseNotes)
  const error = useUpdateStore((s) => s.error)
  const shouldPrompt = useUpdateStore((s) => s.shouldPrompt)
  const initialize = useUpdateStore((s) => s.initialize)
  const installUpdate = useUpdateStore((s) => s.installUpdate)
  const dismissPrompt = useUpdateStore((s) => s.dismissPrompt)

  useEffect(() => {
    void initialize()
  }, [initialize])

  if (!isTauriRuntime()) return null

  const showPopup = shouldPrompt && !!availableVersion && status === 'downloaded'

  if (!showPopup) return null

  const statusText = t('update.readyBody', { version: availableVersion })

  return (
    <div className="fixed bottom-4 left-1/2 z-[120] w-[min(360px,calc(100vw-2rem))] -translate-x-1/2">
      <div className="bg-[var(--color-surface-container-low)] border border-[var(--color-border)] rounded-[var(--radius-lg)] shadow-[var(--shadow-dropdown)] p-3">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">
          {t('update.readyTitle')}
        </p>
        <p className="mt-1 text-xs leading-5 text-[var(--color-text-secondary)]">
          {statusText}
        </p>

        {releaseNotes && (
          <div className="mt-2 max-h-28 overflow-y-auto rounded-lg border border-[var(--color-border)]/60 bg-[var(--color-surface)]/70 px-3 py-2">
            <MarkdownRenderer
              content={releaseNotes}
              className="text-xs leading-5 text-[var(--color-text-secondary)] [&_h1]:mb-2 [&_h1]:text-sm [&_h1]:font-semibold [&_h2]:mb-1.5 [&_h2]:text-xs [&_h2]:font-semibold [&_p]:my-1.5 [&_p]:text-xs [&_p]:leading-5 [&_ul]:my-1.5 [&_ol]:my-1.5"
            />
          </div>
        )}

        {error && (
          <p className="mt-2 text-xs text-[var(--color-error)]">
            {t('update.failed', { error })}
          </p>
        )}

        {status === 'downloaded' && (
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => void installUpdate()}
              className="px-3 py-1 text-xs font-medium rounded-[var(--radius-md)] bg-[var(--color-text-accent)] text-white hover:opacity-90 transition-opacity"
            >
              {t('update.installAndRestart')}
            </button>
            <button
              onClick={dismissPrompt}
              className="px-3 py-1 text-xs text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)] transition-colors"
            >
              {t('update.later')}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
