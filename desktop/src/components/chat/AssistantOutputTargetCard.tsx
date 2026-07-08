import { useCallback, useState } from 'react'
import type { MouseEvent as ReactMouseEvent } from 'react'
import { ChevronDown, ExternalLink, Globe } from 'lucide-react'
import type { AssistantOutputTarget } from '../../lib/assistantOutputTargets'
import { useTranslation, type TranslationKey } from '../../i18n'
import { OpenWithMenu } from '../common/OpenWithMenu'
import { buildOpenWithItems, describeFileType, type OpenWithItem } from '../../lib/openWithItems'
import { openWithContextForHref } from '../../lib/openWithContextForHref'
import { handlePreviewLink } from '../../lib/handlePreviewLink'
import { getServerBaseUrl } from '../../lib/desktopRuntime'
import { useOpenTargetStore } from '../../stores/openTargetStore'
import { useBrowserPanelStore } from '../../stores/browserPanelStore'
import { useWorkspacePanelStore } from '../../stores/workspacePanelStore'

type Props = {
  target: AssistantOutputTarget
  sessionId: string
  workDir?: string
}

export function AssistantOutputTargetCard({ target, sessionId, workDir }: Props) {
  const t = useTranslation()
  const [openWith, setOpenWith] = useState<{ items: OpenWithItem[]; anchor: DOMRect; triggerEl: HTMLElement } | null>(null)

  const isLocalhost = target.kind === 'localhost-url'
  const typeInfo = describeFileType(target.normalizedPath ?? target.href)
  const icon = typeInfo.icon
  const badge = isLocalhost
    ? t('assistantOutputs.kind.localhost')
    : target.kind === 'local-html'
      ? t('assistantOutputs.kind.html')
      : target.kind === 'markdown'
        ? t('assistantOutputs.kind.markdown')
        : t('assistantOutputs.kind.image')
  const subtitle = target.subtitle ?? target.normalizedPath ?? target.href
  const showSubtitle = subtitle !== target.title

  const handleOpen = useCallback((event: ReactMouseEvent<HTMLButtonElement>) => {
    event.stopPropagation()
    handlePreviewLink(target.href, {
      sessionId,
      serverBaseUrl: getServerBaseUrl(),
      openBrowser: (id, url) => useBrowserPanelStore.getState().open(id, url),
      openFilePreview: (id, path) => {
        void useWorkspacePanelStore.getState().openPreview(id, path, 'file')
      },
      openExternal: (url) => {
        void import('@tauri-apps/plugin-shell')
          .then((m) => m.open(url))
          .catch(() => window.open(url, '_blank'))
      },
    })
  }, [sessionId, target.href])

  const handleOpenWith = useCallback((event: ReactMouseEvent<HTMLButtonElement>) => {
    event.stopPropagation()
    // Toggle: a second click on the same trigger closes the menu. OpenWithMenu's
    // outside-mousedown ignores the trigger, so the trigger's own click is the
    // only path that can close it on re-click.
    if (openWith) {
      setOpenWith(null)
      return
    }
    const triggerEl = event.currentTarget
    const rect = triggerEl.getBoundingClientRect()
    void (async () => {
      await useOpenTargetStore.getState().ensureTargets()
      const targets = useOpenTargetStore.getState().targets
      const ctx = openWithContextForHref(target.href, {
        sessionId,
        serverBaseUrl: getServerBaseUrl(),
        workDir,
      })
      if (!ctx) return
      const items = buildOpenWithItems(ctx, targets, {
        openInAppBrowser: (url) => useBrowserPanelStore.getState().open(sessionId, url),
        openSystem: (p) => { void import('@tauri-apps/plugin-shell').then((m) => m.open(p)).catch(() => window.open(p, '_blank')) },
        openWorkspacePreview: (relPath) => { void useWorkspacePanelStore.getState().openPreview(sessionId, relPath, 'file') },
        openTarget: (id, abs) => { void useOpenTargetStore.getState().openTarget(id, abs) },
        t: (k, v) => t(k as TranslationKey, v),
      })
      setOpenWith({ items, anchor: rect, triggerEl })
    })()
  }, [openWith, sessionId, t, target.href, workDir])

  return (
    <section className="flex items-start gap-3 rounded-[var(--radius-lg)] border border-[var(--color-border)]/70 bg-[var(--color-surface-container-low)] px-3 py-2.5 shadow-sm">
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[var(--radius-md)] bg-[var(--color-surface)] text-[var(--color-text-secondary)]">
        {isLocalhost ? (
          <Globe size={17} strokeWidth={2.1} aria-hidden="true" />
        ) : (
          <span className="material-symbols-outlined text-[20px]" aria-hidden="true">{icon}</span>
        )}
      </span>

      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-semibold text-[var(--color-text-primary)]">
            {target.title}
          </span>
          <span className="shrink-0 rounded-full border border-[var(--color-border)]/70 bg-[var(--color-surface)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-tertiary)]">
            {badge}
          </span>
        </div>
        {showSubtitle && (
          <div className="mt-1 truncate text-xs text-[var(--color-text-tertiary)]" title={subtitle}>
            {subtitle}
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1.5">
        <button
          type="button"
          onClick={handleOpen}
          aria-label={t('assistantOutputs.open')}
          title={t('assistantOutputs.open')}
          className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-[var(--color-border)]/70 bg-[var(--color-surface)] text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-brand)]/35 hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-brand)]/35"
        >
          <ExternalLink size={14} strokeWidth={2.2} aria-hidden="true" />
        </button>
        <button
          type="button"
          aria-label={t('openWith.title')}
          onClick={handleOpenWith}
          className="inline-flex h-8 shrink-0 items-center gap-1 rounded-full border border-[var(--color-border)]/70 bg-[var(--color-surface)] px-2.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-brand)]/35 hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-brand)]/35"
        >
          {t('openWith.title')}
          <ChevronDown size={13} strokeWidth={2.2} aria-hidden="true" />
        </button>
      </div>

      {openWith && <OpenWithMenu items={openWith.items} anchor={openWith.anchor} triggerEl={openWith.triggerEl} onClose={() => setOpenWith(null)} />}
    </section>
  )
}
