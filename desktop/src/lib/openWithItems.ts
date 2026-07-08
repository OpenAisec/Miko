import type { OpenTarget } from '../stores/openTargetStore'

// ─── File-type description ────────────────────────────────────────────────────

export type FileTypeInfo = { icon: string; categoryKey: string; ext: string }

const FILE_TYPE_RULES: Array<{ re: RegExp; key: string; icon: string }> = [
  { re: /\.(md|markdown|txt|rst)$/i, key: 'document', icon: 'description' },
  { re: /\.(html?|xhtml)$/i, key: 'web', icon: 'html' },
  { re: /\.(png|jpe?g|gif|svg|webp|avif|bmp|ico)$/i, key: 'image', icon: 'image' },
  { re: /\.(ts|tsx|js|jsx|mjs|cjs|json|css|scss|less|py|rs|go|java|rb|php|c|cc|cpp|h|hpp|sh|ya?ml|toml)$/i, key: 'code', icon: 'code' },
]

export function describeFileType(path: string): FileTypeInfo {
  const ext = (path.split('.').pop() ?? '').toUpperCase()
  for (const rule of FILE_TYPE_RULES) {
    if (rule.re.test(path)) return { icon: rule.icon, categoryKey: `openWith.fileType.${rule.key}`, ext }
  }
  return { icon: 'insert_drive_file', categoryKey: 'openWith.fileType.file', ext }
}

const PREVIEWABLE_CHANGED_FILE_RE = /\.(md|markdown|html?|png|jpe?g|gif|webp|svg)$/i

/**
 * True only for changed-file types with a meaningful *rendered* preview
 * (markdown / html / image). Source files (.ts/.json/.css …) return false.
 * Used to decide which change-card rows get the "open with" affordance —
 * we don't want an open-with pill on every file when a turn touches many.
 */
export function isPreviewableChangedFile(path: string): boolean {
  return PREVIEWABLE_CHANGED_FILE_RE.test(path)
}

// ─── Open-with items ──────────────────────────────────────────────────────────

export type OpenWithIcon = 'in-app-browser' | 'system' | 'ide' | 'file-manager' | 'preview'

export type OpenWithItem = {
  id: string
  label: string
  icon: OpenWithIcon
  target?: OpenTarget          // present for ide/file-manager items (to render its favicon)
  onSelect: () => void
}

export type OpenWithDeps = {
  openInAppBrowser: (url: string) => void
  openSystem: (urlOrPath: string) => void
  openWorkspacePreview: (relPath: string) => void
  openTarget: (targetId: string, absolutePath: string) => void
  t: (key: string, vars?: Record<string, string>) => string
}

export type OpenWithContext =
  | { kind: 'url'; url: string }
  | { kind: 'file'; absolutePath: string; relPath?: string; previewable?: boolean; inAppBrowserUrl?: string }

export function buildOpenWithItems(ctx: OpenWithContext, targets: OpenTarget[], deps: OpenWithDeps): OpenWithItem[] {
  const items: OpenWithItem[] = []
  if (ctx.kind === 'url') {
    items.push({ id: 'in-app', label: deps.t('openWith.inAppBrowser'), icon: 'in-app-browser', onSelect: () => deps.openInAppBrowser(ctx.url) })
    items.push({ id: 'system', label: deps.t('openWith.systemBrowser'), icon: 'system', onSelect: () => deps.openSystem(ctx.url) })
    return items
  }
  if (ctx.previewable && ctx.relPath != null) {
    const relPath = ctx.relPath
    items.push({ id: 'preview', label: deps.t('openWith.workspacePreview'), icon: 'preview', onSelect: () => deps.openWorkspacePreview(relPath) })
  }
  if (ctx.inAppBrowserUrl) {
    const url = ctx.inAppBrowserUrl
    items.push({ id: 'in-app', label: deps.t('openWith.inAppBrowser'), icon: 'in-app-browser', onSelect: () => deps.openInAppBrowser(url) })
  }
  for (const target of targets.filter((x) => x.kind === 'ide')) {
    items.push({ id: `ide:${target.id}`, label: deps.t('openWith.openInTarget', { target: target.label }), icon: 'ide', target, onSelect: () => deps.openTarget(target.id, ctx.absolutePath) })
  }
  for (const target of targets.filter((x) => x.kind === 'file_manager')) {
    items.push({ id: `fm:${target.id}`, label: deps.t('openWith.revealInTarget', { target: target.label }), icon: 'file-manager', target, onSelect: () => deps.openTarget(target.id, ctx.absolutePath) })
  }
  return items
}
