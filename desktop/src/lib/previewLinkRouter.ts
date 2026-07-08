import { isLoopbackHostname } from './desktopRuntime'

export type PreviewLinkKind =
  | 'browser-localhost'
  | 'browser-file'
  | 'file-preview'
  | 'remote'
  | 'ignored'

export type PreviewLinkClass = { kind: PreviewLinkKind; path?: string; url?: string }

const PREVIEWABLE_EXT = new Set(['md', 'markdown', 'txt', 'ts', 'tsx', 'js', 'jsx', 'json', 'css', 'py', 'rs', 'go', 'java', 'sh', 'yml', 'yaml', 'png', 'jpg', 'jpeg', 'gif', 'svg'])

function extOf(p: string): string {
  const m = /\.([a-z0-9]+)(?:[?#].*)?$/i.exec(p)
  const g = m?.[1]
  return g ? g.toLowerCase() : ''
}

export function classifyPreviewLink(href: string): PreviewLinkClass {
  const raw = href.trim()
  if (!raw || raw.startsWith('#')) return { kind: 'ignored' }

  try {
    const u = new URL(raw)
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return isLoopbackHostname(u.hostname)
        ? { kind: 'browser-localhost', url: u.toString() }
        : { kind: 'remote', url: u.toString() }
    }
    if (u.protocol === 'file:') {
      return { kind: 'browser-file', path: decodeURIComponent(u.pathname) }
    }
    return { kind: 'ignored' }
  } catch {
    // not an absolute URL → treat as a path
  }

  const ext = extOf(raw)
  if (ext === 'html' || ext === 'htm') return { kind: 'browser-file', path: raw }
  if (PREVIEWABLE_EXT.has(ext)) {
    return raw.startsWith('/') ? { kind: 'browser-file', path: raw } : { kind: 'file-preview', path: raw }
  }
  return { kind: 'ignored' }
}
