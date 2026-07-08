const HTML_EXT = /\.(html?|xhtml)$/i
const INDEX_HTML_RE = /(^|\/)index\.html?$/i

const STATIC_OUTPUT_DIRS = new Set([
  'build',
  'coverage',
  'dist',
  'docs',
  'lcov-report',
  'out',
  'public',
  'site',
  'storybook-static',
])

function normalizePathForPolicy(filePath: string): string {
  return filePath
    .split(/[?#]/, 1)[0]!
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
}

export function isHtmlFilePath(filePath: string): boolean {
  return HTML_EXT.test(normalizePathForPolicy(filePath))
}

export function shouldOfferStaticHtmlPreview(filePath: string): boolean {
  const normalized = normalizePathForPolicy(filePath)
  if (!HTML_EXT.test(normalized)) return false
  if (!INDEX_HTML_RE.test(normalized)) return true

  return normalized
    .split('/')
    .filter(Boolean)
    .some((segment) => STATIC_OUTPUT_DIRS.has(segment.toLowerCase()))
}
