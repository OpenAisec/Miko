export type BrowserPathCrumb = {
  label: string
  path: string
}

export function normalizeBrowserPath(input: string): string {
  const trimmed = input.trim()
  if (!trimmed) return ''

  const normalized = trimmed.replace(/\\/g, '/')
  if (normalized === '/') return '/'

  const driveRootMatch = normalized.match(/^([a-zA-Z]:)\/?$/)
  if (driveRootMatch) {
    return `${driveRootMatch[1]}/`
  }

  const drivePrefixed = normalized.replace(/^\/(?=[a-zA-Z]:\/)/, '')
  return drivePrefixed.replace(/\/+$/, '') || '/'
}

export function joinBrowserPath(...segments: Array<string | null | undefined>): string {
  const cleaned = segments
    .map((segment) => segment?.trim())
    .filter((segment): segment is string => Boolean(segment))

  if (cleaned.length === 0) return ''

  let result = normalizeBrowserPath(cleaned[0]!)
  for (const segment of cleaned.slice(1)) {
    const next = normalizeBrowserPath(segment)
    const nextPart = next.replace(/^\/+/, '')
    if (!nextPart) continue
    result = result === '/'
      ? `/${nextPart}`
      : `${result.replace(/\/+$/, '')}/${nextPart}`
  }

  return normalizeBrowserPath(result)
}

export function buildBrowserPathBreadcrumbs(input: string): BrowserPathCrumb[] {
  const normalized = normalizeBrowserPath(input)
  if (!normalized) return []
  if (normalized === '/') {
    return [{ label: '/', path: '/' }]
  }

  const driveMatch = normalized.match(/^([a-zA-Z]:)\/(.*)$/)
  if (driveMatch) {
    const drive = driveMatch[1]!
    const remainder = (driveMatch[2] ?? '').replace(/^\/+|\/+$/g, '')
    const breadcrumbs: BrowserPathCrumb[] = [{ label: `${drive}\\`, path: `${drive}/` }]

    if (!remainder) return breadcrumbs

    let current = `${drive}/`
    for (const segment of remainder.split('/').filter(Boolean)) {
      current = `${current.replace(/\/+$/, '')}/${segment}`
      breadcrumbs.push({ label: segment, path: current })
    }
    return breadcrumbs
  }

  const breadcrumbs: BrowserPathCrumb[] = [{ label: '/', path: '/' }]
  let current = ''
  for (const segment of normalized.replace(/^\/+/, '').replace(/\/+$/, '').split('/').filter(Boolean)) {
    current += `/${segment}`
    breadcrumbs.push({ label: segment, path: current })
  }
  return breadcrumbs
}
