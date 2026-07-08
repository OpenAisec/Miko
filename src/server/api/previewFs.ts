import * as fs from 'node:fs'
import * as path from 'node:path'
import {
  isSameOrInsidePathForPlatform,
  normalizeDriveRootPathForPlatform,
} from '../services/windowsDrivePath.js'

const CONTENT_TYPES: Record<string, string> = {
  html: 'text/html; charset=utf-8',
  htm: 'text/html; charset=utf-8',
  css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  json: 'application/json; charset=utf-8',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  ico: 'image/x-icon',
  woff: 'font/woff',
  woff2: 'font/woff2',
  txt: 'text/plain; charset=utf-8',
  md: 'text/plain; charset=utf-8',
  // Video — served inline via <video> with HTTP byte-range streaming.
  mp4: 'video/mp4',
  webm: 'video/webm',
  mov: 'video/quicktime',
  m4v: 'video/x-m4v',
  // Audio.
  mp3: 'audio/mpeg',
  wav: 'audio/wav',
  ogg: 'audio/ogg',
}

export function contentTypeForPath(filePath: string): string {
  const ext = path.extname(filePath).slice(1).toLowerCase()
  return CONTENT_TYPES[ext] ?? 'application/octet-stream'
}

export type ResolveWorkDir = (sessionId: string) => Promise<string | null>

const PREFIX = '/preview-fs/'

/**
 * Upper bound on what we'll serve. The old 50 MB cap existed because the file
 * was buffered into memory via `readFileSync`; that would 413 real dubbed
 * videos. We now STREAM every response through `Bun.file(...)` (including
 * byte-ranges), so the in-memory pressure is gone and we can raise this a lot.
 * We keep a generous-but-finite ceiling (2 GiB) purely as a sanity guard
 * against pathological / runaway files — not as a memory limit.
 */
const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
const ROOT_RELATIVE_HTML_ATTR_RE = /\b(src|href)=(["'])\/(?!\/)([^"']*)\2/gi

export interface ParsedRange {
  start: number
  end: number
}

/**
 * Parse a single HTTP `Range` header against a known file `size`.
 *
 * Supports the common single-range forms:
 *   - `bytes=start-end`  (explicit closed range)
 *   - `bytes=start-`     (open-ended → to EOF)
 *   - `bytes=-N`         (suffix → last N bytes)
 *
 * Returns inclusive `{ start, end }` byte offsets clamped to `[0, size-1]`,
 * `null` when the header is absent/unparseable (caller should fall back to a
 * full 200 response), or `'unsatisfiable'` when the range cannot be satisfied
 * (caller should reply 416). Multi-range requests (comma-separated) are not
 * supported and fall back to a full response.
 */
export function parseRange(
  rangeHeader: string | null | undefined,
  size: number,
): ParsedRange | null | 'unsatisfiable' {
  if (!rangeHeader) return null

  const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim())
  if (!match) return null

  const startRaw = match[1]
  const endRaw = match[2]

  // `bytes=-N` suffix form: the last N bytes.
  if (startRaw === '') {
    if (endRaw === '') return null // `bytes=-` is malformed → ignore.
    const suffixLen = Number(endRaw)
    if (!Number.isFinite(suffixLen) || suffixLen <= 0) return 'unsatisfiable'
    if (size === 0) return 'unsatisfiable'
    const start = Math.max(0, size - suffixLen)
    return { start, end: size - 1 }
  }

  const start = Number(startRaw)
  if (!Number.isFinite(start)) return null

  // start beyond EOF is unsatisfiable.
  if (start >= size) return 'unsatisfiable'

  let end: number
  if (endRaw === '') {
    end = size - 1 // open-ended → EOF
  } else {
    end = Number(endRaw)
    if (!Number.isFinite(end)) return null
    if (end < start) return 'unsatisfiable'
    end = Math.min(end, size - 1) // clamp to EOF
  }

  return { start, end }
}

/**
 * Serve a single file from a session's sandboxed workspace directory.
 *
 * URL shape: `/preview-fs/<sessionId>/<relPath>` where `<relPath>` may itself
 * contain `/` separators. The WHATWG URL parser collapses `..` segments before
 * this handler runs, so a traversal attempt such as
 * `/preview-fs/s1/../../etc/passwd` arrives with its pathname normalized to
 * `/etc/passwd` — i.e. the `/preview-fs/` prefix is gone. We treat any request
 * that lost the prefix as a sandbox escape and return 403. Requests that keep
 * the prefix are additionally re-validated against the resolved work-dir root.
 */
export async function handlePreviewFs(
  url: URL,
  resolveWorkDir: ResolveWorkDir,
  reqHeaders?: Headers,
): Promise<Response> {
  if (!url.pathname.startsWith(PREFIX)) {
    return new Response('forbidden', { status: 403 })
  }

  const rest = url.pathname.slice(PREFIX.length)
  const slash = rest.indexOf('/')
  if (slash <= 0) return new Response('bad request', { status: 400 })

  const sessionId = decodeURIComponent(rest.slice(0, slash))
  const relRaw = decodeURIComponent(rest.slice(slash + 1))

  const workDir = await resolveWorkDir(sessionId)
  if (!workDir) return new Response('no workdir', { status: 404 })

  const root = path.resolve(normalizeDriveRootPathForPlatform(workDir))
  const target = path.resolve(root, relRaw)
  if (!isSameOrInsidePathForPlatform(target, root)) {
    return new Response('forbidden', { status: 403 })
  }

  return servePreviewFsFile(target, url.pathname, reqHeaders)
}

function previewHtmlBasePath(pathname: string): string {
  const slash = pathname.lastIndexOf('/')
  if (slash < 0) return '/'
  return pathname.slice(0, slash + 1)
}

function escapeHtmlAttribute(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

export function rewritePreviewHtml(content: string, basePath: string): string {
  const normalizedBase = basePath.endsWith('/') ? basePath : `${basePath}/`
  const rewrittenRootAssets = content.replace(
    ROOT_RELATIVE_HTML_ATTR_RE,
    (_match, attr: string, quote: string, value: string) =>
      `${attr}=${quote}${normalizedBase}${value}${quote}`,
  )

  if (/<base\b/i.test(rewrittenRootAssets)) {
    return rewrittenRootAssets
  }

  return rewrittenRootAssets.replace(
    /<head\b[^>]*>/i,
    (head) => `${head}<base href="${escapeHtmlAttribute(normalizedBase)}">`,
  )
}

async function servePreviewFsFile(
  target: string,
  requestPathname: string,
  reqHeaders?: Headers,
): Promise<Response> {
  const ext = path.extname(target).toLowerCase()
  if ((ext !== '.html' && ext !== '.htm') || reqHeaders?.has('range')) {
    return serveFileWithRange(target, reqHeaders)
  }

  let stat: fs.Stats
  try {
    stat = fs.statSync(target)
  } catch {
    return new Response('not found', { status: 404 })
  }
  if (!stat.isFile()) return new Response('not a file', { status: 404 })
  if (stat.size > MAX_FILE_BYTES) return new Response('too large', { status: 413 })

  const content = fs.readFileSync(target, 'utf8')
  const transformed = rewritePreviewHtml(content, previewHtmlBasePath(requestPathname))

  return new Response(transformed, {
    status: 200,
    headers: {
      'Content-Type': contentTypeForPath(target),
      'Content-Length': String(Buffer.byteLength(transformed)),
      'Cache-Control': 'no-cache',
    },
  })
}

/**
 * Stream a single resolved absolute file as an HTTP response, honouring a
 * `Range` header (206 partial / 416 unsatisfiable) and falling back to a full
 * 200 otherwise. The body is streamed straight from disk via `Bun.file(...)`,
 * never buffered into memory, so this is safe for large media.
 *
 * Callers are responsible for any path-sandboxing BEFORE invoking this — it
 * trusts `target` to already be authorised. It returns 404 when the path is
 * missing or not a regular file, and 413 above {@link MAX_FILE_BYTES}.
 */
export async function serveFileWithRange(
  target: string,
  reqHeaders?: Headers,
): Promise<Response> {
  let stat: fs.Stats
  try {
    stat = fs.statSync(target)
  } catch {
    return new Response('not found', { status: 404 })
  }
  if (!stat.isFile()) return new Response('not a file', { status: 404 })
  if (stat.size > MAX_FILE_BYTES) return new Response('too large', { status: 413 })

  const size = stat.size
  const contentType = contentTypeForPath(target)
  // Stream straight from disk via Bun.file — never buffer whole media into
  // memory. Bun's file blob is an acceptable Response body.
  const file = Bun.file(target)

  const range = parseRange(reqHeaders?.get('range'), size)

  if (range === 'unsatisfiable') {
    return new Response('range not satisfiable', {
      status: 416,
      headers: {
        'Content-Range': `bytes */${size}`,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'no-cache',
      },
    })
  }

  if (range) {
    const { start, end } = range
    // `slice(start, end + 1)` — Bun's slice end is exclusive, range end is
    // inclusive — streams just the requested window.
    return new Response(file.slice(start, end + 1), {
      status: 206,
      headers: {
        'Content-Type': contentType,
        'Content-Range': `bytes ${start}-${end}/${size}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(end - start + 1),
        'Cache-Control': 'no-cache',
      },
    })
  }

  // No (or unparseable) Range header → stream the whole file as 200.
  return new Response(file, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Content-Length': String(size),
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-cache',
    },
  })
}
