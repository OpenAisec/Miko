/**
 * Worker 输出解析 — 从 worker 文本里宽容地提取唯一 JSON 对象。
 *
 * 仿 Cairn output_parser：先试整段、再剥 ```json 围栏、再扫每个 `{` 位置 raw_decode，
 * 任一成功即用。但与 findingsExtractionService 不同：找不到合法对象就 **抛错**，
 * 绝不返回 null / 空对象兜底（功能就是功能，失败要显式）。
 */

const FENCED_BLOCK_RE = /```(?:json)?\s*\n?([\s\S]*?)```/gi

/** 提取 worker 输出里的唯一 JSON 对象；找不到合法对象抛 Error。 */
export function extractJsonObject(text: string): Record<string, unknown> {
  const raw = (text ?? '').trim()
  if (!raw) throw new Error('worker output is empty')

  const seen = new Set<string>()
  for (const candidate of candidateSegments(raw)) {
    const segment = candidate.trim()
    if (!segment || seen.has(segment)) continue
    seen.add(segment)

    // 整段就是 JSON
    const whole = tryParseObject(segment)
    if (whole) return whole

    // 从每个 `{` 起尝试增量解析（容忍前后噪声）
    for (const start of objectStartPositions(segment)) {
      const obj = tryParseObjectPrefix(segment.slice(start))
      if (obj) return obj
    }
  }

  throw new Error('no JSON object found in worker output')
}

function candidateSegments(text: string): string[] {
  const segments = [text]
  for (const m of text.matchAll(FENCED_BLOCK_RE)) {
    if (m[1]) segments.push(m[1].trim())
  }
  return segments
}

function objectStartPositions(text: string): number[] {
  const positions: number[] = []
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '{') positions.push(i)
  }
  return positions
}

function tryParseObject(segment: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(segment) as unknown
    return isPlainObject(parsed) ? parsed : null
  } catch {
    return null
  }
}

/**
 * 从片段开头解析一个 JSON 对象，容忍其后还有多余字符。
 * JSON.parse 要求整段合法，这里用括号配对找出第一个完整对象的边界再 parse。
 */
function tryParseObjectPrefix(text: string): Record<string, unknown> | null {
  if (text[0] !== '{') return null
  let depth = 0
  let inString = false
  let escaped = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (inString) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === '"') inString = false
      continue
    }
    if (ch === '"') inString = true
    else if (ch === '{') depth++
    else if (ch === '}') {
      depth--
      if (depth === 0) return tryParseObject(text.slice(0, i + 1))
    }
  }
  return null
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}
