/**
 * Board MCP 客户端逻辑 — 纯函数：env 解析 + HTTP 请求构建 + 响应映射。
 *
 * 与 server 外壳分离，可独立单测（不起子进程、不连真 server）。
 *
 * 硬约束（[[data-path-resolver-split]] 教训）：board MCP 是极简纯 HTTP 客户端，
 * **绝不调 getDataDir()、绝不碰会话/数据存储**。它只认 3 个 env，做 HTTP 回调。
 */

export type BoardClientConfig = {
  serverUrl: string   // kimo server 根，如 http://127.0.0.1:3456
  sessionId: string   // 会话 id（黑板归会话；既是存储 key 也是节点 stamp 来源）
}

/** 从 env 解析配置；缺任一必需项即抛（不兜底）。 */
export function parseBoardConfig(env: Record<string, string | undefined>): BoardClientConfig {
  const serverUrl = env.KIMO_BOARD_SERVER_URL?.trim()
  const sessionId = env.KIMO_BOARD_SESSION_ID?.trim()
  if (!serverUrl) throw new Error('KIMO_BOARD_SERVER_URL is required')
  if (!sessionId) throw new Error('KIMO_BOARD_SESSION_ID is required')
  return { serverUrl: serverUrl.replace(/\/+$/, ''), sessionId }
}

/** board_read 的 HTTP 请求（GET 会话黑板图快照）。 */
export function buildReadRequest(config: BoardClientConfig): { url: string; init: RequestInit } {
  return {
    url: `${config.serverUrl}/api/security/sessions/${config.sessionId}/board`,
    init: { method: 'GET' },
  }
}

/** board_write 工具的入参（LLM 提供；sessionId 不在此，由客户端用 env 注入）。 */
export type BoardWriteArgs = {
  kind: 'asset' | 'fact' | 'finding' | 'intent'
  title?: string
  result?: string
  process?: string
  evidence?: string
  payload?: string
  flag?: string
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  phase?: string
  parentId?: string        // 挂在哪个父节点下（asset 骨架 / 对象层级）
  assetKind?: string        // 仅 asset：domain/endpoint/param/module/function…
  detail?: string           // 补充说明（可选）
  intentId?: string        // explore 探完时指向被认领 intent
  agentId?: string         // 探索子 agent id（深链）
  intents?: Array<{ title: string; fromFactIds?: string[]; phase?: string; parentId?: string }> // kind=intent 批量
}

/**
 * board_write 的 HTTP 请求（POST 写节点）。
 * sessionId 由客户端用 env 强制注入到 body（不信任 LLM 传入，防伪造归属）。
 * 校验失败抛错，不兜底。
 */
export function buildWriteRequest(
  config: BoardClientConfig,
  args: BoardWriteArgs,
): { url: string; init: RequestInit } {
  if (args.kind !== 'fact' && args.kind !== 'finding' && args.kind !== 'intent' && args.kind !== 'asset') {
    throw new Error(`invalid kind: ${String(args.kind)}`)
  }
  if (args.kind === 'intent') {
    const intents = args.intents ?? (args.title ? [{ title: args.title, phase: args.phase }] : [])
    if (intents.length === 0) throw new Error('intent write requires title or intents[]')
  } else if (args.kind === 'asset') {
    // asset 是攻击面/对象骨架节点，只需 title（不强制 result）
    if (!args.title?.trim()) throw new Error('asset write requires title')
  } else {
    if (!args.title?.trim()) throw new Error('title is required')
    if (!args.result?.trim()) throw new Error('result is required')
  }
  // sessionId 由 env 注入，覆盖 LLM 可能传入的任何值
  const body = { ...args, sessionId: config.sessionId }
  return {
    url: `${config.serverUrl}/api/security/sessions/${config.sessionId}/board/nodes`,
    init: {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  }
}

/** 把 HTTP 响应映射成 MCP 工具文本结果；非 2xx 抛错（不返空兜底）。 */
export async function mapResponse(res: Response): Promise<string> {
  const text = await res.text()
  if (!res.ok) {
    throw new Error(`board API ${res.status}: ${text.slice(0, 300)}`)
  }
  return text
}
