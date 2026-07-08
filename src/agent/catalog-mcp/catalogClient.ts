/**
 * Catalog MCP 客户端逻辑 — 纯函数：env 解析 + HTTP 请求构建 + 响应映射。
 *
 * 与 server 外壳分离，可独立单测（不起子进程、不连真 server）。照 boardClient.ts 范式。
 *
 * 硬约束（[[data-path-resolver-split]] 教训）：catalog MCP 是极简纯 HTTP 客户端，
 * **绝不调 getDataDir()、绝不碰会话/数据存储**。它只认 env，做 HTTP 回调。
 *
 * 与 board 的差异：台账是**全局**的（不绑会话），所以只需 serverUrl，无 sessionId。
 * 三个只读方法对应分层披露三层（[[工具生态-台账与分级披露方案]] §五）。
 */

export type CatalogClientConfig = {
  serverUrl: string // kimo server 根，如 http://127.0.0.1:3456
}

/** 从 env 解析配置；缺 serverUrl 即抛（不兜底）。 */
export function parseCatalogConfig(env: Record<string, string | undefined>): CatalogClientConfig {
  const serverUrl = env.KIMO_CATALOG_SERVER_URL?.trim()
  if (!serverUrl) throw new Error('KIMO_CATALOG_SERVER_URL is required')
  return { serverUrl: serverUrl.replace(/\/+$/, '') }
}

/** Tier1：list_categories → GET /api/catalog/categories。 */
export function buildListCategoriesRequest(config: CatalogClientConfig): { url: string; init: RequestInit } {
  return {
    url: `${config.serverUrl}/api/catalog/categories`,
    init: { method: 'GET' },
  }
}

/** Tier2：list_tools(category) → GET /api/catalog/tools?category=X。category 必填。 */
export function buildListToolsRequest(
  config: CatalogClientConfig,
  args: { category?: string },
): { url: string; init: RequestInit } {
  const category = args?.category?.trim()
  if (!category) throw new Error('list_tools requires "category"')
  return {
    url: `${config.serverUrl}/api/catalog/tools?category=${encodeURIComponent(category)}`,
    init: { method: 'GET' },
  }
}

/** Tier3：get_tool(id) → GET /api/catalog/tools/:id。id 必填。 */
export function buildGetToolRequest(
  config: CatalogClientConfig,
  args: { id?: string },
): { url: string; init: RequestInit } {
  const id = args?.id?.trim()
  if (!id) throw new Error('get_tool requires "id"')
  return {
    url: `${config.serverUrl}/api/catalog/tools/${encodeURIComponent(id)}`,
    init: { method: 'GET' },
  }
}

/** 把 HTTP 响应映射成 MCP 工具文本结果；非 2xx 抛错（不返空兜底）。 */
export async function mapResponse(res: Response): Promise<string> {
  const text = await res.text()
  if (!res.ok) {
    throw new Error(`catalog API ${res.status}: ${text.slice(0, 300)}`)
  }
  return text
}
