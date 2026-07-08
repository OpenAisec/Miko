import { api } from './client'

/** 工具调用方式：cli（经 Bash 跑）| mcp（直接调 mcp__* 工具）。 */
export type ToolInvoke = 'cli' | 'mcp'

/** 一条工具台账（前端视图，含探测状态 + 保护标志）。 */
export type ToolDef = {
  id: string
  category: string
  name: string
  shortDescription: string
  description?: string
  invoke: ToolInvoke
  check?: string
  bin?: string
  usage?: string
  installHint?: string
  mcpServer?: string
  builtin?: boolean
  /** 绿色二进制随 kimo 分发（装内置目录即"已装"，无需系统安装）。 */
  bundled?: boolean
  /** 靠用户配置本机路径（重型/商业工具如 ghidra/IDA）。 */
  requiresUserPath?: boolean
  /** requiresUserPath 时给用户的路径填写提示。 */
  pathHint?: string
  /** 用户当前配置的绝对路径（requiresUserPath 工具）。 */
  userPath?: string
  /** 探测状态：true 已装 / false 未装 / null 未知（无 check 且无 bin，或未探测）。 */
  installed: boolean | null
  version?: string
  /** 受保护（内置 builtin 或 PROTECTED_TOOLS）→ 隐藏删除按钮。 */
  protected?: boolean
}

/** 分类目录项（Tier1，前端可选用）。 */
export type CatalogCategorySummary = {
  id: string
  label: string
  total: number
  available: number
}

export const catalogApi = {
  /** UI 全量：所有工具 + 状态（按 category 分组渲染用）。 */
  listAll: () => api.get<{ tools: ToolDef[] }>('/api/catalog/all'),
  /** 分类目录（每类计数 + 可用数）。 */
  listCategories: () => api.get<{ categories: CatalogCategorySummary[] }>('/api/catalog/categories'),
  /** 手动重新探测（"重新探测"按钮）。 */
  probe: () => api.post<{ ok: true; status: Record<string, { installed: boolean; version?: string }> }>(
    '/api/catalog/probe',
    {},
    { timeout: 120_000 }, // 探测 80+ 工具，留足超时
  ),
  /** 删除工具（受保护工具后端会拒）。 */
  remove: (id: string) => api.delete<{ ok: true }>(`/api/catalog/tools/${encodeURIComponent(id)}`),
  /** 设置 requiresUserPath 工具的本机路径（立即重探）。 */
  setPath: (id: string, path: string) =>
    api.post<{ ok: true; tool: ToolDef | null }>(`/api/catalog/tools/${encodeURIComponent(id)}/path`, { path }),
  /** 清除用户路径。 */
  clearPath: (id: string) =>
    api.delete<{ ok: true }>(`/api/catalog/tools/${encodeURIComponent(id)}/path`),
}
