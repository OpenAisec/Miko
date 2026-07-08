/**
 * Board MCP session 接线参数构建 — 纯函数：组装 --mcp-config 内联 JSON + --append-system-prompt。
 *
 * 只组装结构，不解析运行时命令路径（那是 conversationService 的活，它有 resolveCliArgs 同款逻辑）。
 * 可独立单测，不碰 conversationService、不起进程。
 *
 * 安全：sessionId 经 board MCP 的 env 注入，board MCP 写节点时强制覆盖（防 LLM 伪造归属，见 boardClient）。
 */

export type BoardMcpLaunch = {
  /** 启动 board MCP server 的命令（如 bun / execPath / bin/kimo），运行时解析。 */
  command: string
  /** 命令参数，含到 board-mcp server 入口为止。 */
  args: string[]
}

export type BoardMcpBinding = {
  serverUrl: string   // kimo server 根（从 sdkUrl 推导的 desktopServerUrl）
  sessionId: string   // 会话 id（黑板归会话：既是存储 key 也是节点 stamp 来源）
}

/** board MCP server 的 stdio 配置项（command/args/env）。 */
export function buildBoardMcpServerEntry(
  launch: BoardMcpLaunch,
  binding: BoardMcpBinding,
): { command: string; args: string[]; env: Record<string, string> } {
  return {
    command: launch.command,
    args: launch.args,
    env: {
      KIMO_BOARD_SERVER_URL: binding.serverUrl,
      KIMO_BOARD_SESSION_ID: binding.sessionId,
    },
  }
}

/** --mcp-config 接受的内联 JSON（mcpServers.board）。 */
export function buildBoardMcpConfigJson(
  launch: BoardMcpLaunch,
  binding: BoardMcpBinding,
): string {
  return JSON.stringify({
    mcpServers: { board: buildBoardMcpServerEntry(launch, binding) },
  })
}

/** catalog MCP 绑定（台账全局，不绑会话，故无 sessionId）。 */
export type CatalogMcpBinding = {
  serverUrl: string
}

/** catalog MCP server 的 stdio 配置项（command/args/env）。 */
export function buildCatalogMcpServerEntry(
  launch: BoardMcpLaunch,
  binding: CatalogMcpBinding,
): { command: string; args: string[]; env: Record<string, string> } {
  return {
    command: launch.command,
    args: launch.args,
    env: { KIMO_CATALOG_SERVER_URL: binding.serverUrl },
  }
}

/**
 * 会话进黑板模式要追加的 CLI 参数：board MCP config + 黑板 OODA system prompt。
 * 现有会话不调此函数 → 完全不变。
 *
 * catalog 可选：传入则把工具台账 MCP（catalog）与 board 挂进**同一份** --mcp-config
 * （MCP 协议原生支持一个 config 多个 server）。catalog launch 复用 board 的同款解析
 * （同 bun + server.ts 入口，仅 env 不同）。
 */
export function buildSecuritySessionArgs(opts: {
  launch: BoardMcpLaunch
  binding: BoardMcpBinding
  appendSystemPrompt: string
  catalog?: { launch: BoardMcpLaunch; binding: CatalogMcpBinding }
}): string[] {
  const mcpServers: Record<string, unknown> = {
    board: buildBoardMcpServerEntry(opts.launch, opts.binding),
  }
  if (opts.catalog) {
    mcpServers.catalog = buildCatalogMcpServerEntry(opts.catalog.launch, opts.catalog.binding)
  }
  return [
    '--mcp-config',
    JSON.stringify({ mcpServers }),
    '--append-system-prompt',
    opts.appendSystemPrompt,
  ]
}
