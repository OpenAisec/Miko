import type { Root } from '../ink.js'

/**
 * Legacy .mcp.json approval is no longer part of startup because runtime MCP
 * servers now come from the user-owned data/mcp.json file.
 */
export async function handleMcpjsonServerApprovals(_root: Root): Promise<void> {
  return
}
