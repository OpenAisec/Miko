/**
 * Catalog MCP server — 极简 stdio MCP server，暴露工具台账的三层只读查询给会话 agent。
 *
 * 分层披露（[[工具生态-台账与分级披露方案]] §五）：台账可能上百条，不整张注入 prompt。
 * agent 按需下钻：list_categories（目录）→ list_tools(类)（章节）→ get_tool(id)（详情）。
 *
 * 硬约束（[[data-path-resolver-split]] 教训）：本进程是极简纯 HTTP 客户端，
 * **绝不 import kimoPaths / 绝不调 getDataDir() / 绝不碰会话或数据存储**。只认 env、做 HTTP。
 *
 * 启动：env 带 KIMO_CATALOG_SERVER_URL（台账全局，不绑会话，故无 SESSION_ID）。
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  type CallToolResult,
  ListToolsRequestSchema,
  type ListToolsResult,
} from '@modelcontextprotocol/sdk/types.js'
import {
  parseCatalogConfig,
  buildListCategoriesRequest,
  buildListToolsRequest,
  buildGetToolRequest,
  mapResponse,
  type CatalogClientConfig,
} from './catalogClient.js'

const LIST_CATEGORIES_TOOL = 'list_categories'
const LIST_TOOLS_TOOL = 'list_tools'
const GET_TOOL_TOOL = 'get_tool'

const LIST_CATEGORIES_DESCRIPTION =
  '列出本机工具台账的所有分类（每类工具数 + 可用数）。想用外部工具时**先调这个**看有哪几类，' +
  '再用 list_tools 进某类。台账按领域分类（web/binary/asset/redteam/cloud/forensics 等）。'

const LIST_TOOLS_DESCRIPTION =
  '列出某分类下的工具（名称 + 已装状态 + 一句话说明）。先用 list_categories 确定分类，再调这个。' +
  '看到想用的工具，用 get_tool 拉它的完整用法。'

const GET_TOOL_DESCRIPTION =
  '取单个工具的完整信息：是否已装/版本、调用方式（cli 经 Bash 跑 / mcp 直接调）、起手命令、未装时的安装方法。' +
  '决定用某工具前调这个拿到准确用法，别凭记忆拼命令。' +
  '**注意 bundledPath 字段**：有值时说明该工具是 kimo 随包内置的二进制、不在系统 PATH，' +
  '经 Bash 调用必须用这个绝对路径当可执行文件（把 usage 里的命令名替换成它），裸命令名会 command not found。'

const LIST_CATEGORIES_SCHEMA = { type: 'object', properties: {}, additionalProperties: false }
const LIST_TOOLS_SCHEMA = {
  type: 'object',
  properties: { category: { type: 'string', description: '分类 id（来自 list_categories）' } },
  required: ['category'],
}
const GET_TOOL_SCHEMA = {
  type: 'object',
  properties: { id: { type: 'string', description: '工具 id（来自 list_tools）' } },
  required: ['id'],
}

/** 建一个挂好三个查询工具的 MCP Server（config 注入，可单测）。 */
export function createCatalogMcpServer(config: CatalogClientConfig, version = '1.0.0'): Server {
  const server = new Server(
    { name: 'kimo/catalog', version },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async (): Promise<ListToolsResult> => ({
    tools: [
      { name: LIST_CATEGORIES_TOOL, description: LIST_CATEGORIES_DESCRIPTION, inputSchema: LIST_CATEGORIES_SCHEMA },
      { name: LIST_TOOLS_TOOL, description: LIST_TOOLS_DESCRIPTION, inputSchema: LIST_TOOLS_SCHEMA },
      { name: GET_TOOL_TOOL, description: GET_TOOL_DESCRIPTION, inputSchema: GET_TOOL_SCHEMA },
    ],
  }))

  server.setRequestHandler(CallToolRequestSchema, async ({ params }): Promise<CallToolResult> => {
    const { name, arguments: args } = params
    try {
      if (name === LIST_CATEGORIES_TOOL) {
        const { url, init } = buildListCategoriesRequest(config)
        const text = await mapResponse(await fetch(url, init))
        return { content: [{ type: 'text', text }] }
      }
      if (name === LIST_TOOLS_TOOL) {
        const { url, init } = buildListToolsRequest(config, (args ?? {}) as { category?: string })
        const text = await mapResponse(await fetch(url, init))
        return { content: [{ type: 'text', text }] }
      }
      if (name === GET_TOOL_TOOL) {
        const { url, init } = buildGetToolRequest(config, (args ?? {}) as { id?: string })
        const text = await mapResponse(await fetch(url, init))
        return { content: [{ type: 'text', text }] }
      }
      throw new Error(`unknown tool: ${name}`)
    } catch (err) {
      // 显式报错给 agent，不兜底返空
      return {
        isError: true,
        content: [{ type: 'text', text: `catalog tool error: ${err instanceof Error ? err.message : String(err)}` }],
      }
    }
  })

  return server
}

/** 入口：解析 env → 建 server → 接 stdio。 */
export async function main(): Promise<void> {
  const config = parseCatalogConfig(process.env)
  const server = createCatalogMcpServer(config)
  const transport = new StdioServerTransport()
  await server.connect(transport)
}

// 直接运行时启动（被 import 时不启动，供单测）
if (import.meta.main) {
  main().catch((err) => {
    process.stderr.write(`catalog-mcp fatal: ${err instanceof Error ? err.message : String(err)}\n`)
    process.exit(1)
  })
}
