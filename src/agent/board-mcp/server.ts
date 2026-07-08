/**
 * Board MCP server — 极简 stdio MCP server，暴露 board_read / board_write 给会话主 agent。
 *
 * 路 A：会话主 agent 当 dispatcher，用这两个工具读/写黑板。回调本地 kimo server HTTP API，
 * securityProjectService 是唯一写入者（避免两进程写 nodes.json 竞态）。
 *
 * 硬约束（[[data-path-resolver-split]] 教训）：本进程是极简纯 HTTP 客户端，
 * **绝不 import kimoPaths / 绝不调 getDataDir() / 绝不碰会话或数据存储**。只认 3 个 env、做 HTTP。
 *
 * 启动：env 带 KIMO_BOARD_SERVER_URL / KIMO_BOARD_SESSION_ID（黑板归会话，不再需要 PROJECT_ID）。
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
  parseBoardConfig,
  buildReadRequest,
  buildWriteRequest,
  mapResponse,
  type BoardClientConfig,
  type BoardWriteArgs,
} from './boardClient.js'

const BOARD_READ_TOOL = 'board_read'
const BOARD_WRITE_TOOL = 'board_write'

const READ_DESCRIPTION =
  '读取当前安全项目的黑板图快照（goal/target/facts/intents/hints，紧凑 JSON）。' +
  '每轮 OODA 循环开始时调用，对照 Goal 判断已覆盖什么、还有哪些 open intent 待探。'

const WRITE_DESCRIPTION =
  '向黑板写节点。先用 kind=asset 把目标拆成攻击面/对象骨架（功能/接口/模块/函数/服务等），' +
  '再用 parentId 把 intent（试过的方向）/fact/finding 挂到对应 asset 下。' +
  'kind=intent 提出待探方向（可批量 intents[]，每项可带 parentId）；' +
  'kind=fact/finding 写已确认事实/漏洞（带 intentId 关联被探 intent，或带 parentId 挂在 asset 下）。' +
  'asset 只需 title；fact/finding 必带 result（有发现写发现，没发现写"不存在+原因"，排除项也要独立成节点）。' +
  'phase 自由标注当前工作阶段。agentId 传探索子 agent id 以便深链。'

const READ_SCHEMA = { type: 'object', properties: {}, additionalProperties: false }
const WRITE_SCHEMA = {
  type: 'object',
  properties: {
    kind: { type: 'string', enum: ['asset', 'fact', 'finding', 'intent'] },
    title: { type: 'string' },
    result: { type: 'string' },
    process: { type: 'string' },
    evidence: { type: 'string' },
    payload: { type: 'string' },
    flag: { type: 'string' },
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
    phase: { type: 'string' },
    parentId: { type: 'string' },
    assetKind: { type: 'string' },
    detail: { type: 'string' },
    intentId: { type: 'string' },
    agentId: { type: 'string' },
    intents: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          fromFactIds: { type: 'array', items: { type: 'string' } },
          phase: { type: 'string' },
          parentId: { type: 'string' },
        },
        required: ['title'],
      },
    },
  },
  required: ['kind'],
}

/** 建一个挂好两个工具的 MCP Server（config 注入，可单测）。 */
export function createBoardMcpServer(config: BoardClientConfig, version = '1.0.0'): Server {
  const server = new Server(
    { name: 'kimo/board', version },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async (): Promise<ListToolsResult> => ({
    tools: [
      { name: BOARD_READ_TOOL, description: READ_DESCRIPTION, inputSchema: READ_SCHEMA },
      { name: BOARD_WRITE_TOOL, description: WRITE_DESCRIPTION, inputSchema: WRITE_SCHEMA },
    ],
  }))

  server.setRequestHandler(CallToolRequestSchema, async ({ params }): Promise<CallToolResult> => {
    const { name, arguments: args } = params
    try {
      if (name === BOARD_READ_TOOL) {
        const { url, init } = buildReadRequest(config)
        const text = await mapResponse(await fetch(url, init))
        return { content: [{ type: 'text', text }] }
      }
      if (name === BOARD_WRITE_TOOL) {
        const { url, init } = buildWriteRequest(config, (args ?? {}) as BoardWriteArgs)
        const text = await mapResponse(await fetch(url, init))
        return { content: [{ type: 'text', text }] }
      }
      throw new Error(`unknown tool: ${name}`)
    } catch (err) {
      // 显式报错给 agent，不兜底返空
      return {
        isError: true,
        content: [{ type: 'text', text: `board tool error: ${err instanceof Error ? err.message : String(err)}` }],
      }
    }
  })

  return server
}

/** 入口：解析 env → 建 server → 接 stdio。 */
export async function main(): Promise<void> {
  const config = parseBoardConfig(process.env)
  const server = createBoardMcpServer(config)
  const transport = new StdioServerTransport()
  await server.connect(transport)
}

// 直接运行时启动（被 import 时不启动，供单测）
if (import.meta.main) {
  main().catch((err) => {
    process.stderr.write(`board-mcp fatal: ${err instanceof Error ? err.message : String(err)}\n`)
    process.exit(1)
  })
}
