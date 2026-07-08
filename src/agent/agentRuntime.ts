/**
 * Agent Runtime — 父子 agent 调用入口
 *
 * 封装 createSubagentContext，基于 AgentContextConfig 显式策略构建子 agent 上下文。
 * 旧 createSubagentContext 保留为 @deprecated 过渡。
 */

import type { ToolUseContext } from '../Tool.js'
import { createSubagentContext } from '../utils/forkedAgent.js'
import { getDataDir } from '../utils/kimoPaths.js'
import * as fs from 'node:fs'
import * as path from 'node:path'
import type { AgentContextConfig, AgentResult, Message, MemoryEntry, FileChange } from './types.js'

/**
 * 基于 AgentContextConfig 创建子 agent 上下文。
 */
export function createAgentContext(
  parentContext: ToolUseContext,
  config: AgentContextConfig,
): ToolUseContext {
  const isInteractive = config.interaction === 'interactive'

  let options = parentContext.options
  if (config.tools.mode === 'inherit' && config.tools.remove?.length) {
    options = {
      ...parentContext.options,
      denyList: [
        ...(parentContext.options.denyList ?? []),
        ...config.tools.remove.map((name) => ({
          name,
          reason: `removed by parent agent config (tools.remove)`,
        })),
      ],
    }
  }

  const ctx = createSubagentContext(parentContext, {
    shareAbortController: isInteractive,
    shareSetAppState: isInteractive,
    shareSetResponseLength: isInteractive,

    messages: config.messages.access === 'read'
      ? [...parentContext.messages]
      : parentContext.messages,

    options,
  })

  // 资源预算：继承父的（共享），或按配置创建新的
  if (parentContext.agentBudget) {
    ctx.agentBudget = parentContext.agentBudget
  } else if (config.budget) {
    const maxAgentCalls = config.budget.maxAgentCalls ?? 20
    ctx.agentBudget = { remainingCalls: maxAgentCalls }
  }

  return ctx
}

/**
 * 运行子 agent 并返回结构化的 AgentResult。
 *
 * runAgent 是 async generator，此函数封装迭代逻辑，
 * 收集所有消息后写入独立 transcript，并返回按需查询接口。
 */
export async function runChildAgent(
  parentContext: ToolUseContext,
  config: AgentContextConfig,
  prompt: string,
): Promise<AgentResult> {
  const agentCtx = createAgentContext(parentContext, config)
  const agentId = agentCtx.agentId

  const { runAgent } = await import('../tools/AgentTool/runAgent.js')
  const promptMessages = [{
    id: 'user-1',
    role: 'user' as const,
    content: prompt,
    timestamp: new Date().toISOString(),
  }]

  // 收集子 agent 的所有消息
  const messages: unknown[] = []
  const generator = runAgent({
    agentDefinition: { agentType: 'general-purpose', name: 'subagent' } as any,
    promptMessages,
    toolUseContext: agentCtx,
    canUseTool: () => true,
    isAsync: false,
    availableTools: agentCtx.options.tools,
  })

  for await (const msg of generator) {
    messages.push(msg)
  }

  // 写入独立 transcript
  const { writeAgentTranscript } = await import('./writeTranscript.js')
  writeAgentTranscript(agentId, messages, agentCtx.options.cwd)

  return {
    agentId,
    summary: extractSummary(messages),
    artifacts: {
      files: extractFiles(messages),
      keyFindings: extractKeyFindings(messages),
    },
    readTranscript: () => readSubagentTranscript(agentId),
    readMemory: () => readSubagentMemory(agentId),
    readFileChanges: () => readSubagentFileChanges(agentId),
  }
}

// ─── 按需查询 ──────────────────────────────────────

async function readSubagentTranscript(agentId: string): Promise<Message[]> {
  const dataDir = getDataDir()
  const globPath = path.join(dataDir, 'projects', '*', 'subagents', `${agentId}.jsonl`)
  try {
    const { Glob } = await import('bun')
    const files = [...new Glob(globPath).scanSync()]
    if (files.length === 0) return []
    const content = fs.readFileSync(files[0], 'utf-8')
    return content
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line) as Message)
  } catch {
    return []
  }
}

async function readSubagentMemory(_agentId: string): Promise<MemoryEntry[]> {
  return []
}

async function readSubagentFileChanges(_agentId: string): Promise<FileChange[]> {
  return []
}

// ─── 辅助函数 ──────────────────────────────────────

function extractSummary(messages: unknown[]): string {
  const lastAssistant = [...messages].reverse().find((m: any) => m?.type === 'assistant')
  if (!lastAssistant) return ''
  const content = (lastAssistant as any).message?.content
  if (Array.isArray(content)) {
    const textBlocks = content.filter((c: any) => c?.type === 'text')
    return textBlocks.map((c: any) => c.text).join('\n').slice(0, 1000)
  }
  return String(content ?? '').slice(0, 1000)
}

function extractFiles(_messages: unknown[]): string[] {
  return []
}

function extractKeyFindings(_messages: unknown[]): string[] {
  return []
}
