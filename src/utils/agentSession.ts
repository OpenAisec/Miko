/**
 * agentSession — 活跃子会话状态管理
 *
 * 在 CLI 子进程内存中维护当前是否有活跃的子 agent 会话。
 * 当有活跃会话时，用户消息自动路由给子 agent 而非主会话。
 */

import type { AgentDefinition } from '../tools/AgentTool/loadAgentsDir.js'
import type { Message } from '../types/message.js'
import type { AppState } from '../state/AppStateStore.js'

export type ActiveAgentSession = {
  agentDefinition: AgentDefinition
  messages: Message[]
  getAppState: () => AppState
  abortController: AbortController
}

let activeSession: ActiveAgentSession | null = null

export function getActiveAgentSession(): ActiveAgentSession | null {
  return activeSession
}

export function setActiveAgentSession(session: ActiveAgentSession | null): void {
  activeSession = session
}

export function clearActiveAgentSession(): void {
  activeSession = null
}

/**
 * 判断 agent 输出是否看起来像最终答案（而非提问）
 */
export function looksLikeFinalAnswer(text: string): boolean {
  if (!text) return true
  // 包含问号 → 可能还在问问题
  if (text.includes('？') || text.includes('?')) return false
  // 明确表示完成
  if (/已完成|修改完成|已修改|已更新|done|completed/i.test(text)) return true
  return true
}
