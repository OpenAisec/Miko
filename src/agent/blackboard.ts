/**
 * Blackboard — 共享探索状态空间
 *
 * 基于 Blackboard Architecture 模式，多个 Agent 通过黑板协作，
 * 不直接通信（Stigmergy）。orchestrator 读取黑板上的 Facts 和 Intents，
 * 决定下一步探索方向。
 */

// ─── Fact：已确认的客观发现 ────────────────────────────────────

export type FactSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type Fact = {
  id: string
  title: string
  detail: string
  severity?: FactSeverity
  sourceIntent: string      // 来源于哪个 Intent
  evidence?: string
  createdAt: number
}

// ─── Intent：想探索的方向 ──────────────────────────────────────

export type IntentStatus = 'pending' | 'exploring' | 'completed' | 'failed'

export type Intent = {
  id: string
  description: string
  status: IntentStatus
  parentFactId?: string      // 从哪个 Fact 延伸
  createdBy: 'agent' | 'user'
  createdAt: number
}

// ─── Hint：用户注入的指导 ──────────────────────────────────────

export type Hint = {
  id: string
  content: string
  createdAt: number
}

// ─── Blackboard ──────────────────────────────────────────────

export type Blackboard = {
  facts: Fact[]
  intents: Intent[]
  hints: Hint[]
  closedIntentIds: string[]   // 已探索无发现的 Intent
}
