/**
 * Agent Runtime — 父子 agent 调用契约
 *
 * 通用架构设计，不限于特定场景。
 * 三类资源：A 父→子（进入时配置）、B 子→父（返回时传递）、C 双向（执行期间）
 */

// ─── 类别 A：父 → 子（进入时配置） ───────────────────────────────────

export type AgentContextConfig = {
  /** 工具：默认继承父的全部，可 remove */
  tools: {
    mode: 'inherit'
    remove?: string[]           // 父基础上移除某些工具（如禁止再嵌套 AgentTool）
  }

  /** 消息：默认只读访问父消息 */
  messages: {
    access: 'read'              // 'read' | 未来可扩展 'isolated'
  }

  /** 记忆/上下文：默认继承父的记忆 */
  memory: {
    mode: 'inherit'             // 'inherit' | 未来可扩展 'isolated'
  }

  /** System prompt：默认继承，可扩展 */
  systemPrompt: {
    mode: 'inherit'             // 'inherit' | 'override' | 'extend'
    extend?: string             // mode='extend' 时追加的 prompt
  }

  /** 交互模式 */
  interaction: 'isolated' | 'interactive'

  /** 资源预算（替代 depth 硬上限） */
  budget?: {
    maxAgentCalls?: number      // 整条链最多调用次数
    maxLatencyMs?: number       // 最长 wall-clock
    maxTotalTokens?: number     // 所有子 agent 总 token
  }
}

// ─── 类别 B：子 → 父（返回时传递） ───────────────────────────────────

export type AgentResult = {
  agentId: string

  /** 自然语言总结（父 agent 阅读） */
  summary: string

  /** 结构化数据（代码直接消费） */
  artifacts: {
    files?: string[]
    keyFindings?: string[]
    custom?: Record<string, unknown>
  }

  /** 按需查询（不自动带回，不污染父上下文） */
  readTranscript(): Promise<Message[]>
  readMemory(): Promise<MemoryEntry[]>
  readFileChanges(): Promise<FileChange[]>
}

// ─── 支撑类型 ────────────────────────────────────────────────

export type Message = {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: string
}

export type MemoryEntry = {
  id: string
  content: string
  timestamp: string
  source: string
}

export type FileChange = {
  path: string
  changeType: 'created' | 'modified' | 'deleted'
  diff?: string
}
