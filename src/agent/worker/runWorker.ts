/**
 * runWorker — worker 单次产出的薄编排：组 prompt → 调 agent → 解析 → 校验。
 *
 * agent 执行是 **注入依赖**（WorkerExecutor）：阶段3 用 mock 单测验证产出契约，
 * 阶段2 调度器接活体 ToolUseContext + runChildAgent 时再注入真实执行器。
 *
 * 不兜底、不回退：组 prompt 失败、agent 出错、解析/校验失败一律向上抛，
 * 调用方（调度器）据此记 failed。绝不返回空结果掩盖失败。
 */

import { extractJsonObject } from './outputParser.js'
import {
  EXPLORE_PROMPT,
  REASON_PROMPT,
  BOOTSTRAP_PROMPT,
  renderPrompt,
} from './prompts.js'
import {
  validateExplorePayload,
  validateReasonPayload,
  validateBootstrapPayload,
  type ExplorePayload,
  type ReasonPayload,
  type BootstrapPayload,
} from './contracts.js'

/** 把组好的 prompt 交给真实 agent 执行，返回 agent 的原始文本输出。 */
export type WorkerExecutor = (prompt: string) => Promise<string>

const DEFAULT_MAX_INTENTS = 4

// ─── explore ────────────────────────────────────────────────

export type ExploreInput = {
  /** exportGraphSnapshot 产出的图快照文本 */
  graph: string
  intentId: string
  intentDescription: string
}

export async function runExplore(input: ExploreInput, execute: WorkerExecutor): Promise<ExplorePayload> {
  const prompt = renderPrompt(EXPLORE_PROMPT, {
    graph: input.graph,
    intent_id: input.intentId,
    intent_description: input.intentDescription,
  })
  const output = await execute(prompt)
  return validateExplorePayload(extractJsonObject(output))
}

// ─── reason ─────────────────────────────────────────────────

export type ReasonInput = {
  graph: string
  /** 可作为 from 来源的事实节点 id 列表（文本块） */
  factIds: string
  /** 已声明未结论的 intent（文本块） */
  openIntents: string
  maxIntents?: number
}

export async function runReason(input: ReasonInput, execute: WorkerExecutor): Promise<ReasonPayload> {
  const prompt = renderPrompt(REASON_PROMPT, {
    graph: input.graph,
    fact_ids: input.factIds,
    open_intents: input.openIntents,
    max_intents: String(input.maxIntents ?? DEFAULT_MAX_INTENTS),
  })
  const output = await execute(prompt)
  return validateReasonPayload(extractJsonObject(output))
}

// ─── bootstrap ──────────────────────────────────────────────

export type BootstrapInput = {
  origin: string
  goal: string
  hints: string
}

export async function runBootstrap(input: BootstrapInput, execute: WorkerExecutor): Promise<BootstrapPayload> {
  const prompt = renderPrompt(BOOTSTRAP_PROMPT, {
    origin: input.origin,
    goal: input.goal,
    hints: input.hints,
  })
  const output = await execute(prompt)
  return validateBootstrapPayload(extractJsonObject(output))
}
