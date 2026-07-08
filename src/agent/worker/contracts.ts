/**
 * Worker 输出契约 — 三套任务的结构化 payload 类型 + 校验。
 *
 * 对齐节点模型（asset/fact/intent/finding + 三槽）与阶段1 后端签名：
 *   explore  → completeIntent(node)
 *   reason   → addIntents(intents) / 标记 complete
 *   bootstrap→ 写首个 fact 节点 (+ 可能 complete)
 *
 * 校验失败或 worker 拒绝（accepted:false）一律 **抛错**，不降级、不兜底。
 */

import type { ExplorePhase } from '../../server/services/findingsExtractionService.js'

// ─── 公共：worker 产出的结果节点（落库前形态） ──────────────

export type WorkerNodeType = 'fact' | 'finding'
const NODE_TYPES: WorkerNodeType[] = ['fact', 'finding']
const PHASES: ExplorePhase[] = ['recon', 'asset', 'probe', 'exploit', 'post', 'other']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

/** worker 探完一个方向产出的节点（喂给 completeIntent）。result 必填——有发现写发现，没发现写"不存在+原因"。 */
export type WorkerNode = {
  type: WorkerNodeType
  title: string
  result: string
  process?: string
  evidence?: string
  payload?: string
  flag?: string
  severity?: (typeof SEVERITIES)[number]
  phase?: ExplorePhase
}

// ─── explore ────────────────────────────────────────────────

export type ExplorePayload = { node: WorkerNode }

/** 校验 explore 输出；非法/rejected 抛错。 */
export function validateExplorePayload(obj: Record<string, unknown>): ExplorePayload {
  assertAccepted(obj)
  const data = requireObject(obj.data, 'data')
  const node = requireWorkerNode(data.node, 'data.node')
  return { node }
}

// ─── bootstrap ──────────────────────────────────────────────

export type BootstrapPayload = { node: WorkerNode; complete?: { description: string } }

/** 校验 bootstrap 输出；非法/rejected 抛错。complete 可选。 */
export function validateBootstrapPayload(obj: Record<string, unknown>): BootstrapPayload {
  assertAccepted(obj)
  const data = requireObject(obj.data, 'data')
  const node = requireWorkerNode(data.node, 'data.node')
  const result: BootstrapPayload = { node }
  if (data.complete !== undefined) {
    const c = requireObject(data.complete, 'data.complete')
    result.complete = { description: requireNonEmptyString(c.description, 'data.complete.description') }
  }
  return result
}

// ─── reason ─────────────────────────────────────────────────

export type ReasonIntent = { title: string; fromFactIds?: string[]; phase?: ExplorePhase }
export type ReasonPayload =
  | { kind: 'complete'; fromFactIds: string[]; description: string }
  | { kind: 'intents'; intents: ReasonIntent[] }
  | { kind: 'noop' }

/**
 * 校验 reason 输出；非法/rejected 抛错。
 * data 形态三选一：{complete:{from,description}} | {intents:[...]} | {}
 */
export function validateReasonPayload(obj: Record<string, unknown>): ReasonPayload {
  assertAccepted(obj)
  const data = requireObject(obj.data, 'data')

  if (data.complete !== undefined) {
    const c = requireObject(data.complete, 'data.complete')
    return {
      kind: 'complete',
      fromFactIds: requireStringArray(c.from, 'data.complete.from'),
      description: requireNonEmptyString(c.description, 'data.complete.description'),
    }
  }

  if (data.intents !== undefined) {
    if (!Array.isArray(data.intents)) throw new Error('data.intents must be an array')
    const intents: ReasonIntent[] = data.intents.map((raw, i) => {
      const it = requireObject(raw, `data.intents[${i}]`)
      const intent: ReasonIntent = { title: requireNonEmptyString(it.title, `data.intents[${i}].title`) }
      if (it.from !== undefined) intent.fromFactIds = requireStringArray(it.from, `data.intents[${i}].from`)
      if (it.phase !== undefined) intent.phase = requirePhase(it.phase, `data.intents[${i}].phase`)
      return intent
    })
    if (intents.length === 0) throw new Error('data.intents is empty; use {} for no-op instead')
    return { kind: 'intents', intents }
  }

  // 空 data = 本轮不提新方向
  return { kind: 'noop' }
}

// ─── 校验原语（失败即抛，不返回默认值） ──────────────────────

function assertAccepted(obj: Record<string, unknown>): void {
  if (obj.accepted !== true) {
    const reason = typeof obj.reason === 'string' ? obj.reason : 'unknown'
    throw new Error(`worker rejected the task: ${reason}`)
  }
}

function requireObject(v: unknown, path: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new Error(`${path} must be an object`)
  }
  return v as Record<string, unknown>
}

function requireNonEmptyString(v: unknown, path: string): string {
  if (typeof v !== 'string' || !v.trim()) throw new Error(`${path} must be a non-empty string`)
  return v.trim()
}

function requireStringArray(v: unknown, path: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) {
    throw new Error(`${path} must be an array of strings`)
  }
  return v as string[]
}

function requirePhase(v: unknown, path: string): ExplorePhase {
  if (typeof v !== 'string' || !PHASES.includes(v as ExplorePhase)) {
    throw new Error(`${path} must be one of ${PHASES.join('|')}`)
  }
  return v as ExplorePhase
}

function requireWorkerNode(v: unknown, path: string): WorkerNode {
  const o = requireObject(v, path)
  const type = o.type
  if (typeof type !== 'string' || !NODE_TYPES.includes(type as WorkerNodeType)) {
    throw new Error(`${path}.type must be fact|finding`)
  }
  const node: WorkerNode = {
    type: type as WorkerNodeType,
    title: requireNonEmptyString(o.title, `${path}.title`),
    result: requireNonEmptyString(o.result, `${path}.result`),
  }
  if (o.process !== undefined) node.process = requireNonEmptyString(o.process, `${path}.process`)
  if (o.evidence !== undefined) node.evidence = requireNonEmptyString(o.evidence, `${path}.evidence`)
  if (o.payload !== undefined) node.payload = requireNonEmptyString(o.payload, `${path}.payload`)
  if (o.flag !== undefined) node.flag = requireNonEmptyString(o.flag, `${path}.flag`)
  if (o.phase !== undefined) node.phase = requirePhase(o.phase, `${path}.phase`)
  if (o.severity !== undefined) {
    if (typeof o.severity !== 'string' || !SEVERITIES.includes(o.severity as WorkerNode['severity'] & string)) {
      throw new Error(`${path}.severity must be one of ${SEVERITIES.join('|')}`)
    }
    node.severity = o.severity as WorkerNode['severity']
  }
  return node
}
