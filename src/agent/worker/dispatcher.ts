/**
 * Dispatcher 决策逻辑 — 纯函数，照 Cairn loop.py 精简（单 worker 串行、进程内）。
 *
 * 全部基于图状态计算，不碰 IO、不起子进程，可独立单测。
 * 调度循环（orchestrator）调这些函数决定每拍派什么任务、怎么把 worker 产出映射成节点。
 */

import type { BoardGraph, ExploreNode } from '../../server/services/securityProjectService.js'
import type { WorkerNode } from './contracts.js'

// ─── reason 检查点：上次 reason 跑完时的图计数 ──────────────────

export type ReasonCheckpoint = {
  factCount: number
  hintCount: number
  openIntentCount: number
}

// ─── 决策 ────────────────────────────────────────────────────

export type Decision =
  | { kind: 'bootstrap' }
  | { kind: 'reason'; trigger: string }
  | { kind: 'explore'; intent: ExploreNode }
  | { kind: 'idle' }

// ─── 图计数原语 ──────────────────────────────────────────────

/** 可作为事实来源的节点：fact / finding / asset。 */
export function factNodes(graph: BoardGraph): ExploreNode[] {
  return graph.nodes.filter((n) => n.type === 'fact' || n.type === 'finding' || n.type === 'asset')
}

/** open intent（待探，可被认领）。 */
export function openIntents(graph: BoardGraph): ExploreNode[] {
  return graph.nodes.filter((n) => n.type === 'intent' && (n.graphStatus ?? 'done') === 'open')
}

/** 当前图对 reason 而言的计数快照。 */
export function graphCounts(graph: BoardGraph): ReasonCheckpoint {
  return {
    factCount: factNodes(graph).length,
    hintCount: graph.hints.length,
    openIntentCount: openIntents(graph).length,
  }
}

// ─── reason 触发判断 ─────────────────────────────────────────

/**
 * 图自上次 reason 后是否变化到需要重新 reason。
 * 照 Cairn：facts↑ / hints↑ / open_intents 从有变空。无 checkpoint=初次=触发。
 * 返回触发原因字符串；不触发返回 null。
 */
export function reasonTrigger(graph: BoardGraph, checkpoint: ReasonCheckpoint | null): string | null {
  if (checkpoint === null) return 'initial'
  const cur = graphCounts(graph)
  const changes: string[] = []
  if (cur.factCount > checkpoint.factCount) changes.push(`facts:${checkpoint.factCount}->${cur.factCount}`)
  if (cur.hintCount > checkpoint.hintCount) changes.push(`hints:${checkpoint.hintCount}->${cur.hintCount}`)
  if (checkpoint.openIntentCount > 0 && cur.openIntentCount === 0) {
    changes.push(`open_intents:${checkpoint.openIntentCount}->0`)
  }
  return changes.length > 0 ? changes.join(',') : null
}

// ─── 下一步决策 ──────────────────────────────────────────────

/**
 * 决定下一拍派什么。串行单 worker，无并发，所以决策只依赖图 + checkpoint：
 *   ① 空图（无任何节点）→ bootstrap
 *   ② reason 该触发 → reason
 *   ③ 有未认领 open intent → explore（取最新的）
 *   ④ 否则 → idle（图没变、无待探，收敛）
 */
export function decideNext(graph: BoardGraph, checkpoint: ReasonCheckpoint | null): Decision {
  if (graph.nodes.length === 0) return { kind: 'bootstrap' }

  const trigger = reasonTrigger(graph, checkpoint)
  if (trigger !== null) return { kind: 'reason', trigger }

  const open = openIntents(graph)
  if (open.length > 0) {
    const newest = open.reduce((a, b) => (b.createdAt > a.createdAt ? b : a))
    return { kind: 'explore', intent: newest }
  }

  return { kind: 'idle' }
}

// ─── worker prompt 输入构建（喂 runReason 的文本块） ─────────────

/** reason 的 Valid facts 块：可作 from 来源的节点 id + 标题。 */
export function buildFactIds(graph: BoardGraph): string {
  const items = factNodes(graph).map((n) => ({ id: n.id, title: n.title }))
  return JSON.stringify(items, null, 2)
}

/** reason 的 Open Intents 块：已声明未结论的 intent。 */
export function buildOpenIntents(graph: BoardGraph): string {
  const items = openIntents(graph).map((n) => ({ id: n.id, title: n.title }))
  return JSON.stringify(items, null, 2)
}

// ─── worker 产出 → 节点（落库前形态） ──────────────────────────

/**
 * 把 worker 吐的 WorkerNode 映射成 completeIntent/addRootFact 的入参。
 * sessionId 来自该次 worker 的专属会话（探索树可点进去看 transcript）。
 */
export function workerNodeToFact(
  node: WorkerNode,
  sessionId: string,
): Omit<ExploreNode, 'id' | 'createdAt'> & { type: 'fact' | 'finding' } {
  return {
    type: node.type,
    title: node.title.slice(0, 200),
    result: node.result,
    process: node.process,
    evidence: node.evidence,
    payload: node.payload,
    flag: node.flag,
    severity: node.severity,
    phase: node.phase,
    sessionId,
  }
}
