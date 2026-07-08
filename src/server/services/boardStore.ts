/**
 * BoardStore — dir-keyed 黑板核心（项目与会话共用）。
 *
 * 把黑板图操作从"项目"概念解耦：只认一个 boardDir（绝对目录），
 * 项目走 security/{projectId}/，会话走 security/_sessions/{sessionId}/。
 * 图语义/节点模型/单写入者规则不变，只换存储目录来源。
 *
 * goal/target 由调用方传入（项目从 meta，会话从 board-meta.json）。
 * 不兜底：失败显式抛或返 null，绝不返空掩盖。
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import type { ExploreNode, BoardHint, BoardGraph } from './securityProjectService.js'
import type { ExplorePhase } from './findingsExtractionService.js'

async function readJson<T>(dir: string, file: string): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(path.join(dir, file), 'utf-8')) as T
  } catch {
    return null
  }
}

async function writeJson(dir: string, file: string, data: unknown): Promise<void> {
  await fs.mkdir(dir, { recursive: true })
  await fs.writeFile(path.join(dir, file), JSON.stringify(data, null, 2), 'utf-8')
}

/**
 * 读节点。兼容：旧 intent 无 graphStatus 时默认 done（不被调度器当待探重复派）。
 */
export async function getNodes(dir: string): Promise<ExploreNode[]> {
  const nodes = (await readJson<ExploreNode[]>(dir, 'nodes.json')) ?? []
  for (const n of nodes) {
    if (n.type === 'intent' && !n.graphStatus) n.graphStatus = 'done'
  }
  return nodes
}

async function writeNodes(dir: string, nodes: ExploreNode[]): Promise<void> {
  await writeJson(dir, 'nodes.json', nodes)
}

export async function getHints(dir: string): Promise<BoardHint[]> {
  return (await readJson<BoardHint[]>(dir, 'hints.json')) ?? []
}

export async function addHint(dir: string, content: string): Promise<BoardHint> {
  const text = (content ?? '').trim()
  if (!text) throw new Error('hint content required')
  const hints = await getHints(dir)
  const hint: BoardHint = { id: crypto.randomUUID(), content: text.slice(0, 1000), createdAt: Date.now() }
  hints.push(hint)
  await writeJson(dir, 'hints.json', hints)
  return hint
}

/** Bootstrap：写无 parent 的根 fact/finding/asset 节点（asset 用于搭攻击面/对象骨架）。 */
export async function addRootFact(
  dir: string,
  fact: Omit<ExploreNode, 'id' | 'type' | 'createdAt'> & { type?: 'fact' | 'finding' | 'asset' },
): Promise<ExploreNode> {
  const nodes = await getNodes(dir)
  const factNode: ExploreNode = { ...fact, id: crypto.randomUUID(), type: fact.type ?? 'fact', createdAt: Date.now() }
  nodes.push(factNode)
  await writeNodes(dir, nodes)
  return factNode
}

/** Reason：批量写 open intent。 */
export async function addIntents(
  dir: string,
  intents: Array<{ title: string; fromFactIds?: string[]; phase?: ExplorePhase; parentId?: string }>,
): Promise<ExploreNode[]> {
  const nodes = await getNodes(dir)
  const created: ExploreNode[] = []
  for (const it of intents) {
    const title = it.title?.trim()
    if (!title) continue
    const node: ExploreNode = {
      id: crypto.randomUUID(),
      type: 'intent',
      title: title.slice(0, 200),
      sessionId: '',
      createdAt: Date.now(),
      graphStatus: 'open',
      phase: it.phase,
      parentId: it.parentId,
      fromFactIds: it.fromFactIds && it.fromFactIds.length > 0 ? it.fromFactIds : undefined,
    }
    nodes.push(node)
    created.push(node)
  }
  if (created.length > 0) await writeNodes(dir, nodes)
  return created
}

/** 派 Explore 前认领：open → running。 */
export async function claimIntent(dir: string, intentId: string, worker: string): Promise<boolean> {
  const nodes = await getNodes(dir)
  const intent = nodes.find((n) => n.id === intentId && n.type === 'intent')
  if (!intent) return false
  if ((intent.graphStatus ?? 'done') !== 'open') return false
  intent.graphStatus = 'running'
  intent.claimedBy = worker
  await writeNodes(dir, nodes)
  return true
}

/** Explore 回写：running → done，写产出 fact 并连边。 */
export async function completeIntent(
  dir: string,
  intentId: string,
  fact: Omit<ExploreNode, 'id' | 'type' | 'createdAt'> & { type?: 'fact' | 'finding' },
): Promise<ExploreNode | null> {
  const nodes = await getNodes(dir)
  const intent = nodes.find((n) => n.id === intentId && n.type === 'intent')
  if (!intent) return null
  const factNode: ExploreNode = {
    ...fact,
    id: crypto.randomUUID(),
    type: fact.type ?? 'fact',
    parentId: fact.parentId ?? intentId,
    createdAt: Date.now(),
  }
  nodes.push(factNode)
  intent.graphStatus = 'done'
  intent.toFactId = factNode.id
  if (fact.result) intent.result = fact.result
  await writeNodes(dir, nodes)
  return factNode
}

/** Explore 探死：running → failed。 */
export async function failIntent(dir: string, intentId: string, reason: string): Promise<boolean> {
  const nodes = await getNodes(dir)
  const intent = nodes.find((n) => n.id === intentId && n.type === 'intent')
  if (!intent) return false
  intent.graphStatus = 'failed'
  if (reason?.trim()) intent.result = reason.trim().slice(0, 500)
  await writeNodes(dir, nodes)
  return true
}

/** 读整张图（goal/target 由调用方给）。 */
export async function getGraph(dir: string, goal: string, target: string): Promise<BoardGraph> {
  const [nodes, hints] = await Promise.all([getNodes(dir), getHints(dir)])
  return { goal, target, nodes, hints }
}

/** 导出 worker 可读的紧凑快照。 */
export async function exportGraphSnapshot(dir: string, goal: string, target: string): Promise<string> {
  const graph = await getGraph(dir, goal, target)
  const compact = {
    goal: graph.goal,
    target: graph.target,
    facts: graph.nodes
      .filter((n) => n.type === 'fact' || n.type === 'finding' || n.type === 'asset')
      .map((n) => ({ id: n.id, type: n.type, title: n.title, parentId: n.parentId, severity: n.severity, result: n.result })),
    intents: graph.nodes
      .filter((n) => n.type === 'intent')
      .map((n) => ({ id: n.id, title: n.title, status: n.graphStatus ?? 'open', parentId: n.parentId, from: n.fromFactIds, to: n.toFactId, result: n.result })),
    hints: graph.hints.map((h) => h.content),
  }
  return JSON.stringify(compact, null, 2)
}
