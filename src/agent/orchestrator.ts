/**
 * Orchestrator — 真黑板调度循环（Cairn 式 Dispatcher，server 进程内、单 worker 串行）。
 *
 * 每拍：读图 → decideNext → 派 bootstrap/reason/explore worker → 调度器（唯一写入者）回写黑板。
 * worker 走一次性 CLI 子进程（createCliWorkerExecutor），不直接读黑板文件、不直接写库。
 *
 * 不兜底：worker 出错/解析失败一律记 failed（explore）或终止本拍，绝不返空掩盖。
 * 终止：Goal 达成 / 用户暂停 / 预算耗尽（默认 50 次 worker 调用 / 60 分钟）。
 */

import * as path from 'node:path'
import * as fs from 'node:fs'
import { getDataDir } from '../utils/kimoPaths.js'
import { securityProjectService } from '../server/services/securityProjectService.js'
import { createCliWorkerExecutor } from './worker/workerExecutor.js'
import { runBootstrap, runReason, runExplore, type WorkerExecutor } from './worker/runWorker.js'
import {
  decideNext,
  graphCounts,
  buildFactIds,
  buildOpenIntents,
  workerNodeToFact,
  type ReasonCheckpoint,
} from './worker/dispatcher.js'

export type OrchestratorStatus = 'running' | 'paused' | 'completed' | 'stopped' | 'budget_exhausted'

export type OrchestratorBudget = {
  maxCalls: number      // worker 调用次数上限
  maxDurationMs: number // wall-clock 上限
}

export const DEFAULT_BUDGET: OrchestratorBudget = {
  maxCalls: 50,
  maxDurationMs: 60 * 60_000,
}

export type OrchestratorState = {
  projectId: string
  status: OrchestratorStatus
  startedAt: number
  stoppedAt?: number
  calls: number
  lastError?: string
}

/** worker 执行器工厂：每次 worker 调用给一个专属 sessionId（产出节点指向真实 transcript）。 */
export type WorkerExecutorFactory = (sessionId: string) => WorkerExecutor

// 运行中编排的控制句柄。
export type Control = { state: OrchestratorState; paused: boolean; stopped: boolean }

/** 造一个初始 Control（running、calls=0）。供 startOrchestrator 与单测共用。 */
export function newControl(projectId: string): Control {
  return {
    state: { projectId, status: 'running', startedAt: Date.now(), calls: 0 },
    paused: false,
    stopped: false,
  }
}

// 运行中编排的注册表（projectId → 控制句柄）。
const registry = new Map<string, Control>()

export function getOrchestratorState(projectId: string): OrchestratorState | null {
  return registry.get(projectId)?.state ?? null
}

/**
 * 核心调度循环（executor 注入，可单测）。
 * 每拍读图决策、派 worker、回写。executorFactory 把每次 worker 调用映射成一次执行。
 */
export async function runDispatchLoop(
  projectId: string,
  executorFactory: WorkerExecutorFactory,
  budget: OrchestratorBudget,
  control: Control,
): Promise<OrchestratorState> {
  const { state } = control
  let checkpoint: ReasonCheckpoint | null = null

  while (true) {
    if (control.stopped) {
      state.status = 'stopped'
      break
    }
    if (control.paused) {
      state.status = 'paused'
      break
    }
    if (state.calls >= budget.maxCalls || Date.now() - state.startedAt >= budget.maxDurationMs) {
      state.status = 'budget_exhausted'
      break
    }

    const graph = await securityProjectService.getGraph(projectId)
    if (!graph) {
      state.status = 'stopped'
      state.lastError = 'project not found'
      break
    }

    const decision = decideNext(graph, checkpoint)
    if (decision.kind === 'idle') {
      state.status = 'completed'
      break
    }

    const sessionId = crypto.randomUUID()
    const execute = executorFactory(sessionId)
    state.calls++

    if (decision.kind === 'bootstrap') {
      const payload = await runBootstrap(
        { origin: graph.target, goal: graph.goal, hints: graph.hints.map((h) => h.content).join('\n') },
        execute,
      )
      await securityProjectService.addRootFact(projectId, workerNodeToFact(payload.node, sessionId))
      if (payload.complete) {
        await securityProjectService.updateProject(projectId, { status: 'completed' })
        state.status = 'completed'
        break
      }
      continue
    }

    if (decision.kind === 'reason') {
      // 派前先拍当前图计数；reason 成功后提交为 checkpoint（防重复触发）。
      const counts = graphCounts(graph)
      const payload = await runReason(
        { graph: await securityProjectService.exportGraphSnapshot(projectId), factIds: buildFactIds(graph), openIntents: buildOpenIntents(graph) },
        execute,
      )
      if (payload.kind === 'complete') {
        await securityProjectService.updateProject(projectId, { status: 'completed' })
        state.status = 'completed'
        break
      }
      if (payload.kind === 'intents') {
        await securityProjectService.addIntents(projectId, payload.intents)
      }
      checkpoint = counts
      continue
    }

    // explore：派前认领（open→running），成功 completeIntent，失败 failIntent（不兜底）。
    const intent = decision.intent
    const claimed = await securityProjectService.claimIntent(projectId, intent.id, sessionId)
    if (!claimed) continue // 竞态/已非 open，跳过本拍重新决策
    try {
      const payload = await runExplore(
        { graph: await securityProjectService.exportGraphSnapshot(projectId), intentId: intent.id, intentDescription: intent.title },
        execute,
      )
      await securityProjectService.completeIntent(projectId, intent.id, workerNodeToFact(payload.node, sessionId))
    } catch (err) {
      await securityProjectService.failIntent(projectId, intent.id, err instanceof Error ? err.message : String(err))
    }
  }

  state.stoppedAt = Date.now()
  return state
}

/** 启动编排：建工作目录 + 真实 CLI executor，后台跑循环（不阻塞调用方）。 */
export async function startOrchestrator(
  projectId: string,
  budget: OrchestratorBudget = DEFAULT_BUDGET,
): Promise<OrchestratorState> {
  const existing = registry.get(projectId)
  if (existing && existing.state.status === 'running') return existing.state

  const workDir = path.join(getDataDir(), 'security', projectId, 'work')
  fs.mkdirSync(workDir, { recursive: true })

  const state: OrchestratorState = { projectId, status: 'running', startedAt: Date.now(), calls: 0 }
  const control: Control = { state, paused: false, stopped: false }
  registry.set(projectId, control)

  const factory: WorkerExecutorFactory = (sessionId) => createCliWorkerExecutor({ workDir, sessionId })

  // 后台跑，不阻塞；前端轮询 nodes.json 看黑板生长（沿用 D2 提炼的轮询模式）。
  void runDispatchLoop(projectId, factory, budget, control).catch((err) => {
    state.status = 'stopped'
    state.lastError = err instanceof Error ? err.message : String(err)
    state.stoppedAt = Date.now()
  })

  return state
}

/** 暂停编排：循环下一拍检测到后停在 paused，黑板保留。 */
export function pauseOrchestrator(projectId: string): OrchestratorState | null {
  const control = registry.get(projectId)
  if (!control) return null
  control.paused = true
  return control.state
}

/** 停止编排：循环下一拍退出，从注册表移除。 */
export function stopOrchestrator(projectId: string): OrchestratorState | null {
  const control = registry.get(projectId)
  if (!control) return null
  control.stopped = true
  return control.state
}
