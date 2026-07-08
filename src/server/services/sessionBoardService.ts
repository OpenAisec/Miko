/**
 * SessionBoardService — 会话级黑板（路 A 纠正：黑板归会话，项目是事后汇总）。
 *
 * 开测试模式不选项目，黑板存 data/security/_sessions/{sessionId}/，
 * 复用 dir-keyed boardStore 的全部图操作。goal/target 存本会话的 board-meta.json
 * （target 可后补/从首条消息推导，goal 默认"发现目标所有高危漏洞"）。
 *
 * 事后"沉淀成项目/并入项目"是独立后续，不在本服务职责内。
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { getDataDir } from '../../utils/kimoPaths.js'
import * as boardStore from './boardStore.js'
import type { ExploreNode, BoardHint, BoardGraph } from './securityProjectService.js'
import type { ExplorePhase } from './findingsExtractionService.js'

const SESSIONS_SUBDIR = path.join('security', '_sessions')

export type SessionBoardMeta = {
  sessionId: string
  goal: string
  target: string
  createdAt: number
}

function sessionBoardDir(sessionId: string): string {
  return path.join(getDataDir(), SESSIONS_SUBDIR, sessionId)
}

function defaultGoal(target: string): string {
  const t = (target ?? '').trim()
  return t ? `发现 ${t} 的所有高危漏洞，覆盖所有可访问入口` : '发现目标的所有高危漏洞，覆盖所有可访问入口'
}

export class SessionBoardService {
  /** 开测试模式时初始化会话黑板 meta（幂等：已存在则只补缺失字段）。 */
  async ensureBoard(sessionId: string, opts?: { goal?: string; target?: string }): Promise<SessionBoardMeta> {
    const dir = sessionBoardDir(sessionId)
    await fs.mkdir(dir, { recursive: true })
    const existing = await this.getMeta(sessionId)
    const target = opts?.target?.trim() || existing?.target || ''
    const meta: SessionBoardMeta = {
      sessionId,
      target,
      goal: opts?.goal?.trim() || existing?.goal || defaultGoal(target),
      createdAt: existing?.createdAt ?? Date.now(),
    }
    await fs.writeFile(path.join(dir, 'board-meta.json'), JSON.stringify(meta, null, 2), 'utf-8')
    return meta
  }

  async getMeta(sessionId: string): Promise<SessionBoardMeta | null> {
    try {
      return JSON.parse(await fs.readFile(path.join(sessionBoardDir(sessionId), 'board-meta.json'), 'utf-8')) as SessionBoardMeta
    } catch {
      return null
    }
  }

  /** 是否存在会话黑板（meta 在即视为已开过测试模式）。 */
  async exists(sessionId: string): Promise<boolean> {
    return (await this.getMeta(sessionId)) !== null
  }

  // ─── 图操作：委托 boardStore，dir = 会话黑板目录 ──────────

  getNodes(sessionId: string): Promise<ExploreNode[]> {
    return boardStore.getNodes(sessionBoardDir(sessionId))
  }

  getHints(sessionId: string): Promise<BoardHint[]> {
    return boardStore.getHints(sessionBoardDir(sessionId))
  }

  addHint(sessionId: string, content: string): Promise<BoardHint> {
    return boardStore.addHint(sessionBoardDir(sessionId), content)
  }

  addRootFact(
    sessionId: string,
    fact: Omit<ExploreNode, 'id' | 'type' | 'createdAt'> & { type?: 'fact' | 'finding' | 'asset' },
  ): Promise<ExploreNode> {
    return boardStore.addRootFact(sessionBoardDir(sessionId), fact)
  }

  addIntents(
    sessionId: string,
    intents: Array<{ title: string; fromFactIds?: string[]; phase?: ExplorePhase; parentId?: string }>,
  ): Promise<ExploreNode[]> {
    return boardStore.addIntents(sessionBoardDir(sessionId), intents)
  }

  claimIntent(sessionId: string, intentId: string, worker: string): Promise<boolean> {
    return boardStore.claimIntent(sessionBoardDir(sessionId), intentId, worker)
  }

  completeIntent(
    sessionId: string,
    intentId: string,
    fact: Omit<ExploreNode, 'id' | 'type' | 'createdAt'> & { type?: 'fact' | 'finding' },
  ): Promise<ExploreNode | null> {
    return boardStore.completeIntent(sessionBoardDir(sessionId), intentId, fact)
  }

  failIntent(sessionId: string, intentId: string, reason: string): Promise<boolean> {
    return boardStore.failIntent(sessionBoardDir(sessionId), intentId, reason)
  }

  /** 读整张图（goal/target 取自会话 board-meta；无 meta 返 null）。 */
  async getGraph(sessionId: string): Promise<BoardGraph | null> {
    const meta = await this.getMeta(sessionId)
    if (!meta) return null
    return boardStore.getGraph(sessionBoardDir(sessionId), meta.goal, meta.target)
  }

  /** 导出 worker 可读快照（无 meta 返空串）。 */
  async exportGraphSnapshot(sessionId: string): Promise<string> {
    const meta = await this.getMeta(sessionId)
    if (!meta) return ''
    return boardStore.exportGraphSnapshot(sessionBoardDir(sessionId), meta.goal, meta.target)
  }
}

export const sessionBoardService = new SessionBoardService()
