/**
 * Catalog API — 工具台账的 REST 端点（catalog-mcp 三层查询 + 前端 Tools tab + 探测/删除）。
 *
 * 注意：与 /api/tools（handleToolsApi，harness 工具的可用性检查）是两回事——见 [[工具生态-台账与分级披露方案]] §〇
 * 「两种 tool 别混」。台账走独立资源 /api/catalog。
 *
 * 端点：
 *   GET    /api/catalog/categories        Tier1 目录（每类计数+可用数）
 *   GET    /api/catalog/tools?category=X   Tier2 章节
 *   GET    /api/catalog/tools/:id          Tier3 详情
 *   GET    /api/catalog/all                UI 全量（前端 Tools tab）
 *   POST   /api/catalog/probe              手动重探（"重新探测"按钮）
 *   DELETE /api/catalog/tools/:id          删（受 PROTECTED_TOOLS 守卫）
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { ApiError, errorResponse } from '../middleware/errorHandler.js'
import {
  listCategories,
  listTools,
  getTool,
  getAll,
  getToolsDir,
  clearCatalogCache,
} from '../services/toolCatalogService.js'
import { readStatus, probeAll, setUserPath, readUserPaths } from '../services/toolProbeService.js'
import { isProtectedTool } from '../services/protectedResources.js'

export async function handleCatalogApi(req: Request, url: URL, _segments: string[]): Promise<Response> {
  try {
    const parts = url.pathname.split('/').filter(Boolean)
    const sub = parts[2] // 'categories' | 'tools' | 'all' | 'probe'

    // GET /api/catalog/categories — Tier1
    if (req.method === 'GET' && sub === 'categories') {
      const status = await readStatus()
      return Response.json({ categories: await listCategories(status) })
    }

    // /api/catalog/tools[...]
    if (sub === 'tools') {
      const toolId = parts[3] ? decodeURIComponent(parts[3]) : undefined

      // GET /api/catalog/tools?category=X — Tier2
      if (req.method === 'GET' && !toolId) {
        const category = url.searchParams.get('category')
        if (!category) throw ApiError.badRequest('category query param is required')
        const status = await readStatus()
        return Response.json({ tools: await listTools(category, status) })
      }

      // GET /api/catalog/tools/:id — Tier3
      if (req.method === 'GET' && toolId) {
        const status = await readStatus()
        const tool = await getTool(toolId, status)
        if (!tool) throw ApiError.notFound(`Tool not found: ${toolId}`)
        const userPaths = await readUserPaths()
        return Response.json({ tool: withProtected({ ...tool, userPath: userPaths[toolId] }) })
      }

      // DELETE /api/catalog/tools/:id — 删（守卫内置）
      if (req.method === 'DELETE' && toolId && !parts[4]) {
        return await deleteTool(toolId)
      }

      // POST /api/catalog/tools/:id/path — 设置用户自定义路径（requiresUserPath 工具）
      if (req.method === 'POST' && toolId && parts[4] === 'path') {
        let body: { path?: string } = {}
        try { body = JSON.parse(await req.text()) } catch { /* 空/非法 body 视为清除 */ }
        await setUserPath(toolId, body.path ?? null)
        await probeAll() // 立即重探使配置生效
        const status = await readStatus()
        const tool = await getTool(toolId, status)
        return Response.json({ ok: true, tool: tool ? withProtected(tool) : null })
      }

      // DELETE /api/catalog/tools/:id/path — 清除用户路径
      if (req.method === 'DELETE' && toolId && parts[4] === 'path') {
        await setUserPath(toolId, null)
        await probeAll()
        return Response.json({ ok: true })
      }

      throw new ApiError(405, 'Method not allowed', 'METHOD_NOT_ALLOWED')
    }

    // GET /api/catalog/all — UI 全量
    if (req.method === 'GET' && sub === 'all') {
      const status = await readStatus()
      const userPaths = await readUserPaths()
      const tools = (await getAll(status)).map((t) => withProtected({ ...t, userPath: userPaths[t.id] }))
      return Response.json({ tools })
    }

    // POST /api/catalog/probe — 手动重探
    if (req.method === 'POST' && sub === 'probe') {
      const status = await probeAll()
      return Response.json({ ok: true, status })
    }

    throw ApiError.notFound('Catalog API route')
  } catch (err) {
    return errorResponse(err)
  }
}

/** 给工具记录加 protected 标志：受 PROTECTED_TOOLS 守卫 或 builtin（随包发）即不可删，前端据此隐藏删除按钮。 */
function withProtected<T extends { id: string; builtin?: boolean }>(tool: T): T & { protected?: boolean } {
  const isProtected = isProtectedTool(tool.id) || tool.builtin === true
  return isProtected ? { ...tool, protected: true } : tool
}

/** 删除单个工具 yaml；内置工具受 PROTECTED_TOOLS 守卫拒绝（照 agent/skill/mcp 三面范式）。 */
async function deleteTool(id: string): Promise<Response> {
  // 防路径穿越
  if (id.includes('..') || id.includes('/') || id.includes('\\') || id.includes(':')) {
    throw ApiError.badRequest('Invalid tool id')
  }
  if (isProtectedTool(id)) {
    throw ApiError.badRequest(`内置工具不可删除：${id}`)
  }
  const dir = getToolsDir()
  const candidates = [path.join(dir, `${id}.yaml`), path.join(dir, `${id}.yml`)]
  let removed = false
  for (const file of candidates) {
    try {
      await fs.unlink(file)
      removed = true
      break
    } catch {
      // try next ext
    }
  }
  if (!removed) throw ApiError.notFound(`Tool not found: ${id}`)
  clearCatalogCache()
  return Response.json({ ok: true })
}
