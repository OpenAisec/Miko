/**
 * Tools REST API
 *
 * GET /api/tools/availability — 返回各工具的可用状态
 */

import { GlobTool } from '../../tools/GlobTool/GlobTool.js'

type ToolAvailability = {
  name: string
  available: boolean
  reason?: string
}

export async function handleToolsApi(
  req: Request,
  url: URL,
  segments: string[],
): Promise<Response> {
  const sub = segments[2]

  if (req.method !== 'GET') {
    return Response.json({ error: 'METHOD_NOT_ALLOWED' }, { status: 405 })
  }

  if (sub === 'availability') {
    // ?refresh=true 时强制重新检测
    if (url.searchParams.get('refresh') === 'true') {
      const { refreshRgAvailability } = await import('../../tools/GlobTool/GlobTool.js')
      refreshRgAvailability()
    }

    const availabilities: ToolAvailability[] = [
      {
        name: GlobTool.name,
        available: GlobTool.checkAvailability?.() ?? true,
        ...(GlobTool.checkAvailability?.() === false ? { reason: '需要安装 ripgrep' } : {}),
      },
    ]

    return Response.json({ tools: availabilities })
  }

  return Response.json({ error: 'NOT_FOUND' }, { status: 404 })
}
