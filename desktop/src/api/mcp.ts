import { api } from './client'
import type { McpServerRecord, McpUpsertPayload } from '../types/mcp'

export type McpDefaultPath = {
  name: string
  label: string
  path: string
  exists: boolean
}

export type McpServerItem = {
  name: string
  description: string
  transport: string
}

export type McpScanResult = {
  sourcePath: string
  results: Array<{
    name: string
    sourceFile: string
    servers: McpServerItem[]
  }>
}

export type McpImportSelection = {
  sourceFile: string
  serverNames: string[]
}

export type McpImportResult = {
  imported: string[]
  errors: string[]
}

export const mcpApi = {
  list: (cwd?: string) => {
    const query = cwd ? `?cwd=${encodeURIComponent(cwd)}` : ''
    return api.get<{ servers: McpServerRecord[] }>(`/api/mcp${query}`)
  },

  projectPaths: () => {
    return api.get<{ projectPaths: string[] }>('/api/mcp/project-paths')
  },

  status: (name: string, cwd?: string) => {
    const query = cwd ? `?cwd=${encodeURIComponent(cwd)}` : ''
    return api.get<{ server: McpServerRecord }>(`/api/mcp/${encodeURIComponent(name)}/status${query}`)
  },

  create: (name: string, payload: McpUpsertPayload, cwd?: string) => {
    return api.post<{ server: McpServerRecord }>('/api/mcp', {
      name,
      ...payload,
      ...(cwd ? { cwd } : {}),
    })
  },

  update: (name: string, payload: McpUpsertPayload, cwd?: string, previousCwd?: string) => {
    return api.put<{ server: McpServerRecord }>(`/api/mcp/${encodeURIComponent(name)}`, {
      ...payload,
      ...(cwd ? { cwd } : {}),
      ...(previousCwd ? { previousCwd } : {}),
    })
  },

  remove: (name: string, scope: string, cwd?: string) => {
    const query = new URLSearchParams({ scope })
    if (cwd) query.set('cwd', cwd)
    return api.delete<{ ok: true }>(`/api/mcp/${encodeURIComponent(name)}?${query.toString()}`)
  },

  toggle: (name: string, cwd?: string, sessionId?: string) => {
    return api.post<{ server: McpServerRecord }>(
      `/api/mcp/${encodeURIComponent(name)}/toggle`,
      { ...(cwd ? { cwd } : {}), ...(sessionId ? { sessionId } : {}) },
    )
  },

  reconnect: (name: string, cwd?: string) => {
    return api.post<{ server: McpServerRecord }>(`/api/mcp/${encodeURIComponent(name)}/reconnect`, cwd ? { cwd } : {})
  },

  // ── Data directory & import ──
  defaultPaths: () => {
    return api.get<{ paths: McpDefaultPath[] }>('/api/mcp/default-paths')
  },

  getDataDirectory: () => {
    return api.get<{ rootPath: string }>('/api/mcp/data-directory')
  },

  setDataDirectory: (rootPath: string) => {
    return api.put<{ ok: boolean; rootPath: string }>('/api/mcp/data-directory', { rootPath })
  },

  scanSource: (path: string) => {
    return api.post<McpScanResult>('/api/mcp/scan-source', { path })
  },

  importConfigs: (sourcePath: string, selections: McpImportSelection[]) => {
    return api.post<McpImportResult>('/api/mcp/import', { sourcePath, selections })
  },

  getJson: () => {
    return api.get<{ content: string; path: string }>('/api/mcp/json')
  },

  putJson: (content: string) => {
    return api.put<{ ok: boolean }>('/api/mcp/json', { content })
  },
}
