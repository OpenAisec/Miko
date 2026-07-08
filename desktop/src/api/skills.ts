import { api } from './client'
import type { SkillMeta, SkillDetail } from '../types/skill'
import type { McpScanResult } from './mcp'

export type SkillsImportResult = {
  imported: string[]
  errors: string[]
}

export const skillsApi = {
  list: (cwd?: string, skillsDir?: string) => {
    const params = new URLSearchParams()
    if (cwd) params.set('cwd', cwd)
    if (skillsDir) params.set('skillsDir', skillsDir)
    const qs = params.toString()
    return api.get<{ skills: SkillMeta[] }>(`/api/skills${qs ? `?${qs}` : ''}`, { timeout: 120_000 })
  },

  delete: (name: string, source: string) =>
    api.delete<{ ok: boolean }>(`/api/skills/${encodeURIComponent(name)}?source=${encodeURIComponent(source)}`),

  updateCategory: (name: string, category: string) =>
    api.patch<{ ok: boolean; name: string; category: string }>(
      `/api/skills/${encodeURIComponent(name)}/category`,
      { category },
    ),

  detail: (source: string, name: string, cwd?: string, skillsDir?: string) => {
    const query = new URLSearchParams({ source, name })
    if (cwd) query.set('cwd', cwd)
    if (skillsDir) query.set('skillsDir', skillsDir)
    return api.get<{ detail: SkillDetail }>(`/api/skills/detail?${query.toString()}`, { timeout: 120_000 })
  },

  scanSource: (path: string) => {
    return api.post<McpScanResult>('/api/skills/scan-source', { path })
  },

  importSkills: (sourcePath: string, targetPath: string, files: string[]) => {
    return api.post<SkillsImportResult>('/api/skills/import', { sourcePath, targetPath, files })
  },
}
