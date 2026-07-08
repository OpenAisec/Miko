import { api } from './client'

export type AgentSource =
  | 'built-in'
  | 'plugin'
  | 'userSettings'
  | 'projectSettings'
  | 'localSettings'
  | 'flagSettings'
  | 'policySettings'

export type AgentDefinition = {
  agentType: string
  description?: string
  model?: string
  modelDisplay?: string
  tools?: string[]
  systemPrompt?: string
  color?: string
  source: AgentSource
  baseDir?: string
  overriddenBy?: AgentSource
  isActive: boolean
  skills?: string[]
  mcpServers?: string[]
  /** 内置受保护 agent（A 档保护）—— true 时隐藏删除入口。 */
  protected?: boolean
}

export type AgentListResponse = {
  activeAgents: AgentDefinition[]
  allAgents: AgentDefinition[]
}

export type AgentCreatePayload = {
  name: string
  description?: string
  model?: string
  tools?: string[]
  systemPrompt?: string
  color?: string
  skills?: string[]
  mcpServers?: string[]
}

export const agentsApi = {
  list: (cwd?: string) => {
    const query = cwd ? `?cwd=${encodeURIComponent(cwd)}` : ''
    return api.get<AgentListResponse>(`/api/agents${query}`)
  },

  create: (data: AgentCreatePayload) => {
    return api.post<{ ok: boolean }>('/api/agents', data)
  },

  update: (name: string, data: Partial<AgentCreatePayload>) => {
    return api.put<{ agent: AgentDefinition }>(`/api/agents/${encodeURIComponent(name)}`, data)
  },

  delete: (name: string) => {
    return api.delete<{ ok: boolean }>(`/api/agents/${encodeURIComponent(name)}`)
  },
}
