import { create } from 'zustand'
import { agentsApi, type AgentDefinition, type AgentCreatePayload } from '../api/agents'

export type AgentDetailReturnTab = 'agents' | 'plugins'

type AgentStore = {
  activeAgents: AgentDefinition[]
  allAgents: AgentDefinition[]
  isLoading: boolean
  error: string | null
  selectedAgent: AgentDefinition | null
  selectedAgentReturnTab: AgentDetailReturnTab

  fetchAgents: (cwd?: string) => Promise<void>
  selectAgent: (
    agent: AgentDefinition | null,
    returnTab?: AgentDetailReturnTab,
  ) => void
  createAgent: (data: AgentCreatePayload, cwd?: string) => Promise<void>
  updateAgent: (name: string, data: Partial<AgentCreatePayload>, cwd?: string) => Promise<void>
  deleteAgent: (name: string, cwd?: string) => Promise<void>
}

export const useAgentStore = create<AgentStore>((set) => ({
  activeAgents: [],
  allAgents: [],
  isLoading: false,
  error: null,
  selectedAgent: null,
  selectedAgentReturnTab: 'agents',

  fetchAgents: async (cwd) => {
    set({ isLoading: true, error: null })
    try {
      const { activeAgents, allAgents } = await agentsApi.list(cwd)
      set({ activeAgents, allAgents, isLoading: false })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load agents'
      set({ isLoading: false, error: message })
    }
  },

  selectAgent: (agent, returnTab = 'agents') =>
    set({
      selectedAgent: agent,
      selectedAgentReturnTab: agent ? returnTab : 'agents',
    }),

  createAgent: async (data, cwd) => {
    await agentsApi.create(data)
    const { activeAgents, allAgents } = await agentsApi.list(cwd)
    set({ activeAgents, allAgents })
  },

  updateAgent: async (name, data, cwd) => {
    await agentsApi.update(name, data)
    const { activeAgents, allAgents } = await agentsApi.list(cwd)
    set({ activeAgents, allAgents })
  },

  deleteAgent: async (name, cwd) => {
    await agentsApi.delete(name)
    const { activeAgents, allAgents } = await agentsApi.list(cwd)
    set({ activeAgents, allAgents })
  },
}))
