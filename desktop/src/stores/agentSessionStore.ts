import { create } from 'zustand'

type AgentSessionStore = {
  active: boolean
  agentType: string | null
  setActive: (active: boolean, agentType?: string) => void
  clear: () => void
}

export const useAgentSessionStore = create<AgentSessionStore>((set) => ({
  active: false,
  agentType: null,
  setActive: (active, agentType) => set({ active, agentType: agentType ?? null }),
  clear: () => set({ active: false, agentType: null }),
}))
