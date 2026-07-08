import { create } from 'zustand'
import { catalogApi, type ToolDef } from '../api/catalog'

type CatalogStore = {
  tools: ToolDef[]
  isLoading: boolean
  isProbing: boolean
  error: string | null

  fetchTools: () => Promise<void>
  probe: () => Promise<void>
  removeTool: (id: string) => Promise<void>
  setToolPath: (id: string, path: string) => Promise<void>
  clearToolPath: (id: string) => Promise<void>
}

export const useCatalogStore = create<CatalogStore>((set, get) => ({
  tools: [],
  isLoading: false,
  isProbing: false,
  error: null,

  fetchTools: async () => {
    set({ isLoading: true, error: null })
    try {
      const { tools } = await catalogApi.listAll()
      set({ tools, isLoading: false })
    } catch (error) {
      set({ isLoading: false, error: error instanceof Error ? error.message : 'Failed to load tools' })
    }
  },

  probe: async () => {
    set({ isProbing: true, error: null })
    try {
      await catalogApi.probe()
      // 探测后重拉一遍带最新状态的全量
      const { tools } = await catalogApi.listAll()
      set({ tools, isProbing: false })
    } catch (error) {
      set({ isProbing: false, error: error instanceof Error ? error.message : 'Probe failed' })
    }
  },

  removeTool: async (id) => {
    await catalogApi.remove(id)
    set({ tools: get().tools.filter((t) => t.id !== id) })
  },

  setToolPath: async (id, path) => {
    const { tool } = await catalogApi.setPath(id, path)
    if (tool) set({ tools: get().tools.map((t) => (t.id === id ? tool : t)) })
  },

  clearToolPath: async (id) => {
    await catalogApi.clearPath(id)
    // 重拉全量拿最新状态（清除后该工具转未配置）
    const { tools } = await catalogApi.listAll()
    set({ tools })
  },
}))
