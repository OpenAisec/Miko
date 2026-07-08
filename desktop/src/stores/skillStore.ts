import { create } from 'zustand'
import { skillsApi } from '../api/skills'
import type { SkillMeta, SkillDetail } from '../types/skill'

export type SkillDetailReturnTab = 'skills' | 'plugins'

type SkillStore = {
  skills: SkillMeta[]
  selectedSkill: SkillDetail | null
  selectedSkillReturnTab: SkillDetailReturnTab
  isLoading: boolean
  isDetailLoading: boolean
  error: string | null

  fetchSkills: (cwd?: string, skillsDir?: string) => Promise<void>
  fetchSkillDetail: (
    source: string,
    name: string,
    cwd?: string,
    returnTab?: SkillDetailReturnTab,
    skillsDir?: string,
  ) => Promise<void>
  updateCategory: (name: string, category: string) => Promise<void>
  clearSelection: () => void
}

export const useSkillStore = create<SkillStore>((set) => ({
  skills: [],
  selectedSkill: null,
  selectedSkillReturnTab: 'skills',
  isLoading: false,
  isDetailLoading: false,
  error: null,

  fetchSkills: async (cwd, skillsDir) => {
    set({ isLoading: true, error: null })
    try {
      const { skills } = await skillsApi.list(cwd, skillsDir)
      set({ skills, isLoading: false })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : String(err),
        isLoading: false,
      })
    }
  },

  fetchSkillDetail: async (source, name, cwd, returnTab = 'skills', skillsDir) => {
    set({ isDetailLoading: true, error: null })
    try {
      const { detail } = await skillsApi.detail(source, name, cwd, skillsDir)
      set({
        selectedSkill: detail,
        selectedSkillReturnTab: returnTab,
        isDetailLoading: false,
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : String(err),
        isDetailLoading: false,
      })
    }
  },

  clearSelection: () => set({ selectedSkill: null, selectedSkillReturnTab: 'skills' }),

  updateCategory: async (name, category) => {
    await skillsApi.updateCategory(name, category)
    // 乐观更新本地列表中对应 skill 的 category
    set((state) => ({
      skills: state.skills.map((s) =>
        s.name === name ? { ...s, category } : s,
      ),
    }))
  },
}))
