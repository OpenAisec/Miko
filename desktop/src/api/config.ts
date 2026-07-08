import { api } from './client'

export type ConfigPaths = {
  dataDir: string
  skillsDir: string
  agentsDir: string
  pluginsDir: string
  workspaceDir: string
}

export const configApi = {
  getPaths: () => api.get<ConfigPaths>('/api/status/paths'),
}
