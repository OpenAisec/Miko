import { api } from './client'

type ToolAvailability = {
  name: string
  available: boolean
  reason?: string
}

type ToolsAvailabilityResponse = {
  tools: ToolAvailability[]
}

export const toolsApi = {
  availability: (refresh?: boolean) =>
    api.get<ToolsAvailabilityResponse>(`/api/tools/availability${refresh ? '?refresh=true' : ''}`),
}
