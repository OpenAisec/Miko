import type { EffortLevel } from './settings'

export type RuntimeSelection = {
  providerId: string | null
  modelId: string
  effortLevel?: EffortLevel
}
