export type AgentMessage =
  | { type: 'ready' }
  | { type: 'navigated'; url: string; title: string }
  | { type: 'error'; message: string }
  | { type: 'selection'; payload: unknown }   // M5 填充结构
  | { type: 'screenshot'; dataUrl: string; kind: 'full' | 'viewport' | 'element' } // M4
  | { type: 'picker-exited' }

export type HostMessage =
  | { type: 'enter-picker' }
  | { type: 'exit-picker' }
  | { type: 'capture'; kind: 'full' | 'viewport' | 'element' }

const HOST_TYPES = new Set(['enter-picker', 'exit-picker', 'capture'])

export function serializeAgentMessage(msg: AgentMessage): string {
  return JSON.stringify({ v: 1, ...msg })
}

export function parseHostMessage(raw: string): HostMessage | null {
  try {
    const obj = JSON.parse(raw) as unknown
    if (
      typeof obj !== 'object' ||
      obj === null ||
      (obj as Record<string, unknown>)['v'] !== 1 ||
      typeof (obj as Record<string, unknown>)['type'] !== 'string' ||
      !HOST_TYPES.has((obj as Record<string, unknown>)['type'] as string)
    ) {
      return null
    }
    const { v: _v, ...rest } = obj as Record<string, unknown>
    return rest as unknown as HostMessage
  } catch {
    return null
  }
}
