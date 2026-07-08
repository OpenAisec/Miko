import { parseHostMessage, serializeAgentMessage, type AgentMessage, type HostMessage } from './protocol'

type Deps = { postToHost: (raw: string) => void; location: Location; title: string }

export function createBridge(deps: Deps) {
  const handlers = new Map<HostMessage['type'], Array<(m: HostMessage) => void>>()
  const send = (m: AgentMessage) => deps.postToHost(serializeAgentMessage(m))
  return {
    reportReady: () => send({ type: 'ready' }),
    reportNavigated: () => send({ type: 'navigated', url: deps.location.href, title: deps.title }),
    reportError: (message: string) => send({ type: 'error', message }),
    send,
    on<T extends HostMessage['type']>(type: T, fn: (m: Extract<HostMessage, { type: T }>) => void) {
      const arr = handlers.get(type) ?? []
      arr.push(fn as (m: HostMessage) => void)
      handlers.set(type, arr)
    },
    handleHostRaw(raw: string) {
      const msg = parseHostMessage(raw)
      if (!msg) return
      for (const fn of handlers.get(msg.type) ?? []) fn(msg)
    },
  }
}
