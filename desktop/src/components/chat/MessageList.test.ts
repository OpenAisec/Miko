import { describe, expect, it } from 'vitest'
import { buildRenderModel } from './MessageList'
import type { UIMessage } from '../../types/chat'

function askToolUse(id: string): UIMessage {
  return {
    id: `message-${id}`,
    type: 'tool_use',
    toolName: 'AskUserQuestion',
    toolUseId: id,
    input: { question: `Question ${id}` },
    timestamp: 1,
    isPending: false,
  }
}

function renderedToolUseIds(messages: UIMessage[], activeToolUseIds?: ReadonlySet<string>) {
  return buildRenderModel(messages, activeToolUseIds).renderItems
    .flatMap((item) => item.kind === 'message' && item.message.type === 'tool_use'
      ? [item.message.toolUseId]
      : [])
}

describe('buildRenderModel AskUserQuestion pending filtering', () => {
  it('renders every active unresolved AskUserQuestion request', () => {
    const messages = [askToolUse('ask-1'), askToolUse('ask-2'), askToolUse('ask-3')]

    expect(renderedToolUseIds(messages, new Set(['ask-1', 'ask-2']))).toEqual(['ask-1', 'ask-2'])
  })

  it('keeps the previous last unresolved fallback when no active request is known', () => {
    const messages = [askToolUse('ask-1'), askToolUse('ask-2')]

    expect(renderedToolUseIds(messages)).toEqual(['ask-2'])
  })
})
