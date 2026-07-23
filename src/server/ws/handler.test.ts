import { describe, expect, it } from 'bun:test'
import { translateCliMessage } from './handler'

describe('translateCliMessage assistant fallback', () => {
  it('does not duplicate assistant text after stream events already delivered the turn', () => {
    const sessionId = 'session-streamed'

    expect(
      translateCliMessage(
        {
          type: 'stream_event',
          event: {
            type: 'content_block_start',
            index: 0,
            content_block: { type: 'text' },
          },
        },
        sessionId,
      ),
    ).toEqual([{ type: 'content_start', blockType: 'text' }])

    expect(
      translateCliMessage(
        {
          type: 'stream_event',
          event: {
            type: 'content_block_delta',
            index: 0,
            delta: { type: 'text_delta', text: 'dependency check passed: Node.js v22.20.0' },
          },
        },
        sessionId,
      ),
    ).toEqual([{ type: 'content_delta', text: 'dependency check passed: Node.js v22.20.0' }])

    expect(
      translateCliMessage(
        {
          type: 'assistant',
          message: {
            content: [{ type: 'text', text: 'dependency check passed: Node.js v22.20.0' }],
            stop_reason: null,
            usage: { output_tokens: 0 },
          },
        },
        sessionId,
      ),
    ).toEqual([])
  })

  it('still falls back to assistant text when no stream events were seen', () => {
    const sessionId = 'session-fallback'

    expect(
      translateCliMessage(
        {
          type: 'assistant',
          message: {
            content: [{ type: 'text', text: 'anything else to continue?' }],
            stop_reason: null,
            usage: { output_tokens: 0 },
          },
        },
        sessionId,
      ),
    ).toEqual([
      { type: 'content_start', blockType: 'text' },
      { type: 'content_delta', text: 'anything else to continue?' },
    ])
  })
})
