import type { ChatSendBehavior } from '../../types/settings'
import type { KeyboardEvent as ReactKeyboardEvent } from 'react'

export function shouldSubmitOnEnter(
  event: Pick<KeyboardEvent | ReactKeyboardEvent, 'key' | 'shiftKey' | 'ctrlKey' | 'metaKey'>,
  behavior: ChatSendBehavior,
): boolean {
  if (event.key !== 'Enter' || event.shiftKey) return false
  if (behavior === 'modifierEnter') return event.ctrlKey || event.metaKey
  return !event.ctrlKey && !event.metaKey
}
