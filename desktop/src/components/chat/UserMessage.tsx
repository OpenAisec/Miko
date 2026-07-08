import { memo } from 'react'
import type { UIAttachment } from '../../types/chat'
import { AttachmentGallery } from './AttachmentGallery'
import { MessageActionBar, type MessageBranchAction } from './MessageActionBar'

type Props = {
  content: string
  attachments?: UIAttachment[]
  branchAction?: MessageBranchAction
  timestamp?: number
}

export const UserMessage = memo(function UserMessage({ content, attachments, branchAction, timestamp }: Props) {
  const hasText = content.trim().length > 0

  return (
    <div className="mb-5 flex justify-end">
      <div
        data-message-shell="user"
        className="group flex min-w-0 max-w-[82%] flex-col items-end sm:max-w-[78%] lg:max-w-[72%]"
      >
        <div className="flex max-w-full flex-col items-end gap-2">
          {attachments && attachments.length > 0 && (
            <AttachmentGallery attachments={attachments} variant="message" />
          )}

          {hasText && (
            <div
              className="min-w-0 max-w-full bg-[var(--color-surface-user-msg)] px-4 py-3 text-sm leading-relaxed text-[var(--color-text-primary)] whitespace-pre-wrap break-words"
              style={{
                borderRadius: '18px 4px 18px 18px',
                overflowWrap: 'anywhere',
                wordBreak: 'break-word',
              }}
            >
              {content}
            </div>
          )}
        </div>

        {hasText && (
          <MessageActionBar
            copyText={content}
            copyLabel="Copy prompt"
            branchAction={branchAction}
            align="end"
            timestamp={timestamp}
          />
        )}
      </div>
    </div>
  )
})
