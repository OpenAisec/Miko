import { useEffect, useState, type PointerEventHandler, type ReactNode } from 'react'
import { copyTextToClipboard } from '../chat/clipboard'

type Props = {
  text: string
  label?: string
  copiedLabel?: string
  displayLabel?: ReactNode
  displayCopiedLabel?: ReactNode
  className?: string
  onPointerUp?: PointerEventHandler<HTMLButtonElement>
}

export function CopyButton({
  text,
  label = 'Copy',
  copiedLabel = 'Copied',
  displayLabel,
  displayCopiedLabel,
  className = '',
  onPointerUp,
}: Props) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return
    const timer = window.setTimeout(() => setCopied(false), 1500)
    return () => window.clearTimeout(timer)
  }, [copied])

  const handleCopy = async () => {
    try {
      const ok = await copyTextToClipboard(text)
      if (!ok) {
        setCopied(false)
        return
      }
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  const currentLabel = copied ? copiedLabel : label
  const buttonText = copied
    ? (displayCopiedLabel ?? copiedLabel)
    : (displayLabel ?? label)

  return (
    <button
      type="button"
      onClick={handleCopy}
      onPointerUp={onPointerUp}
      className={className}
      aria-label={currentLabel}
      title={currentLabel}
    >
      {buttonText}
    </button>
  )
}
