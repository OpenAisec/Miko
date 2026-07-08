import { Button } from './Button'

type ConfirmPopoverProps = {
  message: string
  confirmLabel: string
  onConfirm: () => void
  onCancel: () => void
  cancelLabel: string
  confirmVariant?: 'primary' | 'danger'
}

export function ConfirmPopover({
  message,
  confirmLabel,
  onConfirm,
  onCancel,
  cancelLabel,
  confirmVariant = 'primary',
}: ConfirmPopoverProps) {
  return (
    <div className="absolute right-0 top-full mt-1.5 z-50 w-52 rounded-[var(--radius-md)] border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg p-3">
      <p className="mb-2.5 text-xs text-[var(--color-text-secondary)]">{message}</p>
      <div className="flex justify-end gap-1.5">
        <Button type="button" variant="ghost" size="sm" onClick={onCancel}>
          {cancelLabel}
        </Button>
        <Button type="button" variant={confirmVariant} size="sm" onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </div>
  )
}
