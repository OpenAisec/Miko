export type WebviewBounds = { x: number; y: number; width: number; height: number }

export function computeWebviewBounds(rect: Pick<DOMRect, 'left' | 'top' | 'width' | 'height'>): WebviewBounds {
  return {
    x: Math.round(rect.left),
    y: Math.round(rect.top),
    width: Math.max(0, Math.round(rect.width)),
    height: Math.max(0, Math.round(rect.height)),
  }
}
