export type EditInput = { text?: string; color?: string; background?: string; opacity?: string; fontFamily?: string }
export type EditDiff = {
  text?: { from: string; to: string }; color?: { from: string; to: string }
  background?: { from: string; to: string }; opacity?: { from: string; to: string }; fontFamily?: { from: string; to: string }
}

export function applyEdit(el: HTMLElement, input: EditInput): EditDiff {
  const cs = window.getComputedStyle(el)
  const diff: EditDiff = {}
  if (input.text != null && input.text !== el.textContent) { diff.text = { from: el.textContent ?? '', to: input.text }; el.textContent = input.text }
  if (input.color) { diff.color = { from: cs.color, to: input.color }; el.style.color = input.color }
  if (input.background) { diff.background = { from: cs.backgroundColor, to: input.background }; el.style.background = input.background }
  if (input.opacity) { diff.opacity = { from: cs.opacity, to: input.opacity }; el.style.opacity = input.opacity }
  if (input.fontFamily) { diff.fontFamily = { from: cs.fontFamily, to: input.fontFamily }; el.style.fontFamily = input.fontFamily }
  return diff
}
