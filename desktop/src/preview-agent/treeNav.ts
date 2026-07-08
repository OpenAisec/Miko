export function climb(el: Element): Element | null {
  const p = el.parentElement
  if (!p || p.tagName.toLowerCase() === 'body' || p.tagName.toLowerCase() === 'html') return null
  return p
}
export function descend(el: Element): Element | null {
  return el.firstElementChild
}
