function cssTag(el: Element): string {
  const tag = el.tagName.toLowerCase()
  const parent = el.parentElement
  if (!parent) return tag
  const same = Array.from(parent.children).filter((c) => c.tagName === el.tagName)
  if (same.length <= 1) return tag
  return `${tag}:nth-of-type(${same.indexOf(el) + 1})`
}

export function buildSelector(el: Element): string {
  if (el.id) return `#${el.id}`
  const parts: string[] = []
  let node: Element | null = el
  while (node && node.nodeType === 1 && node.tagName.toLowerCase() !== 'html' && node.tagName.toLowerCase() !== 'body') {
    if (node.id) { parts.unshift(`#${node.id}`); break }
    parts.unshift(cssTag(node))
    node = node.parentElement
  }
  return parts.join(' > ')
}

export function buildNthPath(el: Element): string {
  const parts: string[] = []
  let node: Element | null = el
  while (node && node.parentElement) {
    const idx = Array.from(node.parentElement.children).indexOf(node) + 1
    parts.unshift(`${node.tagName.toLowerCase()}:nth-child(${idx})`)
    node = node.parentElement
  }
  return parts.join(' > ')
}
