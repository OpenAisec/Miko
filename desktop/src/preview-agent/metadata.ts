import { buildSelector, buildNthPath } from './selector'

export type ElementMetadata = {
  selector: string; nthPath: string; tag: string; id?: string; classes: string[]
  text?: string; boundingBox: { x: number; y: number; w: number; h: number }
  computedStyles: Record<string, string>; outerHtmlSnippet?: string
}

const STYLE_KEYS = ['color', 'backgroundColor', 'opacity', 'fontFamily', 'fontSize', 'fontWeight', 'textAlign', 'padding', 'margin'] as const

export function buildElementMetadata(el: Element): ElementMetadata {
  const cs = window.getComputedStyle(el)
  const styles: Record<string, string> = {}
  for (const k of STYLE_KEYS) styles[k] = (cs as unknown as Record<string, string>)[k] ?? ''
  const r = el.getBoundingClientRect()
  const sel = buildSelector(el)
  return {
    selector: sel, nthPath: buildNthPath(el), tag: el.tagName.toLowerCase(),
    id: el.id || undefined, classes: Array.from(el.classList),
    text: (el.textContent ?? '').trim().slice(0, 200) || undefined,
    boundingBox: { x: r.x, y: r.y, w: r.width, h: r.height },
    computedStyles: styles,
    outerHtmlSnippet: sel.includes(':nth') ? el.outerHTML.slice(0, 300) : undefined,
  }
}
