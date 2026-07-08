import type { ElementMetadata } from '../preview-agent/metadata'
import type { EditDiff } from '../preview-agent/popover'

export type SelectionPayload = {
  pageUrl: string; sourceHint?: string
  element: ElementMetadata
  change?: EditDiff & { description?: string }
}

export type SelectionDirectMessage = {
  modelText: string
  displayName: string
  note?: string
}

/**
 * 选中元素的「引用」由随附的圈选标注截图承载（截图里已把元素圈出来）。
 * 这里只产出用户的修改意见 + 具体改动（人话），**不再**把 selector / DOM 定位 /
 * computedStyles / 页面 URL 等写进输入框 —— 那些 DOM 噪音交互体验差，且图片已是引用。
 * 无描述、无改动时返回空串（让图片单独作为引用进输入框）。
 */
export function buildSelectionComposerText(p: SelectionPayload): string {
  const c = p.change
  const lines: string[] = []
  if (c?.description) lines.push(c.description)
  if (c?.text) lines.push(`- 文本：「${c.text.from}」→「${c.text.to}」`)
  if (c?.color) lines.push(`- 文字颜色：${c.color.from} → ${c.color.to}`)
  if (c?.background) lines.push(`- 背景：${c.background.from} → ${c.background.to}`)
  if (c?.opacity) lines.push(`- 不透明度：${c.opacity.from} → ${c.opacity.to}`)
  if (c?.fontFamily) lines.push(`- 字体：${c.fontFamily.from} → ${c.fontFamily.to}`)
  return lines.join('\n')
}

function formatElementLabel(element: ElementMetadata): string {
  const tag = element.tag || 'element'
  return `<${tag}>`
}

export function buildSelectionDirectMessage(p: SelectionPayload): SelectionDirectMessage {
  const displayName = formatElementLabel(p.element)
  const note = buildSelectionComposerText(p)
  const lines = [
    '请根据截图中编号 1 的蓝色标注修改本地前端。',
    `目标元素：${displayName}`,
    `Selector：${p.element.selector}`,
  ]

  if (p.element.nthPath) lines.push(`DOM 路径：${p.element.nthPath}`)
  if (p.sourceHint) lines.push(`页面标题：${p.sourceHint}`)
  if (p.pageUrl) lines.push(`页面 URL：${p.pageUrl}`)
  if (p.element.text) lines.push(`当前文本：${p.element.text}`)
  if (note) {
    lines.push('用户注释：')
    lines.push(note)
  } else {
    lines.push('用户没有提供额外注释；请只依据截图中的选中元素理解修改目标。')
  }
  lines.push('请优先依据截图里的编号标注定位元素，selector 只作为辅助线索。')

  return {
    modelText: lines.join('\n'),
    displayName,
    note: note || undefined,
  }
}
