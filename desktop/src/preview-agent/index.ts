import { createBridge } from './bridge'
import { captureToDataUrl, captureAnnotatedRegion } from './screenshot'
import { createPicker } from './picker'
import { buildElementMetadata } from './metadata'
import { createEditBubble } from './editBubble'

;(() => {
  ;(window as unknown as { __PREVIEW_AGENT__?: boolean }).__PREVIEW_AGENT__ = true

  const postToHost = (raw: string) => {
    const internals = (window as unknown as { __TAURI_INTERNALS__?: { invoke?: (c: string, a: unknown) => void } }).__TAURI_INTERNALS__
    if (internals?.invoke) internals.invoke('preview_message', { raw })
    // 回退（M1 证伪 IPC 时启用）：new WebSocket('ws://127.0.0.1:'+PORT+'/preview-agent') ...
  }

  const bridge = createBridge({ postToHost, location: window.location, title: document.title })
  ;(window as unknown as { __PREVIEW_BRIDGE__?: unknown }).__PREVIEW_BRIDGE__ = bridge
  ;(window as unknown as Record<string, unknown>).__PREVIEW_AGENT_CAPTURE__ = captureToDataUrl

  bridge.on('capture', async (m) => {
    try { bridge.send({ type: 'screenshot', dataUrl: await captureToDataUrl(m.kind), kind: m.kind }) }
    catch (e) { bridge.reportError(String(e)) }
  })

  let pickerOn = false
  let activeBubble: { destroy: () => void } | null = null
  const picker = createPicker({ onSelect: () => {} })

  const teardown = () => {
    activeBubble?.destroy()
    activeBubble = null
    pickerOn = false
    picker.exit()
    bridge.send({ type: 'picker-exited' })
  }

  const emitSelection = async (el: Element, change?: unknown) => {
    try {
      const dataUrl = await captureAnnotatedRegion(el)
      bridge.send({
        type: 'selection',
        payload: {
          pageUrl: window.location.href,
          sourceHint: document.title || undefined,
          element: buildElementMetadata(el),
          change,
          screenshot: { dataUrl, kind: 'region' },
        },
      })
    } catch (e) { bridge.reportError(String(e)) }
  }

  bridge.on('enter-picker', () => { pickerOn = true; picker.enter() })
  bridge.on('exit-picker', () => { teardown() })

  document.addEventListener('mousemove', (e) => {
    if (!pickerOn) return
    const t = e.target
    if (t instanceof Element) picker.hover(t)
  }, true)

  document.addEventListener('click', (e) => {
    if (!pickerOn || activeBubble) return
    e.preventDefault(); e.stopPropagation()
    picker.select()
    const el = picker.current()
    pickerOn = false   // stop hovering; keep highlight on the selected element while the bubble is open
    if (!(el instanceof HTMLElement)) { teardown(); return }
    activeBubble = createEditBubble(el, {
      onConfirm: (change) => { teardown(); void emitSelection(el, change) },
      onCancel: () => { teardown() },
    })
  }, true)

  const onReady = () => { bridge.reportReady(); bridge.reportNavigated() }
  if (document.readyState !== 'loading') onReady()
  else document.addEventListener('DOMContentLoaded', onReady)
  window.addEventListener('popstate', () => bridge.reportNavigated())
})()
