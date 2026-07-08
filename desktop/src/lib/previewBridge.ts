import { invoke } from '@tauri-apps/api/core'
import { isTauriRuntime } from './desktopRuntime'
import type { WebviewBounds } from '../components/browser/computeWebviewBounds'

async function call(cmd: string, args?: Record<string, unknown>): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke(cmd, args)
}

export const previewBridge = {
  open: (url: string, bounds: WebviewBounds) => call('preview_open', { url, bounds }),
  navigate: (url: string) => call('preview_navigate', { url }),
  setBounds: (bounds: WebviewBounds) => call('preview_set_bounds', { bounds }),
  setVisible: (visible: boolean) => call('preview_set_visible', { visible }),
  close: () => call('preview_close'),
  eval: (js: string) => call('preview_eval', { js }),
}
