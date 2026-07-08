/**
 * agentOutput — 流式输出通道
 *
 * 在 CLI 初始化时设置 writeOutput 回调，指向 structuredIO.write()。
 * agent 分支执行时通过此回调逐条写消息到 stdout/SDK socket，直通桌面。
 * 不初始化时不影响任何功能（batch 模式仍正常工作）。
 */

let writeOutput: ((message: Record<string, unknown>) => void) | null = null

export function setAgentOutputWriter(writer: ((message: Record<string, unknown>) => void) | null): void {
  writeOutput = writer
}

export function getAgentOutputWriter(): ((message: Record<string, unknown>) => void) | null {
  return writeOutput
}
