/**
 * 子 agent transcript 写入工具
 *
 * 在 AgentTool.call() 完成后调用，将子 agent 的消息写入独立的 JSONL 文件。
 * 不修改现有的主会话写入逻辑。
 */

import * as path from 'path'
import * as fs from 'fs'
import { getDataDir } from '../utils/kimoPaths.js'

const TRANSCRIPT_DIR = 'subagents'

export function writeAgentTranscript(
  agentId: string,
  messages: unknown[],
  projectDir?: string,
): void {
  const dataDir = getDataDir()
  const project = projectDir
    ? path.join(dataDir, 'projects', sanitizeDirName(projectDir))
    : path.join(dataDir, 'projects', '_default')

  const transcriptDir = path.join(project, TRANSCRIPT_DIR)
  const transcriptPath = path.join(transcriptDir, `${agentId}.jsonl`)

  try {
    fs.mkdirSync(transcriptDir, { recursive: true })
  } catch {
    return // 目录创建失败则静默跳过
  }

  try {
    const lines = messages
      .filter(m => m != null)
      .map(m => JSON.stringify(m))
      .join('\n')
    fs.appendFileSync(transcriptPath, lines + '\n', 'utf-8')
  } catch {
    // 写入失败不影响主流程
  }
}

function sanitizeDirName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_\-]/g, '_')
}
