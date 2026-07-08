/**
 * WorkerExecutor 实现 — 一次性 CLI 子进程，对接 runWorker 的注入点。
 *
 * 照 cronScheduler 的 server 端 one-shot spawn 模式：
 *   bin/kimo --print --output-format json --dangerously-skip-permissions --session-id <s> -- <prompt>
 * 抓 stdout 的 result JSON，取 .result（最终 assistant 文本）喂给 runWorker 的解析/校验。
 *
 * 安全决策（用户拍板）：安全测试模式 = 程序最高权限，worker 子进程对应
 * --dangerously-skip-permissions（自主对目标动手的渗透 agent，平台本意）。
 *
 * 不兜底：spawn 失败 / 非零退出 / 无 result / result.is_error 一律抛错，
 * 由调度器据此记 failed。绝不返回空字符串掩盖失败。
 */

import * as path from 'node:path'
import {
  resolveClaudeCliLauncher,
  buildClaudeCliArgs,
} from '../../utils/desktopBundledCli.js'
import { buildChildEnv } from '../../server/services/sharedChildEnv.js'
import { ProviderService } from '../../server/services/providerService.js'
import type { WorkerExecutor } from './runWorker.js'

const WORKER_TIMEOUT_MS = 10 * 60_000

export type WorkerExecutorOptions = {
  /** worker 工作目录（artifacts 落点）。 */
  workDir: string
  /** 该次 worker 的专属会话 id（产出节点 sessionId 指向它，探索树可点进去）。 */
  sessionId: string
  /** 可选 provider / model 覆盖；默认走 providers.json 活跃项。 */
  providerId?: string | null
  model?: string | null
}

/** 组装一次性 worker 的 CLI argv（导出供单测断言，不真正 spawn）。 */
export function buildWorkerCliArgs(sessionId: string, model?: string | null): string[] {
  const baseArgs = [
    '--print',
    '--output-format',
    'json',
    '--dangerously-skip-permissions',
    '--session-id',
    sessionId,
    ...(model?.trim() ? ['--model', model.trim()] : []),
  ]
  const launcher = resolveClaudeCliLauncher({
    cliPath: process.env.CLAUDE_CLI_PATH,
    execPath: process.execPath,
  })
  if (launcher) {
    return buildClaudeCliArgs(launcher, baseArgs, process.env.CLAUDE_APP_ROOT)
  }
  if (process.platform === 'win32') {
    return [
      process.execPath,
      '--preload',
      path.resolve(import.meta.dir, '../../../preload.ts'),
      path.resolve(import.meta.dir, '../../entrypoints/cli.tsx'),
      ...baseArgs,
    ]
  }
  return [path.resolve(import.meta.dir, '../../../bin/kimo'), ...baseArgs]
}

/** 从 --output-format json 的 stdout 提取最终 assistant 文本；非法/错误结果抛。 */
export function extractResultText(rawStdout: string): string {
  const trimmed = rawStdout.trim()
  if (!trimmed) throw new Error('worker produced no stdout')
  // --output-format json 非 verbose：最后一行是 result 消息对象
  const lines = trimmed.split('\n').filter((l) => l.trim())
  const lastLine = lines[lines.length - 1]!
  let parsed: { type?: string; subtype?: string; is_error?: boolean; result?: string }
  try {
    parsed = JSON.parse(lastLine)
  } catch {
    throw new Error('worker stdout is not valid JSON result')
  }
  if (parsed.type !== 'result') throw new Error(`worker output last message is not a result (type=${parsed.type})`)
  if (parsed.is_error) throw new Error(`worker reported error result (subtype=${parsed.subtype})`)
  if (typeof parsed.result !== 'string' || !parsed.result.trim()) {
    throw new Error('worker result text is empty')
  }
  return parsed.result
}

/** 造一个 WorkerExecutor：每次调用 spawn 一个一次性 CLI 子进程。 */
export function createCliWorkerExecutor(options: WorkerExecutorOptions): WorkerExecutor {
  const providerService = new ProviderService()
  return async (prompt: string): Promise<string> => {
    const argv = buildWorkerCliArgs(options.sessionId, options.model)
    const childEnv = await buildChildEnv(providerService, {
      workDir: options.workDir,
      providerId: options.providerId,
      model: options.model,
    })

    const proc = Bun.spawn(argv, {
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
      cwd: options.workDir,
      env: childEnv,
    })

    // prompt 走 stdin（避免命令行长度限制 / 转义问题）
    try {
      proc.stdin.write(prompt)
      proc.stdin.end()
    } catch {
      // 进程可能已退出
    }

    const timeout = setTimeout(() => {
      try {
        proc.kill()
      } catch {
        // ignore
      }
    }, WORKER_TIMEOUT_MS)

    try {
      const stdout = await new Response(proc.stdout).text()
      const exitCode = await proc.exited
      if (exitCode !== 0) {
        throw new Error(`worker CLI exited with code ${exitCode}`)
      }
      return extractResultText(stdout)
    } finally {
      clearTimeout(timeout)
    }
  }
}
