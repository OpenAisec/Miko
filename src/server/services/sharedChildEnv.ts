/**
 * Shared child env builder — 唯一路径，供 conversationService 和 cronScheduler 共用。
 *
 * kimo Phase 0：消除 conversationService.buildChildEnv 和 cronScheduler.buildTaskChildEnv
 * 之间的重复逻辑。两处使用同一套 env 构建规则。
 */

import { getProcessEnvWithTerminalShellEnvironment } from '../../utils/terminalShellEnvironment.js'
import { attributionHeaderEnvForModel } from './attributionHeaderPolicy.js'
import { ProviderService } from './providerService.js'
import { isProviderManagedEnvVar } from '../../utils/managedEnvConstants.js'

export type BuildChildEnvOptions = {
  workDir: string
  providerId?: string | null
  model?: string | null
}

/**
 * 构建 CLI 子进程的基础环境变量。
 *
 * 规则：
 * 1. 从系统 shell 环境继承，剥离 CLAUDE_CODE_OAUTH_TOKEN
 * 2. 从 ProviderService 读取正式 provider env（providers.json 真相源）
 * 3. 注入 kimo 标准 env：KIMO_SKIP_DOTENV、CALLER_DIR、PROVIDER_MANAGED_BY_HOST
 * 4. 附加 attribution header
 *
 * 注意：不负责剥离继承的 provider env var，调用方如有需要自行处理。
 */
export async function buildChildEnv(
  providerService: ProviderService,
  options: BuildChildEnvOptions,
): Promise<Record<string, string | undefined>> {
  const cleanEnv = await getProcessEnvWithTerminalShellEnvironment()
  delete cleanEnv.CLAUDE_CODE_OAUTH_TOKEN

  // 从 ProviderService 读取正式 provider env（providers.json 事实源）。
  // providerId 未指定（非 string）语义 = "用当前激活的 provider"，故回落到 activeId 解析，
  // 而非留空指望继承的 process.env——打包态干净环境下继承 env 无 token，留空即丢失。
  // 三条调用方（会话 / cron / worker）借此走同一条 provider 解析路径。
  const explicitProviderEnv =
    typeof options.providerId === 'string'
      ? await providerService.getProviderRuntimeEnv(options.providerId)
      : await providerService.getActiveProviderRuntimeEnv()

  if (explicitProviderEnv && options.model?.trim()) {
    explicitProviderEnv.ANTHROPIC_MODEL = options.model.trim()
  }

  const attributionHeaderEnv = attributionHeaderEnvForModel(
    options.model?.trim() ||
      explicitProviderEnv?.ANTHROPIC_MODEL ||
      cleanEnv.ANTHROPIC_MODEL,
  )

  return {
    ...cleanEnv,
    KIMO_SKIP_DOTENV: '1',
    CALLER_DIR: options.workDir,
    PWD: options.workDir,
    ...(explicitProviderEnv
      ? { CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST: '1' }
      : {}),
    ...(explicitProviderEnv ?? {}),
    ...attributionHeaderEnv,
  }
}

/**
 * 判断是否应该剥离从 shell 继承的 provider env var。
 *
 * 当存在 providers.json 或指定了 providerId 时，
 * 子进程应从 providers.json 读取 provider，而非从父进程继承。
 */
export function shouldStripInheritedProviderEnv(
  configDir: string,
  providerId?: string | null,
): boolean {
  if (providerId !== undefined) {
    return true
  }

  const { existsSync } = require('node:fs')
  const path = require('node:path')
  const providersPath = path.join(configDir, 'kimo', 'providers.json')
  const oldProvidersPath = path.join(configDir, 'providers.json')

  if (existsSync(providersPath) || existsSync(oldProvidersPath)) {
    return true
  }

  return false
}
