import { getAPIProvider } from './model/providers.js'

export type ProviderUsageTrust = 'high' | 'low'

export type ContextUsageLike = {
  input_tokens: number
  output_tokens?: number
  cache_creation_input_tokens: number
  cache_read_input_tokens: number
}

export type ContextBudgetSource = 'estimate' | 'provider_usage'

export type ContextBudget = {
  usedTokens: number
  source: ContextBudgetSource
  providerUsageTokens: number | null
  estimatedTokens: number
  ignoredUsageReason?: 'low_trust_media_usage'
}

export function getProviderUsageTrust(args: {
  isFirstPartyAnthropic: boolean
}): ProviderUsageTrust {
  return getAPIProvider() === 'firstParty' && args.isFirstPartyAnthropic
    ? 'high'
    : 'low'
}

function isMediaAttachment(attachment: unknown): boolean {
  if (typeof attachment !== 'object' || attachment === null) return false

  const candidate = attachment as {
    type?: unknown
    content?: { type?: unknown } | null
  }

  if (candidate.type !== 'file') return false

  return (
    candidate.content?.type === 'image' || candidate.content?.type === 'pdf'
  )
}

export function hasMediaInput(
  messages: readonly {
    type: string
    message?: { content?: unknown }
    attachment?: unknown
  }[],
): boolean {
  return messages.some(message => {
    if (message.type === 'attachment') {
      return isMediaAttachment(message.attachment)
    }
    if (message.type !== 'user' && message.type !== 'assistant') return false
    if (!Array.isArray(message.message?.content)) return false

    return message.message.content.some(
      block =>
        typeof block === 'object' &&
        block !== null &&
        'type' in block &&
        (block.type === 'image' || block.type === 'document'),
    )
  })
}

type ShouldIgnoreLowTrustUsageArgs = {
  usageTrust: ProviderUsageTrust
  hasMediaInput: boolean
  usageTokens: number
  estimatedTokens: number
  contextWindow: number
}

type CalculateContextBudgetArgs = {
  estimatedTokens: number
  contextWindow: number
  currentUsage: ContextUsageLike | null
  usageTrust: ProviderUsageTrust
  hasMediaInput: boolean
}

export function getUsageTokenTotal(
  usage: ContextUsageLike,
  options?: { includeOutput?: boolean },
): number {
  const includeOutput = options?.includeOutput ?? true

  return (
    usage.input_tokens +
    usage.cache_creation_input_tokens +
    usage.cache_read_input_tokens +
    (includeOutput ? usage.output_tokens ?? 0 : 0)
  )
}

export function shouldIgnoreLowTrustUsage(
  args: ShouldIgnoreLowTrustUsageArgs,
): boolean {
  if (args.usageTrust === 'high') return false
  if (!args.hasMediaInput) return false
  if (args.estimatedTokens <= 0) return false
  if (args.usageTokens < args.contextWindow) return false
  if (args.estimatedTokens >= args.contextWindow) return false

  const suspiciousFloor = Math.max(
    args.estimatedTokens * 4,
    args.estimatedTokens + 50_000,
  )
  return args.usageTokens > suspiciousFloor
}

export function calculateContextBudget(
  args: CalculateContextBudgetArgs,
): ContextBudget {
  const estimatedTokens = Math.min(args.estimatedTokens, args.contextWindow)

  if (!args.currentUsage) {
    return {
      usedTokens: estimatedTokens,
      source: 'estimate',
      providerUsageTokens: null,
      estimatedTokens: args.estimatedTokens,
    }
  }

  const providerUsageTokens = getUsageTokenTotal(args.currentUsage)

  if (
    shouldIgnoreLowTrustUsage({
      usageTrust: args.usageTrust,
      hasMediaInput: args.hasMediaInput,
      usageTokens: providerUsageTokens,
      estimatedTokens: args.estimatedTokens,
      contextWindow: args.contextWindow,
    })
  ) {
    return {
      usedTokens: estimatedTokens,
      source: 'estimate',
      providerUsageTokens,
      estimatedTokens: args.estimatedTokens,
      ignoredUsageReason: 'low_trust_media_usage',
    }
  }

  const usedTokens = Math.min(
    Math.max(args.estimatedTokens, providerUsageTokens),
    args.contextWindow,
  )

  return {
    usedTokens,
    source:
      providerUsageTokens >= args.estimatedTokens ? 'provider_usage' : 'estimate',
    providerUsageTokens,
    estimatedTokens: args.estimatedTokens,
  }
}

export function calculateContextPercentagesFromTokens(
  usedTokens: number | null,
  contextWindowSize: number,
): { used: number | null; remaining: number | null } {
  if (usedTokens === null || contextWindowSize <= 0) {
    return { used: null, remaining: null }
  }

  const usedPercentage = Math.round((usedTokens / contextWindowSize) * 100)
  const used = Math.min(100, Math.max(0, usedPercentage))

  return {
    used,
    remaining: 100 - used,
  }
}
