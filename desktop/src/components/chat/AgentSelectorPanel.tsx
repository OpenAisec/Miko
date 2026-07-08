import { useEffect, useState } from 'react'
import { agentsApi, type AgentDefinition } from '../../api/agents'

type AgentSelectorPanelProps = {
  cwd?: string
  onSelect: (agentName: string) => void
  onClose: () => void
}

export function AgentSelectorPanel({ cwd, onSelect, onClose }: AgentSelectorPanelProps) {
  const [agents, setAgents] = useState<AgentDefinition[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    agentsApi.list(cwd)
      .then((response) => {
        if (cancelled) return
        setAgents(response.activeAgents)
      })
      .catch((err) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : String(err))
      })
    return () => { cancelled = true }
  }, [cwd])

  return (
    <div className="absolute bottom-full left-0 right-0 z-50 mb-3 overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-container-lowest)] shadow-[var(--shadow-dropdown)]">
      <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] px-5 py-4">
        <div>
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)]">Agent</h3>
          {cwd && (
            <p className="mt-1 text-sm text-[var(--color-text-tertiary)]">project: {cwd}</p>
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="flex h-9 w-9 items-center justify-center rounded-full text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]"
        >
          <span className="material-symbols-outlined text-[18px]">close</span>
        </button>
      </div>
      <div className="max-h-[min(620px,72vh)] overflow-y-auto px-5 py-4">
        {error ? (
          <div className="px-4 py-3 text-sm text-red-500">{error}</div>
        ) : agents === null ? (
          <div className="flex items-center justify-center py-8 text-sm text-[var(--color-text-tertiary)]">
            <div className="mr-3 h-5 w-5 animate-spin rounded-full border-2 border-[var(--color-brand)] border-t-transparent" />
            Loading agents...
          </div>
        ) : agents.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] px-5 py-10 text-center">
            <div className="text-sm font-semibold text-[var(--color-text-primary)]">No agents configured</div>
            <div className="mt-2 text-xs leading-6 text-[var(--color-text-tertiary)]">Create agents in Settings &gt; Agents</div>
          </div>
        ) : (
          <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
            {agents.map((agent) => (
              <button
                type="button"
                key={agent.agentType}
                onClick={() => onSelect(agent.agentType)}
                className="block w-full border-t border-[var(--color-border)] px-4 py-4 text-left first:border-t-0 hover:bg-[var(--color-surface-hover)]"
              >
                <div className="flex items-center gap-3">
                  <div className="text-sm font-semibold text-[var(--color-text-primary)]">
                    /{agent.agentType}
                  </div>
                  <span className="rounded-full bg-[var(--color-surface-hover)] px-2 py-1 text-[11px] text-[var(--color-text-secondary)]">
                    {agent.source}
                  </span>
                </div>
                {agent.description && (
                  <div className="mt-1 text-xs text-[var(--color-text-tertiary)] line-clamp-2">
                    {agent.description}
                  </div>
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
