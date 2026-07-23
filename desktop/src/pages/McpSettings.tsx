import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Button } from '../components/shared/Button'
import { DirectoryPicker } from '../components/shared/DirectoryPicker'
import { Input } from '../components/shared/Input'
import { ConfirmDialog } from '../components/shared/ConfirmDialog'
import { useTranslation } from '../i18n'
import { useUIStore } from '../stores/uiStore'
import { useMcpStore } from '../stores/mcpStore'
import { useSessionStore } from '../stores/sessionStore'
import { sessionsApi } from '../api/sessions'
import { mcpApi, type McpDefaultPath, type McpScanResult, type McpImportResult, type McpImportSelection } from '../api/mcp'
import type { McpServerRecord, McpUpsertPayload, McpWritableScope } from '../types/mcp'

type EditorMode =
  | { type: 'list' }
  | { type: 'create' }
  | { type: 'edit'; server: McpServerRecord }
  | { type: 'details'; server: McpServerRecord }
  | { type: 'json' }
  | { type: 'serverJson'; server: McpServerRecord }

type TransportKind = 'stdio' | 'http' | 'sse'

type StringRow = {
  id: string
  value: string
}

type KeyValueRow = {
  id: string
  key: string
  value: string
}

type McpDraft = {
  name: string
  scope: McpWritableScope
  projectPath: string
  transport: TransportKind
  command: string
  args: StringRow[]
  env: KeyValueRow[]
  url: string
  headers: KeyValueRow[]
  headersHelper: string
  oauthClientId: string
  oauthCallbackPort: string
}

type McpGroupKey =
  | 'plugin'
  | 'project'
  | 'managed'
  | 'enterprise'
  | 'dynamic'

const MCP_GROUP_ORDER: McpGroupKey[] = [
  'plugin',
  'project',
  'managed',
  'enterprise',
  'dynamic',
]

const STATUS_TONE: Record<McpServerRecord['status'], string> = {
  connected: 'bg-[var(--color-inspector-success-bg)] text-[var(--color-inspector-success)] border-[var(--color-border)]',
  checking: 'bg-[var(--color-surface-hover)] text-[var(--color-text-secondary)] border-[var(--color-border)]',
  'needs-auth': 'bg-[var(--color-surface-container-low)] text-[var(--color-warning)] border-[var(--color-border)]',
  failed: 'bg-[var(--color-inspector-danger-bg)] text-[var(--color-inspector-danger)] border-[var(--color-border)]',
  disabled: 'bg-[var(--color-surface-hover)] text-[var(--color-text-secondary)] border-[var(--color-border)]',
}

function createId() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID()
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function createStringRow(value = ''): StringRow {
  return { id: createId(), value }
}

function createKeyValueRow(key = '', value = ''): KeyValueRow {
  return { id: createId(), key, value }
}

function createEmptyDraft(): McpDraft {
  return {
    name: '',
    scope: 'project',
    projectPath: '',
    transport: 'stdio',
    command: '',
    args: [createStringRow('')],
    env: [createKeyValueRow()],
    url: '',
    headers: [createKeyValueRow()],
    headersHelper: '',
    oauthClientId: '',
    oauthCallbackPort: '',
  }
}

function serverHasProjectContext(server: Pick<McpServerRecord, 'scope' | 'projectPath'>) {
  return server.scope === 'project' && !!server.projectPath
}

function isStdioConfig(config: McpServerRecord['config']): config is Extract<McpServerRecord['config'], { type: 'stdio' }> {
  return config.type === 'stdio'
}

function isRemoteConfig(config: McpServerRecord['config']): config is Extract<McpServerRecord['config'], { type: 'http' | 'sse' }> {
  return config.type === 'http' || config.type === 'sse'
}

function draftFromServer(server: McpServerRecord): McpDraft {
  const base = createEmptyDraft()
  base.name = server.name

  if (isStdioConfig(server.config)) {
    return {
      ...base,
      transport: 'stdio',
      command: server.config.command,
      args: (server.config.args.length ? server.config.args : ['']).map((value) => createStringRow(value)),
      env: Object.entries(server.config.env ?? {}).map(([key, value]) => createKeyValueRow(key, value)).concat(
        Object.keys(server.config.env ?? {}).length === 0 ? [createKeyValueRow()] : [],
      ),
    }
  }

  if (isRemoteConfig(server.config)) {
    return {
      ...base,
      transport: server.config.type,
      url: server.config.url,
      headers: Object.entries(server.config.headers ?? {}).map(([key, value]) => createKeyValueRow(key, value)).concat(
        Object.keys(server.config.headers ?? {}).length === 0 ? [createKeyValueRow()] : [],
      ),
      headersHelper: server.config.headersHelper ?? '',
      oauthClientId: server.config.oauth?.clientId ?? '',
      oauthCallbackPort: server.config.oauth?.callbackPort ? String(server.config.oauth.callbackPort) : '',
    }
  }

  return base
}

function rowsToRecord(rows: KeyValueRow[]) {
  const entries: Array<[string, string]> = []
  for (const row of rows) {
    const key = row.key.trim()
    if (!key) continue
    entries.push([key, row.value])
  }
  return Object.fromEntries(entries)
}

function rowsToList(rows: StringRow[]) {
  return rows.map((row) => row.value.trim()).filter(Boolean)
}

function buildPayload(draft: McpDraft): McpUpsertPayload {
  if (draft.transport === 'stdio') {
    return {
      scope: 'project' as const,
      config: {
        type: 'stdio',
        command: draft.command.trim(),
        args: rowsToList(draft.args),
        env: rowsToRecord(draft.env),
      },
    }
  }

  const oauthCallbackPort = draft.oauthCallbackPort.trim()
  const callbackPortNumber = oauthCallbackPort ? Number(oauthCallbackPort) : undefined
  const oauthClientId = draft.oauthClientId.trim()

  return {
    scope: 'project' as const,
    config: {
      type: draft.transport,
      url: draft.url.trim(),
      headers: rowsToRecord(draft.headers),
      ...(draft.headersHelper.trim() ? { headersHelper: draft.headersHelper.trim() } : {}),
      ...(oauthClientId || callbackPortNumber
        ? {
            oauth: {
              ...(oauthClientId ? { clientId: oauthClientId } : {}),
              ...(callbackPortNumber ? { callbackPort: callbackPortNumber } : {}),
            },
          }
        : {}),
    },
  }
}

function parseServerConfigJson(content: string): McpServerRecord['config'] {
  const parsed = JSON.parse(content) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('MCP config JSON must be an object')
  }
  return parsed as McpServerRecord['config']
}

function isDraftValid(draft: McpDraft) {
  if (!draft.name.trim()) return false
  if (draft.transport === 'stdio') return draft.command.trim().length > 0
  return draft.url.trim().length > 0
}

function transportLabel(transport: string, t: ReturnType<typeof useTranslation>) {
  switch (transport) {
    case 'stdio':
      return 'STDIO'
    case 'http':
      return t('settings.mcp.transport.http')
    case 'sse':
      return 'SSE'
    default:
      return transport
  }
}

function getServerGroupKey(server: McpServerRecord): McpGroupKey {
  if (server.name.startsWith('plugin:')) return 'plugin'
  switch (server.scope) {
    case 'project':
    case 'managed':
    case 'enterprise':
    case 'dynamic':
      return server.scope
    default:
      return 'dynamic'
  }
}

function scopeLabel(server: McpServerRecord, t: ReturnType<typeof useTranslation>) {
  const group = getServerGroupKey(server)
  if (group === 'plugin') return t('settings.mcp.scope.plugin')
  return t(`settings.mcp.scope.${group}`)
}

function StatusBadge({ server }: { server: McpServerRecord }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold ${STATUS_TONE[server.status]}`}>
      {server.statusLabel}
    </span>
  )
}

function getServerIdentityKey(server: Pick<McpServerRecord, 'name' | 'scope' | 'projectPath'>) {
  return `${server.scope}:${server.name}`
}

function ToggleSwitch({
  checked,
  disabled,
  onChange,
}: {
  checked: boolean
  disabled?: boolean
  onChange: () => void
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={onChange}
      className={`relative inline-flex h-8 w-14 items-center rounded-full transition-colors ${
        checked ? 'bg-[var(--color-switch-checked-bg)]' : 'bg-[var(--color-border)]'
      } ${disabled ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'}`}
    >
      <span
        className={`inline-block h-6 w-6 transform rounded-full bg-[var(--color-switch-thumb)] shadow-sm transition-transform ${
          checked ? 'translate-x-7' : 'translate-x-1'
        }`}
      />
    </button>
  )
}

function ArraySection({
  title,
  rows,
  onChange,
  onAdd,
  onRemove,
  keyPlaceholder,
  valuePlaceholder,
  singleValue = false,
  addLabel,
}: {
  title: string
  rows: KeyValueRow[] | StringRow[]
  onChange: (id: string, field: 'key' | 'value', value: string) => void
  onAdd: () => void
  onRemove: (id: string) => void
  keyPlaceholder?: string
  valuePlaceholder: string
  singleValue?: boolean
  addLabel: string
}) {
  return (
    <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="text-sm font-semibold text-[var(--color-text-primary)] mb-4">{title}</div>
      <div className="space-y-3">
        {rows.map((row) => (
          <div key={row.id} className={`grid gap-3 ${singleValue ? 'grid-cols-[minmax(0,1fr)_32px]' : 'grid-cols-[minmax(0,1fr)_minmax(0,1fr)_32px]'}`}>
            {!singleValue && 'key' in row && (
              <Input
                value={row.key}
                onChange={(event) => onChange(row.id, 'key', event.target.value)}
                placeholder={keyPlaceholder}
              />
            )}
            <Input
              value={row.value}
              onChange={(event) => onChange(row.id, 'value', event.target.value)}
              placeholder={valuePlaceholder}
            />
            <button
              type="button"
              onClick={() => onRemove(row.id)}
              className="mt-1 flex h-10 w-8 items-center justify-center rounded-[var(--radius-md)] text-[var(--color-text-tertiary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]"
              aria-label={addLabel}
            >
              <span className="material-symbols-outlined text-[18px]">delete</span>
            </button>
          </div>
        ))}
        <button
          type="button"
          onClick={onAdd}
          className="flex h-12 w-full items-center justify-center gap-2 rounded-[var(--radius-lg)] bg-[var(--color-surface-hover)] text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
        >
          <span className="material-symbols-outlined text-[18px]">add</span>
          {addLabel}
        </button>
      </div>
    </section>
  )
}

function LoadingState({ label }: { label: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-[220px] flex-col items-center justify-center gap-3 rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-container-low)] text-center"
    >
      <div className="h-7 w-7 animate-spin rounded-full border-2 border-[var(--color-brand)] border-t-transparent" />
      <div className="text-sm font-medium text-[var(--color-text-secondary)]">{label}</div>
    </div>
  )
}

function ServerRow({
  server,
  isBusy,
  onOpen,
  onToggle,
  t,
}: {
  server: McpServerRecord
  isBusy: boolean
  onOpen: () => void
  onToggle: () => void
  t: ReturnType<typeof useTranslation>
}) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-4 px-6 py-5 border-t border-[var(--color-border)] first:border-t-0">
      <div className="min-w-0">
        <div className="flex items-center gap-3 mb-2 min-w-0">
          <div className="text-[1.05rem] font-semibold text-[var(--color-text-primary)] truncate">{server.name}</div>
          <StatusBadge server={server} />
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--color-text-tertiary)]">
          <span className="rounded-full bg-[var(--color-surface-hover)] px-2 py-1 font-medium text-[var(--color-text-secondary)]">
            {transportLabel(server.transport, t)}
          </span>
          <span className="rounded-full bg-[var(--color-surface-hover)] px-2 py-1 font-medium text-[var(--color-text-secondary)]">
            {scopeLabel(server, t)}
          </span>
          {serverHasProjectContext(server) && (
            <span
              className="max-w-full truncate rounded-full bg-[var(--color-surface-hover)] px-2 py-1 font-[var(--font-mono)] text-[11px] text-[var(--color-text-tertiary)]"
              title={server.projectPath}
            >
              {server.projectPath}
            </span>
          )}
          <span className="truncate">{server.summary}</span>
        </div>
        {server.statusDetail && (
          <div className="mt-2 text-xs text-[var(--color-text-tertiary)] truncate">{server.statusDetail}</div>
        )}
      </div>

      <button
        type="button"
        onClick={onOpen}
        className="flex h-10 w-10 items-center justify-center rounded-full text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]"
        aria-label={`Open ${server.name}`}
      >
        <span className="material-symbols-outlined text-[20px]">settings</span>
      </button>

      <ToggleSwitch checked={server.enabled} disabled={isBusy || !server.canToggle} onChange={onToggle} />
    </div>
  )
}

function IndeterminateCheckbox({ checked, indeterminate, onChange }: { checked: boolean; indeterminate: boolean; onChange: (checked: boolean) => void }) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate
  }, [indeterminate])
  return (
    <input
      ref={ref}
      type="checkbox"
      checked={checked}
      onChange={(e) => onChange(e.target.checked)}
      className="accent-[var(--color-brand)]"
    />
  )
}

export function McpSettings() {
  const { servers, selectedServer, isLoading, error, fetchServers, createServer, updateServer, deleteServer, toggleServer, reconnectServer, refreshServerStatus, selectServer } = useMcpStore()
  const addToast = useUIStore((s) => s.addToast)
  const sessions = useSessionStore((s) => s.sessions)
  const activeSessionId = useSessionStore((s) => s.activeSessionId)
  const t = useTranslation()
  const [view, setView] = useState<EditorMode>({ type: 'list' })
  const [draft, setDraft] = useState<McpDraft>(createEmptyDraft)
  const [isSaving, setIsSaving] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [busyServerKey, setBusyServerKey] = useState<string | null>(null)
  const [pendingDeleteServer, setPendingDeleteServer] = useState<McpServerRecord | null>(null)
  const [isInitialLoading, setIsInitialLoading] = useState(true)
  const projectPathsForFetchRef = useRef<string[] | undefined>(undefined)
  const refreshInFlightRef = useRef(new Set<string>())
  const [jsonContent, setJsonContent] = useState('')
  const [jsonSaving, setJsonSaving] = useState(false)

  // ── Data directory state ──
  const [dataDirOpen, setDataDirOpen] = useState(true)
  const [defaultPaths, setDefaultPaths] = useState<McpDefaultPath[]>([])
  const [scanResult, setScanResult] = useState<McpScanResult | null>(null)
  const [importResult, setImportResult] = useState<McpImportResult | null>(null)
  const [importing, setImporting] = useState(false)
  const [selectedServers, setSelectedServers] = useState<Record<string, Set<string>>>({})
  const [rootDataPath, setRootDataPath] = useState('')

  const activeSession = sessions.find((session) => session.id === activeSessionId)
  const currentWorkDir = activeSession?.workDir || undefined
  const resolveOperationCwd = (server?: McpServerRecord) => server?.projectPath ?? currentWorkDir

  useEffect(() => {
    let cancelled = false
    setIsInitialLoading(useMcpStore.getState().servers.length === 0)

    const loadServers = async () => {
      try {
        const [recentProjectPaths, privateMcpProjectPaths] = await Promise.all([
          sessionsApi.getRecentProjects(8)
            .then(({ projects }) => projects.map((project) => project.realPath))
            .catch(() => []),
          mcpApi.projectPaths()
            .then(({ projectPaths }) => projectPaths)
            .catch(() => []),
        ])
        if (cancelled) return
        const paths = [
          currentWorkDir,
          ...recentProjectPaths,
          ...privateMcpProjectPaths,
        ].filter((path): path is string => !!path)
        const projectPathsForFetch = Array.from(new Set(paths))
        projectPathsForFetchRef.current = projectPathsForFetch.length ? projectPathsForFetch : undefined
        await fetchServers(projectPathsForFetchRef.current, currentWorkDir)
      } finally {
        if (!cancelled) setIsInitialLoading(false)
      }
    }

    void loadServers()

    return () => {
      cancelled = true
    }
  }, [fetchServers, currentWorkDir])

  // ── Load saved data directory config and default paths on mount ──
  useEffect(() => {
    let cancelled = false
    // Load saved config first
    mcpApi.getDataDirectory().then((saved) => {
      if (cancelled) return
      if (saved.rootPath) {
        setRootDataPath(saved.rootPath)
      } else if (currentWorkDir) {
        setRootDataPath(`${currentWorkDir}/data`)
      }
    }).catch(() => {
      if (currentWorkDir && !cancelled) {
        setRootDataPath(`${currentWorkDir}/data`)
      }
    })
    // Then load default paths as fallback
    mcpApi.defaultPaths().then((data) => {
      if (cancelled) return
      setDefaultPaths(data.paths)
    }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  // Save data directory path when it changes (debounced)
  const saveDataDirTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const setRootDataPathAndSave = useCallback((path: string) => {
    setRootDataPath(path)
    if (saveDataDirTimer.current) clearTimeout(saveDataDirTimer.current)
    saveDataDirTimer.current = setTimeout(() => {
      mcpApi.setDataDirectory(path).catch(() => {})
    }, 500)
  }, [])

  const handleScanSource = async (path: string) => {
    setScanResult(null)
    setSelectedServers({})
    try {
      const result = await mcpApi.scanSource(path)
      setScanResult(result)
      const allSelected: Record<string, Set<string>> = {}
      for (const src of result.results) {
        allSelected[src.sourceFile] = new Set(src.servers.map(s => s.name))
      }
      setSelectedServers(allSelected)
    } catch { /* silent */ }
  }

  const toggleImportServer = (sourceFile: string, serverName: string) => {
    setSelectedServers(prev => {
      const next = { ...prev }
      const set = new Set(next[sourceFile] || [])
      if (set.has(serverName)) set.delete(serverName)
      else set.add(serverName)
      next[sourceFile] = set
      return next
    })
  }

  const toggleAllServers = (sourceFile: string, serverNames: string[], checked: boolean) => {
    setSelectedServers(prev => ({
      ...prev,
      [sourceFile]: checked ? new Set(serverNames) : new Set(),
    }))
  }

  const handleImport = async (sourcePath: string) => {
    const selections: McpImportSelection[] = Object.entries(selectedServers)
      .filter(([, names]) => names.size > 0)
      .map(([sourceFile, serverNames]) => ({ sourceFile, serverNames: Array.from(serverNames) }))
    if (selections.length === 0) return
    setImporting(true)
    setImportResult(null)
    try {
      const result = await mcpApi.importConfigs(sourcePath, selections)
      setImportResult(result)
      await fetchServers(projectPathsForFetchRef.current, currentWorkDir)
    } catch { /* silent */ }
    setImporting(false)
  }

  const groupedServers = useMemo(() => {
    const groups: Partial<Record<McpGroupKey, McpServerRecord[]>> = {}
    for (const server of servers) {
      const key = getServerGroupKey(server)
      ;(groups[key] ??= []).push(server)
    }
    return groups
  }, [servers])

  const showListLoading = (isInitialLoading || isLoading) && servers.length === 0

  const beginCreate = () => {
    setDraft(createEmptyDraft())
    setView({ type: 'create' })
  }

  const beginEdit = (server: McpServerRecord) => {
    selectServer(server)
    if (!server.canEdit) {
      setView({ type: 'details', server })
      return
    }
    setDraft(draftFromServer(server))
    setView({ type: 'edit', server })
  }

  const beginServerJsonEdit = (server: McpServerRecord) => {
    if (!server.canEdit) return
    setJsonContent(JSON.stringify(server.config, null, 2))
    setView({ type: 'serverJson', server })
  }

  useEffect(() => {
    if (!selectedServer) return
    if (selectedServer.canEdit) {
      setDraft(draftFromServer(selectedServer))
      setView({ type: 'edit', server: selectedServer })
    } else {
      setView({ type: 'details', server: selectedServer })
    }
  }, [selectedServer])

  useEffect(() => {
    const pendingServers = servers.filter((server) => (
      server.enabled &&
      server.status === 'checking' &&
      !refreshInFlightRef.current.has(getServerIdentityKey(server))
    ))

    if (pendingServers.length === 0) return

    let cancelled = false
    const queue = [...pendingServers]
    const workerCount = Math.min(2, queue.length)

    const runWorker = async () => {
      while (!cancelled) {
        const server = queue.shift()
        if (!server) return

        const key = getServerIdentityKey(server)
        refreshInFlightRef.current.add(key)
        try {
          const updated = await refreshServerStatus(server, resolveOperationCwd(server))
          if (cancelled) return

          setView((current) => {
            if (current.type !== 'details' && current.type !== 'edit') return current
            if (getServerIdentityKey(current.server) !== key) return current
            return { ...current, server: updated }
          })
        } catch {
          // Keep passive checks silent. Explicit reconnect remains the action that
          // surfaces failures to the user.
        } finally {
          refreshInFlightRef.current.delete(key)
        }
      }
    }

    void Promise.all(Array.from({ length: workerCount }, () => runWorker()))

    return () => {
      cancelled = true
    }
  }, [servers, refreshServerStatus, currentWorkDir])

  const handleToggle = async (server: McpServerRecord) => {
    setBusyServerKey(getServerIdentityKey(server))
    try {
      const updated = await toggleServer(server, resolveOperationCwd(server), activeSessionId ?? undefined)
      addToast({
        type: 'success',
        message: updated.enabled ? t('settings.mcp.toast.enabled', { name: server.name }) : t('settings.mcp.toast.disabled', { name: server.name }),
      })
    } catch (error) {
      addToast({
        type: 'error',
        message: error instanceof Error ? error.message : t('settings.mcp.toast.toggleFailed'),
      })
    } finally {
      setBusyServerKey(null)
    }
  }

  const handleReconnect = async (server: McpServerRecord) => {
    const optimistic = {
      ...server,
      status: 'checking' as const,
      statusLabel: t('status.reconnecting'),
      statusDetail: undefined,
    }

    setBusyServerKey(getServerIdentityKey(server))
    setView((current) => {
      if (current.type !== 'details' && current.type !== 'edit') return current
      if (getServerIdentityKey(current.server) !== getServerIdentityKey(server)) return current
      return { ...current, server: optimistic }
    })
    try {
      const updated = await reconnectServer(server, resolveOperationCwd(server))
      addToast({
        type: updated.status === 'connected' ? 'success' : 'warning',
        message: updated.status === 'connected'
          ? t('settings.mcp.toast.reconnected', { name: server.name })
          : updated.statusDetail || updated.statusLabel,
      })
      if (view.type === 'edit') setView({ type: 'edit', server: updated })
      if (view.type === 'details') setView({ type: 'details', server: updated })
    } catch (error) {
      setView((current) => {
        if (current.type !== 'details' && current.type !== 'edit') return current
        if (getServerIdentityKey(current.server) !== getServerIdentityKey(server)) return current
        return { ...current, server }
      })
      addToast({
        type: 'error',
        message: error instanceof Error ? error.message : t('settings.mcp.toast.reconnectFailed'),
      })
    } finally {
      setBusyServerKey(null)
    }
  }

  const handleDelete = (server: McpServerRecord) => {
    setPendingDeleteServer(server)
  }

  const confirmDelete = async () => {
    const server = pendingDeleteServer
    if (!server) return
    setIsDeleting(true)
    try {
      await deleteServer(server, resolveOperationCwd(server))
      addToast({
        type: 'success',
        message: t('settings.mcp.toast.deleted', { name: server.name }),
      })
      setView({ type: 'list' })
      selectServer(null)
      setPendingDeleteServer(null)
    } catch (error) {
      addToast({
        type: 'error',
        message: error instanceof Error ? error.message : t('settings.mcp.toast.deleteFailed'),
      })
    } finally {
      setIsDeleting(false)
    }
  }

  const deleteModal = (
    <ConfirmDialog
      open={pendingDeleteServer !== null}
      onClose={() => {
        if (isDeleting) return
        setPendingDeleteServer(null)
      }}
      title={t('settings.mcp.form.deleteTitle')}
      body={pendingDeleteServer ? t('settings.mcp.form.deleteConfirmBody', { name: pendingDeleteServer.name }) : ''}
      confirmLabel={t('settings.mcp.form.confirmDelete')}
      cancelLabel={t('settings.mcp.form.cancel')}
      confirmVariant="danger"
      loading={isDeleting}
      onConfirm={confirmDelete}
    />
  )

  const handleSave = async () => {
    if (!isDraftValid(draft)) return
    setIsSaving(true)
    try {
      const payload = buildPayload(draft)
      const saved = view.type === 'edit'
        ? await updateServer(view.server, payload, undefined)
        : await createServer(draft.name.trim(), payload, undefined)

      addToast({
        type: 'success',
        message: view.type === 'edit'
          ? t('settings.mcp.toast.saved', { name: saved.name })
          : t('settings.mcp.toast.created', { name: saved.name }),
      })
      setView({ type: 'list' })
      selectServer(null)
    } catch (error) {
      addToast({
        type: 'error',
        message: error instanceof Error ? error.message : t('settings.mcp.toast.saveFailed'),
      })
    } finally {
      setIsSaving(false)
    }
  }

  const setDraftField = <K extends keyof McpDraft>(key: K, value: McpDraft[K]) => {
    setDraft((current) => ({ ...current, [key]: value }))
  }

  const updateStringRows = (key: 'args', id: string, value: string) => {
    setDraft((current) => ({
      ...current,
      [key]: current[key].map((row) => (row.id === id ? { ...row, value } : row)),
    }))
  }

  const updateKeyValueRows = (key: 'env' | 'headers', id: string, field: 'key' | 'value', value: string) => {
    setDraft((current) => ({
      ...current,
      [key]: current[key].map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    }))
  }

  const addRow = (key: 'args' | 'env' | 'headers') => {
    setDraft((current) => ({
      ...current,
      [key]: [...current[key], key === 'args' ? createStringRow() : createKeyValueRow()],
    }))
  }

  const removeRow = (key: 'args' | 'env' | 'headers', id: string) => {
    setDraft((current) => {
      const next = current[key].filter((row) => row.id !== id)
      return {
        ...current,
        [key]: next.length > 0 ? next : [key === 'args' ? createStringRow() : createKeyValueRow()],
      }
    })
  }

  if (view.type === 'json') {
    return (
      <div className="w-full min-w-0">
        <button
          type="button"
          onClick={() => { setView({ type: 'list' }); setJsonContent('') }}
          className="mb-5 inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
        >
          <span className="material-symbols-outlined text-[18px]">arrow_back</span>
          {t('settings.mcp.form.back')}
        </button>

        <h2 className="text-[1.6rem] font-semibold tracking-[-0.03em] text-[var(--color-text-primary)] mb-1">{t('settings.mcp.editJson')}</h2>
        <p className="text-sm text-[var(--color-text-tertiary)] mb-4">{t('settings.mcp.jsonEditorHint')}</p>

        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden mb-4">
          <div className="flex items-center justify-between px-5 py-3 border-b border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
            <span className="text-xs font-mono text-[var(--color-text-secondary)]">data/mcp.json</span>
          </div>
          <textarea
            value={jsonContent}
            onChange={(e) => setJsonContent(e.target.value)}
            spellCheck={false}
            className="w-full min-h-[400px] p-5 font-mono text-sm leading-relaxed bg-[var(--color-surface)] text-[var(--color-text-primary)] outline-none resize-y border-0"
            style={{ tabSize: 2 }}
          />
        </div>

        <div className="flex items-center gap-3">
          <Button variant="primary" onClick={async () => {
            setJsonSaving(true)
            try {
              await mcpApi.putJson(jsonContent)
              addToast({ type: 'success', message: t('settings.mcp.toast.saved') })
              setView({ type: 'list' })
              setJsonContent('')
              await fetchServers(projectPathsForFetchRef.current, currentWorkDir)
            } catch (e) {
              addToast({ type: 'error', message: e instanceof Error ? e.message : t('common.error') })
            } finally {
              setJsonSaving(false)
            }
          }} loading={jsonSaving}>
            {t('common.save')}
          </Button>
          <Button variant="secondary" onClick={() => { setView({ type: 'list' }); setJsonContent('') }}>
            {t('common.cancel')}
          </Button>
        </div>
      </div>
    )
  }

  if (view.type === 'serverJson') {
    const server = view.server
    return (
      <div className="w-full min-w-0">
        <button
          type="button"
          onClick={() => {
            setJsonContent('')
            setView(server.canEdit ? { type: 'edit', server } : { type: 'details', server })
          }}
          className="mb-5 inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
        >
          <span className="material-symbols-outlined text-[18px]">arrow_back</span>
          {t('settings.mcp.form.back')}
        </button>

        <h2 className="text-[1.6rem] font-semibold tracking-[-0.03em] text-[var(--color-text-primary)] mb-1">
          {t('settings.mcp.currentJson.title', { name: server.name })}
        </h2>
        <p className="text-sm text-[var(--color-text-tertiary)] mb-4">
          {t('settings.mcp.currentJson.hint')}
        </p>

        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden mb-4">
          <div className="flex items-center justify-between px-5 py-3 border-b border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
            <span className="text-xs font-mono text-[var(--color-text-secondary)]">
              mcpServers.{server.name}
            </span>
          </div>
          <textarea
            value={jsonContent}
            onChange={(e) => setJsonContent(e.target.value)}
            spellCheck={false}
            className="w-full min-h-[360px] p-5 font-mono text-sm leading-relaxed bg-[var(--color-surface)] text-[var(--color-text-primary)] outline-none resize-y border-0"
            style={{ tabSize: 2 }}
          />
        </div>

        <div className="flex items-center gap-3">
          <Button variant="primary" onClick={async () => {
            setJsonSaving(true)
            try {
              const config = parseServerConfigJson(jsonContent)
              const saved = await updateServer(
                server,
                { scope: 'project', config },
                resolveOperationCwd(server),
              )
              addToast({ type: 'success', message: t('settings.mcp.toast.saved', { name: saved.name }) })
              setJsonContent('')
              setDraft(draftFromServer(saved))
              setView({ type: 'edit', server: saved })
              await fetchServers(projectPathsForFetchRef.current, currentWorkDir)
            } catch (e) {
              addToast({ type: 'error', message: e instanceof Error ? e.message : t('common.error') })
            } finally {
              setJsonSaving(false)
            }
          }} loading={jsonSaving}>
            {t('common.save')}
          </Button>
          <Button variant="secondary" onClick={() => {
            setJsonContent('')
            setView(server.canEdit ? { type: 'edit', server } : { type: 'details', server })
          }}>
            {t('common.cancel')}
          </Button>
        </div>
      </div>
    )
  }

  if (view.type === 'details') {
    const server = view.server
    return (
      <>
        <div className="max-w-5xl min-w-0">
          <button
            type="button"
            onClick={() => {
              setView({ type: 'list' })
              selectServer(null)
            }}
            className="mb-5 inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
          >
            <span className="material-symbols-outlined text-[18px]">arrow_back</span>
            {t('settings.mcp.form.back')}
          </button>

          <div className="flex items-start justify-between gap-4 mb-8">
            <div>
              <h2 className="text-[2.2rem] font-semibold tracking-[-0.03em] text-[var(--color-text-primary)]">{server.name}</h2>
              <p className="mt-3 text-base text-[var(--color-text-secondary)]">{server.summary}</p>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <StatusBadge server={server} />
                {server.statusDetail && (
                  <span className="text-sm text-[var(--color-text-tertiary)]">{server.statusDetail}</span>
                )}
              </div>
            </div>
            {server.canReconnect && (
              <Button variant="secondary" onClick={() => handleReconnect(server)} loading={busyServerKey === getServerIdentityKey(server)}>
                <span className="material-symbols-outlined text-[16px]">sync</span>
                {t('settings.mcp.form.reconnect')}
              </Button>
            )}
          </div>

          <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
            <div className="grid gap-4 md:grid-cols-2">
              <InfoPair label={t('settings.mcp.form.transport')} value={transportLabel(server.transport, t)} />
              <InfoPair label={t('settings.mcp.form.scope')} value={scopeLabel(server, t)} />
              <InfoPair label={t('settings.mcp.form.status')} value={server.statusLabel} />
              <InfoPair label={t('settings.mcp.form.location')} value={server.configLocation} />
            </div>
            <div className="mt-5">
              <div className="text-sm font-semibold text-[var(--color-text-primary)] mb-2">{t('settings.mcp.form.rawConfig')}</div>
              <pre className="overflow-x-auto rounded-[var(--radius-lg)] bg-[var(--color-surface-hover)] p-4 text-xs text-[var(--color-text-secondary)]">
                {JSON.stringify(server.config, null, 2)}
              </pre>
            </div>
          </section>
        </div>
        {deleteModal}
      </>
    )
  }

  if (view.type === 'create' || view.type === 'edit') {
    const editing = view.type === 'edit'
    const targetServer = editing ? view.server : null
    const transportLocked = editing
    const isBusy = isSaving || isDeleting

    return (
      <>
        <div className="max-w-5xl min-w-0">
          <button
            type="button"
            onClick={() => {
              setView({ type: 'list' })
              selectServer(null)
            }}
            className="mb-5 inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
          >
            <span className="material-symbols-outlined text-[18px]">arrow_back</span>
            {t('settings.mcp.form.back')}
          </button>

          <div className="flex items-start justify-between gap-4 mb-8">
            <div>
              <h2 className="text-[2.2rem] font-semibold tracking-[-0.03em] text-[var(--color-text-primary)]">
                {editing ? t('settings.mcp.form.editTitle', { name: targetServer!.name }) : t('settings.mcp.form.createTitle')}
              </h2>
              <p className="mt-3 text-base text-[var(--color-text-secondary)]">
                {editing ? t('settings.mcp.form.editHint') : t('settings.mcp.form.createHint')}
              </p>
              {editing && targetServer && (
                <div className="mt-4 flex flex-wrap items-center gap-3">
                  <StatusBadge server={targetServer} />
                  {targetServer.statusDetail && (
                    <span className="text-sm text-[var(--color-text-tertiary)]">{targetServer.statusDetail}</span>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center gap-3">
              {editing && targetServer?.canEdit && (
                <Button variant="secondary" onClick={() => beginServerJsonEdit(targetServer)}>
                  <span className="material-symbols-outlined text-[16px]">data_object</span>
                  {t('settings.mcp.currentJson.action')}
                </Button>
              )}
              {editing && targetServer?.canReconnect && (
                <Button variant="secondary" onClick={() => handleReconnect(targetServer)} loading={busyServerKey === getServerIdentityKey(targetServer)}>
                  <span className="material-symbols-outlined text-[16px]">sync</span>
                  {t('settings.mcp.form.reconnect')}
                </Button>
              )}
              {editing && targetServer?.canRemove && (
                <Button
                  variant="ghost"
                  className="text-[var(--color-error)] hover:text-[var(--color-error)] hover:bg-[var(--color-error)]/8"
                  onClick={() => handleDelete(targetServer)}
                  loading={isDeleting}
                >
                  <span className="material-symbols-outlined text-[16px]">delete</span>
                  {t('settings.mcp.form.uninstall')}
                </Button>
              )}
            </div>
          </div>

          <div className="space-y-4">
          <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <Input
              label={t('settings.mcp.form.name')}
              value={draft.name}
              onChange={(event) => setDraftField('name', event.target.value)}
              placeholder={t('settings.mcp.form.namePlaceholder')}
              disabled={editing}
              required
            />
          </section>

          <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <div className="flex items-center gap-3">
              <span className="material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)]">info</span>
              <p className="text-xs text-[var(--color-text-tertiary)]">
                {t('settings.mcp.form.mcpListHint')}
              </p>
            </div>
          </section>

          <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
            <div className="grid grid-cols-3">
              {(['stdio', 'http', 'sse'] as TransportKind[]).map((transport) => {
                const active = draft.transport === transport
                return (
                  <button
                    key={transport}
                    type="button"
                    disabled={transportLocked}
                    onClick={() => setDraftField('transport', transport)}
                    className={`h-14 text-sm font-semibold transition-colors ${
                      active
                        ? 'bg-[var(--color-surface-selected)] text-[var(--color-text-primary)]'
                        : 'bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]'
                    } ${transportLocked ? 'cursor-not-allowed opacity-70' : ''}`}
                  >
                    {transport === 'stdio' ? 'STDIO' : transportLabel(transport, t)}
                  </button>
                )
              })}
            </div>
          </section>

          {editing && (
            <div className="text-sm text-[var(--color-text-tertiary)]">
              {t('settings.mcp.form.transportLocked')}
            </div>
          )}

          {draft.transport === 'stdio' ? (
            <>
              <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
                <Input
                  label={t('settings.mcp.form.command')}
                  value={draft.command}
                  onChange={(event) => setDraftField('command', event.target.value)}
                  placeholder={t('settings.mcp.form.commandPlaceholder')}
                  required
                />
                <p className="mt-2 text-xs leading-5 text-[var(--color-text-tertiary)]">
                  {t('settings.mcp.form.commandHostHint')}
                </p>
              </section>

              <ArraySection
                title={t('settings.mcp.form.arguments')}
                rows={draft.args}
                onChange={(id, _field, value) => updateStringRows('args', id, value)}
                onAdd={() => addRow('args')}
                onRemove={(id) => removeRow('args', id)}
                singleValue
                valuePlaceholder={t('settings.mcp.form.argumentPlaceholder')}
                addLabel={t('settings.mcp.form.addArgument')}
              />

              <ArraySection
                title={t('settings.mcp.form.environmentVariables')}
                rows={draft.env}
                onChange={(id, field, value) => updateKeyValueRows('env', id, field, value)}
                onAdd={() => addRow('env')}
                onRemove={(id) => removeRow('env', id)}
                keyPlaceholder={t('settings.mcp.form.keyPlaceholder')}
                valuePlaceholder={t('settings.mcp.form.valuePlaceholder')}
                addLabel={t('settings.mcp.form.addEnv')}
              />
            </>
          ) : (
            <>
              <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
                <Input
                  label={draft.transport === 'http' ? t('settings.mcp.form.url') : t('settings.mcp.form.sseUrl')}
                  value={draft.url}
                  onChange={(event) => setDraftField('url', event.target.value)}
                  placeholder={t('settings.mcp.form.urlPlaceholder')}
                  required
                />
              </section>

              <ArraySection
                title={t('settings.mcp.form.headers')}
                rows={draft.headers}
                onChange={(id, field, value) => updateKeyValueRows('headers', id, field, value)}
                onAdd={() => addRow('headers')}
                onRemove={(id) => removeRow('headers', id)}
                keyPlaceholder={t('settings.mcp.form.keyPlaceholder')}
                valuePlaceholder={t('settings.mcp.form.valuePlaceholder')}
                addLabel={t('settings.mcp.form.addHeader')}
              />

              <section className="rounded-[var(--radius-xl)] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
                <div className="grid gap-4 md:grid-cols-2">
                  <Input
                    label={t('settings.mcp.form.oauthClientId')}
                    value={draft.oauthClientId}
                    onChange={(event) => setDraftField('oauthClientId', event.target.value)}
                    placeholder={t('settings.mcp.form.oauthClientIdPlaceholder')}
                  />
                  <Input
                    label={t('settings.mcp.form.oauthCallbackPort')}
                    value={draft.oauthCallbackPort}
                    onChange={(event) => setDraftField('oauthCallbackPort', event.target.value)}
                    placeholder={t('settings.mcp.form.oauthCallbackPortPlaceholder')}
                  />
                </div>
                <div className="mt-4">
                  <Input
                    label={t('settings.mcp.form.headersHelper')}
                    value={draft.headersHelper}
                    onChange={(event) => setDraftField('headersHelper', event.target.value)}
                    placeholder={t('settings.mcp.form.headersHelperPlaceholder')}
                  />
                </div>
              </section>
            </>
          )}

          <div className="flex justify-end pt-2">
            <Button onClick={handleSave} disabled={!isDraftValid(draft) || isBusy} loading={isSaving}>
              {t('settings.mcp.form.save')}
            </Button>
          </div>
        </div>
        </div>
        {deleteModal}
      </>
    )
  }

  return (
    <div className="max-w-5xl min-w-0">
      <div className="flex items-start justify-between gap-6 mb-8">
        <div>
          <h2 className="text-[2.2rem] font-semibold tracking-[-0.03em] text-[var(--color-text-primary)]">
            {t('settings.mcp.title')}
          </h2>
          <p className="mt-3 text-base text-[var(--color-text-secondary)]">
            {t('settings.mcp.description')}
          </p>
        </div>
        <Button variant="secondary" size="lg" onClick={beginCreate}>
          <span className="material-symbols-outlined text-[18px]">add</span>
          {t('settings.mcp.addServer')}
        </Button>
        <Button variant="secondary" size="lg" onClick={async () => {
          try {
            const { content } = await mcpApi.getJson()
            setJsonContent(content)
          } catch {
            setJsonContent('{\n  "mcpServers": {}\n}')
          }
          setView({ type: 'json' })
        }}>
          <span className="material-symbols-outlined text-[18px]">code</span>
          {t('settings.mcp.editJson')}
        </Button>
      </div>

      {/* ── Data Directory section ── */}
      <div className="mb-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
        <button
          type="button"
          onClick={() => setDataDirOpen(!dataDirOpen)}
          className="flex w-full items-center gap-3 px-5 py-4 text-left transition-colors hover:bg-[var(--color-surface-hover)]"
        >
          <span className={`material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)] transition-transform ${dataDirOpen ? 'rotate-90' : ''}`}>chevron_right</span>
          <span className="text-sm font-semibold text-[var(--color-text-primary)]">Data Directory</span>
          <span className="text-xs text-[var(--color-text-tertiary)] ml-auto">MCP storage paths</span>
        </button>

        {dataDirOpen && (
          <div className="border-t border-[var(--color-border)] px-5 py-4 space-y-4">
            {/* Data Directory root path */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-tertiary)] mb-2">Root Path</div>
              <div className="flex items-center gap-3 rounded-xl bg-[var(--color-surface-container-low)] px-4 py-3">
                <span className="material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)]">folder</span>
                <span className="flex-1 text-xs font-mono text-[var(--color-text-secondary)] break-all">
                  {rootDataPath || (currentWorkDir ? `${currentWorkDir}/data` : 'data/')}
                </span>
                <DirectoryPicker
                  value={rootDataPath || (currentWorkDir ? `${currentWorkDir}/data` : 'data/')}
                  onChange={(path) => setRootDataPathAndSave(path)}
                />
              </div>
              <p className="text-[11px] text-[var(--color-text-tertiary)] mt-1.5 ml-1">
                MCP configs are stored in <code className="text-[var(--color-text-secondary)]">data/mcp.json</code>.
              </p>
            </div>

            {/* Import from external sources */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-tertiary)] mb-2">Import From</div>
              <div className="flex flex-wrap gap-2">
                {defaultPaths.map((entry) => (
                  <button
                    key={entry.name}
                    type="button"
                    onClick={() => handleScanSource(entry.path)}
                    disabled={!entry.exists}
                    className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition-colors ${
                      entry.exists
                        ? 'border-[var(--color-border)] hover:border-[var(--color-border-focus)] hover:bg-[var(--color-surface-hover)]'
                        : 'border-dashed border-[var(--color-border)] opacity-50 cursor-not-allowed'
                    }`}
                  >
                    <span className={`w-2 h-2 rounded-full ${entry.exists ? 'bg-[var(--color-success)]' : 'bg-[var(--color-text-tertiary)]'}`} />
                    {entry.label}
                    <span className="text-[10px] text-[var(--color-text-tertiary)] font-mono truncate max-w-[100px]">{entry.path}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Import result */}
            {scanResult && (
              <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-container-low)] overflow-hidden">
                <div className="px-4 py-3 bg-[var(--color-surface-container-low)] border-b border-[var(--color-border)] flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-tertiary)]">
                    {scanResult.sourcePath}
                  </span>
                </div>
                {scanResult.results.length > 0 ? (
                  <>
                    {scanResult.results.map((src) => (
                      <div key={src.name} className="border-b border-[var(--color-border)] last:border-b-0">
                        <div className="px-4 py-2 bg-[var(--color-surface-container-low)]/50 flex items-center gap-3">
                          <IndeterminateCheckbox
                            checked={(selectedServers[src.sourceFile]?.size || 0) === src.servers.length && src.servers.length > 0}
                            indeterminate={(selectedServers[src.sourceFile]?.size || 0) > 0 && (selectedServers[src.sourceFile]?.size || 0) < src.servers.length}
                            onChange={(checked) => toggleAllServers(src.sourceFile, src.servers.map(s => s.name), checked)}
                          />
                          <span className="text-xs font-medium text-[var(--color-text-secondary)]">{src.name}</span>
                          <span className="text-[10px] text-[var(--color-text-tertiary)]">{src.servers.length} servers</span>
                        </div>
                        <div className="pl-10 pr-4 pb-2">
                          {src.servers.map((svr) => (
                            <label key={svr.name} className="flex items-center gap-3 py-1.5 rounded-lg hover:bg-[var(--color-surface-hover)] cursor-pointer">
                              <input
                                type="checkbox"
                                checked={(selectedServers[src.sourceFile] || new Set()).has(svr.name)}
                                onChange={() => toggleImportServer(src.sourceFile, svr.name)}
                                className="accent-[var(--color-brand)]"
                              />
                              <span className="material-symbols-outlined text-[14px] text-[var(--color-text-tertiary)]">extension</span>
                              <div className="flex-1 min-w-0">
                                <span className="text-sm text-[var(--color-text-primary)]">{svr.name}</span>
                                {svr.description && (
                                  <span className="text-[11px] text-[var(--color-text-tertiary)] ml-2 truncate">{svr.description}</span>
                                )}
                              </div>
                              <span className="text-[10px] rounded-full bg-[var(--color-surface-container-high)] px-2 py-0.5 text-[var(--color-text-tertiary)]">{svr.transport}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    ))}
                    <div className="flex items-center gap-3 px-4 py-3 border-t border-[var(--color-border)]">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => handleImport(scanResult.sourcePath)}
                        loading={importing}
                        disabled={Object.values(selectedServers).every(s => s.size === 0)}
                      >
                        <span className="material-symbols-outlined text-[14px]">download</span>
                        Copy to data/mcp.json
                      </Button>
                      {importResult && (
                        <span className="text-xs text-[var(--color-text-tertiary)]">
                          {importResult.imported.length > 0
                            ? `Imported ${importResult.imported.length} servers`
                            : importResult.errors.length > 0
                              ? `Errors: ${importResult.errors.join('; ')}`
                              : 'No changes'}
                        </span>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="px-4 py-6 text-xs text-[var(--color-text-tertiary)] text-center">
                    No MCP configurations found at this location.
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {showListLoading ? (
        <LoadingState label={t('common.loading')} />
      ) : (
        <>
          {error ? (
            <div className="text-center py-16 rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
              <span className="material-symbols-outlined text-[40px] text-[var(--color-error)] mb-3 block">error</span>
              <p className="text-sm text-[var(--color-error)] mb-3">{error}</p>
              <button
                type="button"
                onClick={() => void fetchServers(projectPathsForFetchRef.current, currentWorkDir)}
                className="text-sm text-[var(--color-text-accent)] hover:underline"
              >
                {t('common.retry')}
              </button>
            </div>
          ) : servers.length === 0 ? (
            <div className="text-center py-16 rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-container-low)]">
              <span className="material-symbols-outlined text-[40px] text-[var(--color-text-tertiary)] mb-3 block">dns</span>
              <p className="text-sm text-[var(--color-text-secondary)] mb-1">{t('settings.mcp.empty')}</p>
              <p className="text-xs text-[var(--color-text-tertiary)]">{t('settings.mcp.emptyHint')}</p>
            </div>
          ) : (
            <div className="flex flex-col gap-6">
              {MCP_GROUP_ORDER.map((group) => {
                const groupServers = groupedServers[group]
                if (!groupServers?.length) return null

                return (
                  <section key={group}>
                    <div className="flex items-center justify-between mb-3">
                      <div className="text-[1.35rem] font-semibold text-[var(--color-text-primary)]">
                        {group === 'plugin' ? t('settings.mcp.scope.plugin') : t(`settings.mcp.scope.${group}`)}
                      </div>
                      <div className="text-sm text-[var(--color-text-tertiary)]">{groupServers.length}</div>
                    </div>
                    <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
                      {groupServers.map((server) => (
                        <ServerRow
                          key={getServerIdentityKey(server)}
                          server={server}
                          isBusy={busyServerKey === getServerIdentityKey(server)}
                          onOpen={() => beginEdit(server)}
                          onToggle={() => void handleToggle(server)}
                          t={t}
                        />
                      ))}
                    </div>
                  </section>
                )
              })}
            </div>
          )}
        </>
      )}
      {deleteModal}
    </div>
  )
}

function InfoPair({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[var(--radius-lg)] bg-[var(--color-surface-hover)] px-4 py-3">
      <div className="text-xs uppercase tracking-[0.16em] font-semibold text-[var(--color-text-tertiary)] mb-2">{label}</div>
      <div className="text-sm text-[var(--color-text-primary)] break-all">{value}</div>
    </div>
  )
}
