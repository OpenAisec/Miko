import { useEffect, useMemo, useState } from 'react'
import { useSkillStore } from '../../stores/skillStore'
import { useSessionStore } from '../../stores/sessionStore'
import { useTranslation } from '../../i18n'
import type { SkillMeta, SkillSource } from '../../types/skill'
import { useChatStore } from '../../stores/chatStore'
import { useTabStore } from '../../stores/tabStore'

/** 分类 id → 中文标签 + 顺序（镜像后端 BUILTIN_CATEGORIES，与设置-工具页面一致）。 */
const CATEGORY_META: Record<string, { label: string; order: number }> = {
  web: { label: 'Web 渗透', order: 0 },
  audit: { label: '代码审计', order: 1 },
  asset: { label: '资产收集', order: 2 },
  mobile: { label: '移动端', order: 3 },
  binary: { label: '二进制', order: 4 },
  redteam: { label: '红队·横向', order: 5 },
  forensics: { label: '取证·隐写', order: 6 },
  cloud: { label: '云·容器', order: 7 },
  custom: { label: '自定义', order: 8 },
}

function catLabel(id: string): string {
  return CATEGORY_META[id]?.label ?? id
}

/** source 降为卡片角标（原分组轴 → 小徽标）。 */
const SOURCE_ACCENT_CLASSES: Record<SkillSource, string> = {
  project: 'bg-[var(--color-success-container)] text-[var(--color-success)]',
  plugin: 'bg-[var(--color-warning-container)] text-[var(--color-warning)]',
  mcp: 'bg-[var(--color-info-container)] text-[var(--color-info)]',
  bundled: 'bg-[var(--color-surface-container-high)] text-[var(--color-text-tertiary)]',
  user: 'bg-[var(--color-surface-container-high)] text-[var(--color-text-secondary)]',
}

function estimateTokens(contentLength: number) {
  return Math.ceil(contentLength / 4)
}

export function SkillList({ skillsDir }: { skillsDir?: string }) {
  const { skills, isLoading, error, fetchSkills, fetchSkillDetail } =
    useSkillStore()
  const sessions = useSessionStore((s) => s.sessions)
  const activeSessionId = useSessionStore((s) => s.activeSessionId)
  const t = useTranslation()
  const activeSession = sessions.find((session) => session.id === activeSessionId)
  const currentWorkDir = activeSession?.workDir || undefined
  const [searchQuery, setSearchQuery] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [createName, setCreateName] = useState('')
  const [createDesc, setCreateDesc] = useState('')
  // 折叠状态：存已展开的 category id（默认全展开，skill 数量少于工具）
  const [expanded, setExpanded] = useState<Set<string>>(new Set(Object.keys(CATEGORY_META)))
  const toggleCat = (cat: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(cat) ? next.delete(cat) : next.add(cat)
      return next
    })
  const normalizedSearchQuery = searchQuery.trim().toLocaleLowerCase()

  useEffect(() => {
    fetchSkills(currentWorkDir, skillsDir)
  }, [fetchSkills, currentWorkDir, skillsDir])

  const filteredSkills = useMemo(() => {
    if (!normalizedSearchQuery) return skills
    return skills.filter((skill) => {
      const fields = [
        skill.name, skill.displayName, skill.description,
        skill.source, catLabel(skill.category ?? 'custom'),
        skill.version, skill.pluginName,
      ]
      return fields.some((f) => f?.toLocaleLowerCase().includes(normalizedSearchQuery))
    })
  }, [skills, normalizedSearchQuery])

  // 按 category 分组
  const grouped = useMemo(() => {
    const map: Record<string, SkillMeta[]> = {}
    for (const skill of filteredSkills) {
      const cat = skill.category ?? 'custom'
      ;(map[cat] ??= []).push(skill)
    }
    return map
  }, [filteredSkills])

  // 按 CATEGORY_META 顺序排列（未知 category 排末尾）
  const sortedCats = useMemo(
    () =>
      Object.keys(grouped).sort(
        (a, b) =>
          (CATEGORY_META[a]?.order ?? 99) - (CATEGORY_META[b]?.order ?? 99) ||
          a.localeCompare(b),
      ),
    [grouped],
  )

  const totalTokens = useMemo(
    () => filteredSkills.reduce((sum, skill) => sum + estimateTokens(skill.contentLength), 0),
    [filteredSkills],
  )

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin w-5 h-5 border-2 border-[var(--color-brand)] border-t-transparent rounded-full" />
      </div>
    )
  }

  if (error) {
    return <div className="text-sm text-[var(--color-error)] py-4">{error}</div>
  }

  if (skills.length === 0) {
    return (
      <div className="text-center py-12 rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-container-low)] px-6">
        <span className="material-symbols-outlined text-[40px] text-[var(--color-text-tertiary)] mb-2 block">
          auto_awesome
        </span>
        <p className="text-sm text-[var(--color-text-tertiary)]">
          {t('settings.skills.empty')}
        </p>
        <p className="text-xs text-[var(--color-text-tertiary)] mt-1">
          {t('settings.skills.emptyHint')}
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6 min-w-0">
      <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-container-low)] overflow-hidden">
        <div className="grid gap-4 px-5 py-5 min-w-0 xl:grid-cols-[minmax(0,1.6fr)_minmax(320px,1fr)] xl:items-end">
          <div className="min-w-0">
            <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--color-text-tertiary)] mb-2">
              {t('settings.skills.browserEyebrow')}
            </div>
            <div className="flex items-center gap-3 mb-2">
              <span className="material-symbols-outlined text-[22px] text-[var(--color-brand)]">
                auto_awesome
              </span>
              <h3 className="text-lg font-semibold text-[var(--color-text-primary)]">
                {t('settings.skills.browserTitle')}
              </h3>
              <button
                type="button"
                onClick={() => { setCreateName(''); setCreateDesc(''); setShowCreate(true) }}
                className="ml-auto flex items-center gap-1.5 rounded-lg bg-[var(--color-brand)] px-3 py-1.5 text-xs font-semibold text-white transition-opacity hover:opacity-90"
              >
                <span className="material-symbols-outlined text-[14px]">add</span>
                新建
              </button>
            </div>
            <p className="text-sm leading-6 text-[var(--color-text-secondary)] max-w-3xl">
              {t('settings.skills.browserDescription')}
            </p>
            <div className="mt-4 max-w-2xl">
              <label className="sr-only" htmlFor="settings-skill-search">
                {t('settings.skills.searchLabel')}
              </label>
              <div className="flex min-h-11 items-center gap-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-3 transition-colors focus-within:border-[var(--color-border-focus)] focus-within:ring-2 focus-within:ring-[var(--color-brand)]/20">
                <span className="material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)]">
                  search
                </span>
                <input
                  id="settings-skill-search"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder={t('settings.skills.searchPlaceholder')}
                  className="min-w-0 flex-1 bg-transparent text-sm text-[var(--color-text-primary)] outline-none placeholder:text-[var(--color-text-tertiary)]"
                />
                {searchQuery && (
                  <button
                    type="button"
                    aria-label={t('settings.skills.clearSearch')}
                    onClick={() => setSearchQuery('')}
                    className="inline-flex h-7 w-7 items-center justify-center rounded-full text-[var(--color-text-tertiary)] transition-colors hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-brand)]"
                  >
                    <span className="material-symbols-outlined text-[16px]">close</span>
                  </button>
                )}
              </div>
              {normalizedSearchQuery && (
                <p className="mt-2 text-[11px] text-[var(--color-text-tertiary)]">
                  {t('settings.skills.searchResultCount', {
                    count: String(filteredSkills.length),
                    total: String(skills.length),
                  })}
                </p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 min-w-0 sm:grid-cols-3">
            <SummaryCard
              label={t('settings.skills.summary.totalSkills')}
              value={String(filteredSkills.length)}
              icon="auto_awesome"
            />
            <SummaryCard
              label="分类"
              value={String(sortedCats.length)}
              icon="category"
            />
            <SummaryCard
              label={t('settings.skills.summary.tokens')}
              value={t('settings.skills.tokenEstimateShort', { count: String(totalTokens) })}
              icon="notes"
              className="col-span-2 sm:col-span-1"
            />
          </div>
        </div>
      </section>

      {filteredSkills.length === 0 && (
        <div className="text-center py-12 rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-container-low)] px-6">
          <span className="material-symbols-outlined text-[40px] text-[var(--color-text-tertiary)] mb-2 block">
            search_off
          </span>
          <p className="text-sm text-[var(--color-text-tertiary)]">
            {t('settings.skills.noSearchResults')}
          </p>
          <p className="text-xs text-[var(--color-text-tertiary)] mt-1">
            {t('settings.skills.noSearchResultsHint')}
          </p>
        </div>
      )}

      <div className="flex flex-col gap-4">
        {sortedCats.map((cat) => {
          const group = grouped[cat]!
          const isOpen = expanded.has(cat)
          const catTokenCount = group.reduce(
            (sum, skill) => sum + estimateTokens(skill.contentLength),
            0,
          )

          return (
            <section
              key={cat}
              className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden min-w-0"
            >
              <button
                type="button"
                onClick={() => toggleCat(cat)}
                className="flex w-full items-center gap-2 px-5 py-4 text-left transition-colors hover:bg-[var(--color-surface-hover)] bg-[var(--color-surface-container-low)]"
              >
                <span className={`material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)] transition-transform ${isOpen ? 'rotate-90' : ''}`}>
                  chevron_right
                </span>
                <h4 className="text-sm font-semibold text-[var(--color-text-primary)]">{catLabel(cat)}</h4>
                <span className="text-xs text-[var(--color-text-tertiary)]">{group.length} 个</span>
                <span className="ml-auto text-[11px] text-[var(--color-text-tertiary)] whitespace-nowrap">
                  {t('settings.skills.tokenEstimateShort', { count: String(catTokenCount) })}
                </span>
              </button>

              {isOpen && (
              <div className="flex flex-col p-2 border-t border-[var(--color-border)]">
                {group.map((skill) => (
                  <button
                    key={`${skill.source}-${skill.name}`}
                    onClick={() =>
                      skill.hasDirectory &&
                      fetchSkillDetail(skill.source, skill.name, currentWorkDir, 'skills', skillsDir)
                    }
                    disabled={!skill.hasDirectory}
                    className="group rounded-xl border border-transparent px-3 py-3 text-left transition-all hover:border-[var(--color-border-focus)] hover:bg-[var(--color-surface-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-brand)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)] disabled:opacity-60 disabled:cursor-default disabled:hover:bg-transparent disabled:hover:border-transparent"
                  >
                    <div className="flex items-start gap-3">
                      <span className="mt-0.5 material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)]">
                        auto_awesome
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold text-[var(--color-text-primary)] break-all">
                            {skill.displayName || skill.name}
                          </span>
                          {skill.version && (
                            <span className="rounded-full bg-[var(--color-surface-container-high)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-tertiary)]">
                              v{skill.version}
                            </span>
                          )}
                          {/* source 降为角标 */}
                          <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${SOURCE_ACCENT_CLASSES[skill.source as SkillSource] ?? SOURCE_ACCENT_CLASSES.user}`}>
                            {skill.source}
                          </span>
                          {skill.userInvocable && (
                            <span className="rounded-full border border-[var(--color-border)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-tertiary)]">
                              {t('settings.skills.slashCommand')}
                            </span>
                          )}
                        </div>
                        <p className="mt-1 text-xs leading-5 text-[var(--color-text-secondary)] break-words">
                          {skill.description}
                        </p>
                        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[var(--color-text-tertiary)]">
                          <span>{t('settings.skills.tokenEstimateShort', { count: String(estimateTokens(skill.contentLength)) })}</span>
                          <span>{skill.hasDirectory ? t('settings.skills.ready') : t('settings.skills.unavailable')}</span>
                        </div>
                      </div>
                      <span className="material-symbols-outlined text-[18px] text-[var(--color-text-tertiary)] opacity-60 transition-transform group-hover:translate-x-0.5 group-hover:opacity-100">
                        chevron_right
                      </span>
                    </div>
                  </button>
                ))}
              </div>
              )}
            </section>
          )
        })}
      </div>

      {showCreate && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/40" onClick={() => setShowCreate(false)}>
          <div className="w-full max-w-md mx-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-xl" onClick={(e) => e.stopPropagation()}>
            <div className="px-5 py-4 border-b border-[var(--color-border)]">
              <h3 className="text-base font-semibold text-[var(--color-text-primary)]">新建技能</h3>
            </div>
            <div className="px-5 py-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1">技能名称</label>
                <input value={createName} onChange={(e) => setCreateName(e.target.value)}
                  placeholder="例如：my-qa-skill"
                  className="w-full rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-border-focus)]" />
              </div>
              <div>
                <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1">描述</label>
                <textarea value={createDesc} onChange={(e) => setCreateDesc(e.target.value)} rows={3}
                  placeholder="描述这个技能应该做什么"
                  className="w-full rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-border-focus)] resize-y" />
              </div>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-[var(--color-border)]">
              <button onClick={() => setShowCreate(false)}
                className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)]">
                取消
              </button>
              <button onClick={async () => {
                if (!createName.trim()) return
                const name = createName.trim()
                if (!name) return
                const sessionStore = useSessionStore.getState()
                const chatStore = useChatStore.getState()
                const tabStore = useTabStore.getState()
                const sessionId = await sessionStore.createSession()
                const msg = createDesc.trim()
                  ? `/skill-creator-agent 创建 ${name}：${createDesc.trim()}`
                  : `/skill-creator-agent 创建 ${name}`
                tabStore.openTab(sessionId, `创建技能 ${name}`)
                chatStore.connectToSession(sessionId)
                chatStore.sendMessage(sessionId, msg, [])
                setShowCreate(false)
              }}
              disabled={!createName.trim()}
              className="rounded-lg bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-40">
              创建并发送
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

function SummaryCard({
  label,
  value,
  icon,
  className = '',
}: {
  label: string
  value: string
  icon: string
  className?: string
}) {
  return (
    <div className={`rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-3 min-w-0 ${className}`}>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-[0.12em] text-[var(--color-text-tertiary)] min-w-0">
        <span className="material-symbols-outlined text-[14px] flex-shrink-0">{icon}</span>
        <span className="truncate">{label}</span>
      </div>
      <div className="mt-2 text-lg font-semibold text-[var(--color-text-primary)] truncate">
        {value}
      </div>
    </div>
  )
}
