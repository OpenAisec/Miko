/**
 * Findings Extraction Service — D2：用 LLM 把渗透会话提炼成结构化发现
 *
 * 设计照搬 titleService 的"一次性 LLM 调用"范式：
 *   new ProviderService() → 解析 active/by-id provider → POST {baseUrl}/v1/messages → 解析 JSON。
 * 失败/无 provider 一律返回空数组（fire-and-forget），绝不抛错阻塞关联流程。
 * 不新增 SDK 依赖、不硬编码 provider。
 */

import { ProviderService } from './providerService.js'

export type ExtractedFinding = {
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  location?: string
  payload?: string
  evidence?: string
  flag?: string
  status: 'unverified' | 'verified' | 'false_positive'
}

const EXTRACTION_SYSTEM_PROMPT = `你是安全测试报告分析助手。下面是一次渗透测试会话的记录（含 AI 的分析与结论）。
请从中提取所有"已确认或疑似的安全发现"，输出为 JSON 数组，不要输出任何额外文字。

每个发现对象字段：
- title: 漏洞简短标题（如 "SQL 注入"、"精度舍入攻击"）
- severity: critical | high | medium | low | info（按危害严重度）
- location: 漏洞位置/接口（可选，如 "/pay?prePayMoney="）
- payload: 触发用的 payload（可选）
- evidence: 一句话证据/原理（可选）
- flag: 若拿到 flag 填它（可选）
- status: verified（已验证）| unverified（疑似）| false_positive（已排除）

规则：
- 只提取真实出现在会话里的发现，不要编造。
- 若会话明确"排除"了某类漏洞（如确认无 SSTI/SQLi），不要列为发现。
- 没有任何发现时返回 []。

只返回 JSON 数组，例如：
[{"title":"精度舍入攻击","severity":"critical","location":"/pay?prePayMoney=","payload":"prePayMoney=0.001","evidence":"四舍五入为0触发flag","flag":"flag{...}","status":"verified"}]`

// 单会话提炼输入 = 主会话文本 + 黑板全文 + 上一版基线（增量精炼防缩水的关键，拼在末尾）。
// 12000 太小：丰富会话（黑板几十节点、几万字符）会把末尾的基线连同半个黑板截掉，
// 模型看不到上一版 → 重新归纳 → 节点变少（实测 39→26 的根因）。DeepSeek v4 1M 上下文，
// 200000 字符（约 120K token）能完整装下单会话黑板 + 基线，仍远低于窗口上限。
const MAX_INPUT_CHARS = 200000
// 项目级提炼要让 LLM 综合大量黑板节点、生成丰富的三槽节点树，生成量大、耗时长。
// 30s 太短，丰富会话（真打靶场的几十节点）会超时被静默吞成空。放宽到 5 分钟。
const EXTRACTION_TIMEOUT_MS = 300_000
// 4000 太小：丰富会话的节点树生成到一半就撞 max_tokens 被截断，残缺 JSON 解析成空。
// 提到 16000 给节点树足够生成空间（项目级要展示更多内容）。
const MAX_OUTPUT_TOKENS = 16000

// ─── 探索节点提炼（通用测试思维：探索 → 发现） ──────────────────

export type ExploreNodeType = 'asset' | 'fact' | 'intent' | 'finding'
/** 阶段标签：agent 据当前工作自由命名（"信息收集"/"通读代码"/"挖洞"…）。
 *  平台不预设领域、不限定阶段——黑板是通用探索思路容器，结构由 agent 自然生长。 */
export type ExplorePhase = string

export type ExtractedNode = {
  /** LLM 给的临时 key，用于表达父子关系（parentKey 指向它）。后端落库时换成真 id。 */
  key: string
  type: ExploreNodeType
  title: string
  parentKey?: string
  phase?: ExplorePhase
  // 三槽：过程 / 证据 / 结论 —— 任何探测动作通用
  process?: string   // 做了什么：命令 / 请求 / payload / 字典 / 配置
  evidence?: string  // 看到了什么：响应 / 输出（会话里有就存，不编造）
  result?: string    // 判定：确认 / 不存在 / 不可利用 + 原因
  // type 相关可选字段
  assetKind?: string
  detail?: string
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status?: string
  location?: string
  payload?: string
  flag?: string
}

const NODE_EXTRACTION_SYSTEM_PROMPT = `你是测试过程分析助手。下面是一次安全测试/审计会话的记录（含 AI 的分析与结论）。
请把整个"探索过程"提炼成一棵节点树，输出 JSON 数组，不要输出任何额外文字。

节点四种 type：
- asset    攻击面对象：域名/子域名/IP/端口/目录/接口/参数
- fact     已确认的客观事实（非漏洞）：如"端口 8888 开放"、"技术栈 PHP 8.1"
- intent   一次探测动作/方向：如"探测 SQL 注入"、"爆破登录"、"SSRF 探测"
- finding  确认或疑似的安全发现（漏洞）

层级约束（严格遵守，固定三层，结构必须稳定）：
- 第1层：只放 asset（攻击面对象，由粗到细：目标 → 接口 → 参数，可嵌套但都是 asset）
- 第2层：intent（探测动作），挂在对应 asset 下；**必须有 result 结论**
- 第3层：finding（确认的漏洞），只挂在产生它的 intent 下，不要孤立放在顶层
- fact 挂在它所属的 asset 下
- 不要超过这个结构（asset → intent → finding）。没探出漏洞的探测就停在 intent（result=不存在），不生 finding。

核心：每个探测动作（intent / finding）都应尽量带"三槽"——
- process: 做了什么（命令 / 请求 / payload / 字典 / 配置）
- evidence: 看到了什么（响应 / 输出原文，会话里有才填，截断即可，绝不编造）
- result: 判定结论（确认漏洞 / 不存在 / 不可利用，并给原因）

每个节点字段：
- key:      本次输出内唯一短标识（你自己编，如 "n1"），用于父子引用
- type:     asset | fact | intent | finding
- title:    一行标题
- parentKey: 父节点 key（从哪延伸；顶层 asset 不填）
- phase:    当前工作阶段，自由命名（如 信息收集 / 资产收集 / 挖洞 / 通读代码 / 静态分析 …）
- assetKind: 仅 asset：domain|subdomain|ip|port|dir|endpoint|param（可选）
- process / evidence / result: 见上（探测动作尽量都填）
- 仅 finding：severity(critical|high|medium|low|info)、status(verified|unverified|false_positive)、location、payload、flag
- 仅 intent：status(pending|exploring|completed|failed)
- detail:   其它补充（可选）

关键规则：
- 真实反映会话，不编造。证据没有就不填，绝不杜撰数据包。
- **凡 status=completed 的 intent，必须有 result**：发现漏洞就写发现；没发现就写"不存在 + 原因"（如"不存在，无数据库交互"）。不要留空。
- 一个探测动作就是一个节点，多次尝试塞进同一节点的 process/evidence，不要每个请求拆一个节点。
- 用 parentKey 体现"从哪打出来"。排除掉的漏洞类型用 intent(completed, result=不存在)，不要列为 finding。
- 没有任何内容时返回 []。

只返回 JSON 数组，例如：
[{"key":"a1","type":"asset","title":"s2rdpor.bug2.sanjiuctf.com:8888","phase":"recon","assetKind":"endpoint"},
{"key":"a2","type":"asset","title":"/pay 接口","parentKey":"a1","phase":"probe","assetKind":"endpoint"},
{"key":"i1","type":"intent","title":"探测 SQL 注入","parentKey":"a2","phase":"probe","status":"completed","process":"注入 1' OR '1'='1、1;DROP TABLE","evidence":"返回\\"充值金额格式错误\\"","result":"不存在，后端 float() 解析、无数据库交互"},
{"key":"i2","type":"intent","title":"金额精度四舍五入测试","parentKey":"a2","phase":"exploit","status":"completed","process":"prePayMoney=0.001","evidence":"round(0.001,2)=0.00，余额不变","result":"确认漏洞：round() 精度处理导致业务逻辑绕过"},
{"key":"f1","type":"finding","title":"金额精度四舍五入漏洞 → Flag 获取","parentKey":"i2","phase":"exploit","severity":"critical","status":"verified","location":"/pay?prePayMoney=","result":"round(0.001,2)=0.00，余额不变触发 flag","flag":"flag{...}"}]

增量修订：如果用户消息里附带了"上一版分析结果"，请把它当作基线——
- 保留上一版已有的节点（标题尽量不变，便于对应），不要删减；
- 在它基础上补全遗漏、修正错误、完善 process/evidence/result；
- 只增不删，让结果越改越完整，绝不比上一版更少。`

/**
 * 把一段会话 transcript 文本提炼为结构化发现。
 * 失败/无可用 provider 返回空数组，绝不抛错。
 */
export async function extractFindings(
  transcriptText: string,
  providerId?: string | null,
): Promise<ExtractedFinding[]> {
  const text = (transcriptText ?? '').trim()
  if (!text) return []

  try {
    const providerService = new ProviderService()
    let resolved = providerId ? await providerService.getProvider(providerId) : null

    if (!resolved) {
      const { activeId, providers } = await providerService.listProviders()
      resolved = activeId ? providers.find((p) => p.id === activeId) ?? null : null
    }

    if (!resolved?.baseUrl || !resolved?.apiKey) return []

    const model = resolved.models.main || resolved.models.sonnet || resolved.models.haiku
    if (!model) return []

    const url = `${resolved.baseUrl.replace(/\/+$/, '')}/v1/messages`
    if (text.length > MAX_INPUT_CHARS) {
      console.warn(
        `[findingsExtraction] 输入被截断：${text.length} > ${MAX_INPUT_CHARS} 字符，提炼可能不完整。`,
      )
    }
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': resolved.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model,
        max_tokens: MAX_OUTPUT_TOKENS,
        system: EXTRACTION_SYSTEM_PROMPT,
        messages: [{ role: 'user', content: text.slice(0, MAX_INPUT_CHARS) }],
      }),
      signal: AbortSignal.timeout(EXTRACTION_TIMEOUT_MS),
    })

    if (!response.ok) return []

    const body = (await response.json()) as {
      content?: Array<{ type: string; text?: string }>
    }
    const out = body.content?.find((b) => b.type === 'text')?.text
    if (!out) return []

    return parseFindingsJson(out)
  } catch {
    return []
  }
}

const VALID_SEVERITY = new Set(['critical', 'high', 'medium', 'low', 'info'])
const VALID_STATUS = new Set(['verified', 'unverified', 'false_positive'])

/**
 * 容错解析 LLM 返回的发现 JSON：去 ```json 围栏、提取首尾方括号、逐字段校验。
 * 解析不出合法数组返回 []。
 */
export function parseFindingsJson(raw: string): ExtractedFinding[] {
  const trimmed = (raw ?? '').trim()
  if (!trimmed) return []

  const candidates = new Set<string>([trimmed])
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i)?.[1]?.trim()
  if (fenced) candidates.add(fenced)
  const firstBracket = trimmed.indexOf('[')
  const lastBracket = trimmed.lastIndexOf(']')
  if (firstBracket >= 0 && lastBracket > firstBracket) {
    candidates.add(trimmed.slice(firstBracket, lastBracket + 1))
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate)
      if (!Array.isArray(parsed)) continue
      const findings = parsed
        .map(normalizeFinding)
        .filter((f): f is ExtractedFinding => f !== null)
      return findings
    } catch {
      // try next candidate
    }
  }
  return []
}

/**
 * 共享的一次性 LLM 调用：解析 provider → POST /v1/messages → 返回纯文本。
 * 失败/无 provider 返回 null。供 findings 与 nodes 提炼复用。
 */
async function callLlmText(
  systemPrompt: string,
  userText: string,
  providerId?: string | null,
): Promise<string | null> {
  const text = (userText ?? '').trim()
  if (!text) return null

  const providerService = new ProviderService()
  let resolved = providerId ? await providerService.getProvider(providerId) : null
  if (!resolved) {
    const { activeId, providers } = await providerService.listProviders()
    resolved = activeId ? providers.find((p) => p.id === activeId) ?? null : null
  }
  if (!resolved?.baseUrl || !resolved?.apiKey) return null

  const model = resolved.models.main || resolved.models.sonnet || resolved.models.haiku
  if (!model) return null

  const url = `${resolved.baseUrl.replace(/\/+$/, '')}/v1/messages`
  // 真发生截断才告警：超出 MAX_INPUT_CHARS 意味着末尾的增量基线被切掉，提炼可能比上一版少。
  // 超长会话的正解是"会话内按 asset 分块提炼"（见 wendang 待实施），此处先确保不静默吞掉。
  if (text.length > MAX_INPUT_CHARS) {
    console.warn(
      `[findingsExtraction] 输入被截断：${text.length} > ${MAX_INPUT_CHARS} 字符，末尾基线/黑板会丢失，提炼可能缩水。考虑会话内按 asset 分块。`,
    )
  }
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': resolved.apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      max_tokens: MAX_OUTPUT_TOKENS,
      system: systemPrompt,
      messages: [{ role: 'user', content: text.slice(0, MAX_INPUT_CHARS) }],
      // 关掉 thinking：否则思考会吃光 token 预算，导致没有最终 text 块返回。
      thinking: { type: 'disabled' },
    }),
    signal: AbortSignal.timeout(EXTRACTION_TIMEOUT_MS),
  })
  if (!response.ok) return null
  const body = (await response.json()) as { content?: Array<{ type: string; text?: string }> }
  // 取所有 text 块拼接（thinking 块已禁用，但保险起见仍只收 text）。
  const outText = (body.content ?? [])
    .filter((b) => b.type === 'text' && typeof b.text === 'string')
    .map((b) => b.text)
    .join('')
  return outText || null
}

/**
 * 把一段会话 transcript 提炼为探索节点树。
 * priorNodes：上一版已提炼的节点（增量精炼基线）。LLM 在它基础上修订、只增不删。
 * 失败/无 provider 返回空数组，绝不抛错。
 */
export async function extractNodes(
  transcriptText: string,
  providerId?: string | null,
  priorNodes?: PriorNode[],
): Promise<ExtractedNode[]> {
  try {
    // 把上一版作为基线拼进 user 消息，引导 LLM 在它上面做加法。
    let userText = transcriptText
    if (priorNodes && priorNodes.length > 0) {
      const baseline = JSON.stringify(
        priorNodes.map((n) => ({
          title: n.title, type: n.type, parentTitle: n.parentTitle,
          status: n.status, severity: n.severity, result: n.result,
        })),
      ).slice(0, 4000)
      userText = `${transcriptText}\n\n=== 上一版分析结果（基线，请在它基础上修订、保留不删减） ===\n${baseline}`
    }
    const out = await callLlmText(NODE_EXTRACTION_SYSTEM_PROMPT, userText, providerId)
    if (!out) return []
    return parseNodesJson(out)
  } catch {
    return []
  }
}

/** 传给 extractNodes 的上一版节点摘要（用标题表达父子，避免 id 漂移）。 */
export type PriorNode = {
  title: string
  type: ExploreNodeType
  parentTitle?: string
  status?: string
  severity?: string
  result?: string
}

const VALID_NODE_TYPE = new Set(['asset', 'fact', 'intent', 'finding'])

/**
 * 容错解析 LLM 返回的节点 JSON：去围栏、提取首尾方括号、逐字段校验。
 * 解析不出合法数组返回 []。
 */
export function parseNodesJson(raw: string): ExtractedNode[] {
  const trimmed = (raw ?? '').trim()
  if (!trimmed) return []

  const candidates = new Set<string>([trimmed])
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i)?.[1]?.trim()
  if (fenced) candidates.add(fenced)
  const firstBracket = trimmed.indexOf('[')
  const lastBracket = trimmed.lastIndexOf(']')
  if (firstBracket >= 0 && lastBracket > firstBracket) {
    candidates.add(trimmed.slice(firstBracket, lastBracket + 1))
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate)
      if (!Array.isArray(parsed)) continue
      const nodes = parsed.map(normalizeNode).filter((n): n is ExtractedNode => n !== null)
      if (nodes.length > 0 || parsed.length === 0) return nodes
    } catch {
      // try next candidate
    }
  }
  return []
}

function normalizeNode(raw: unknown): ExtractedNode | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  const type = typeof r.type === 'string' && VALID_NODE_TYPE.has(r.type) ? (r.type as ExploreNodeType) : null
  const title = typeof r.title === 'string' ? r.title.trim() : ''
  const key = typeof r.key === 'string' && r.key.trim() ? r.key.trim() : ''
  if (!type || !title || !key) return null

  const node: ExtractedNode = { key, type, title: title.slice(0, 200) }
  if (typeof r.parentKey === 'string' && r.parentKey.trim()) node.parentKey = r.parentKey.trim()
  if (typeof r.phase === 'string' && r.phase.trim()) node.phase = r.phase.trim().slice(0, 40)
  if (typeof r.assetKind === 'string' && r.assetKind.trim()) node.assetKind = r.assetKind.trim().slice(0, 40)
  if (typeof r.detail === 'string' && r.detail.trim()) node.detail = r.detail.trim().slice(0, 500)
  if (typeof r.process === 'string' && r.process.trim()) node.process = r.process.trim().slice(0, 800)
  if (typeof r.result === 'string' && r.result.trim()) node.result = r.result.trim().slice(0, 500)
  if (typeof r.severity === 'string' && VALID_SEVERITY.has(r.severity)) node.severity = r.severity as ExtractedNode['severity']
  if (typeof r.status === 'string' && r.status.trim()) node.status = r.status.trim().slice(0, 40)
  if (typeof r.location === 'string' && r.location.trim()) node.location = r.location.trim().slice(0, 300)
  if (typeof r.payload === 'string' && r.payload.trim()) node.payload = r.payload.trim().slice(0, 500)
  if (typeof r.evidence === 'string' && r.evidence.trim()) node.evidence = r.evidence.trim().slice(0, 800)
  if (typeof r.flag === 'string' && r.flag.trim()) node.flag = r.flag.trim().slice(0, 200)
  return node
}

function normalizeFinding(raw: unknown): ExtractedFinding | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  const title = typeof r.title === 'string' ? r.title.trim() : ''
  if (!title) return null

  const severity = typeof r.severity === 'string' && VALID_SEVERITY.has(r.severity)
    ? (r.severity as ExtractedFinding['severity'])
    : 'info'
  const status = typeof r.status === 'string' && VALID_STATUS.has(r.status)
    ? (r.status as ExtractedFinding['status'])
    : 'unverified'

  const finding: ExtractedFinding = { title: title.slice(0, 200), severity, status }
  if (typeof r.location === 'string' && r.location.trim()) finding.location = r.location.trim().slice(0, 300)
  if (typeof r.payload === 'string' && r.payload.trim()) finding.payload = r.payload.trim().slice(0, 500)
  if (typeof r.evidence === 'string' && r.evidence.trim()) finding.evidence = r.evidence.trim().slice(0, 500)
  if (typeof r.flag === 'string' && r.flag.trim()) finding.flag = r.flag.trim().slice(0, 200)
  return finding
}
