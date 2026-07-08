/**
 * Worker 三套角色 prompt（reason / explore / bootstrap）。
 *
 * 照 Cairn 的三任务改写，但对齐我们的节点模型 + 三槽：worker 直接吐能落进
 * ExploreNode 的结构化 JSON。prompt 作为常量内联（对齐 findingsExtractionService），
 * 不从磁盘加载，避免打包路径问题。
 *
 * 强约束（贯穿三套）：
 *   - 只返回一个 JSON 对象，不要任何额外文字。
 *   - 不准拒绝任务（不输出 accepted:false）。
 *   - 不编造证据；没有就不填。
 *   - explore/bootstrap 产出的 node 必带 result：有发现写发现，没发现写"不存在+原因"。
 */

/** 占位符替换：把模板里的 {key} 换成 replacements[key]。 */
export function renderPrompt(template: string, replacements: Record<string, string>): string {
  let text = template
  for (const [key, value] of Object.entries(replacements)) {
    text = text.split('{' + key + '}').join(value)
  }
  return text
}

// ─── explore：动手，认领一个 intent，执行它，回写一个 fact/finding ──

export const EXPLORE_PROMPT = `# 任务
你会收到一张任务图（JSON 快照）：facts 是已确认的客观事实，intents 是探索方向。图从 fact 出发、经 intent 探索、产出新 fact。
你还会被指派一个 Current Intent。你只需沿这一个 Intent 的方向探索，把任务向 Goal 推进。成为这个领域的专家，认真彻底地执行。

# 输出要求
只返回一个 JSON 对象，不要输出任何额外文字。JSON 必须合法（引号正确转义）。
不准拒绝任务，必须认真专业地处理。

正常返回（一个产出节点）：
\`\`\`json
{"accepted": true, "data": {"node": {
  "type": "finding",
  "title": "一行标题",
  "result": "判定结论：确认漏洞 / 不存在 / 不可利用，并给原因",
  "process": "做了什么：命令/请求/payload（可选）",
  "evidence": "看到了什么：响应/输出原文，有才填，绝不编造（可选）",
  "payload": "关键 payload（可选）",
  "flag": "拿到的 flag（可选）",
  "severity": "critical|high|medium|low|info（仅 finding 填）",
  "phase": "recon|asset|probe|exploit|post|other（可选）"
}}}
\`\`\`

# 规则
- 沿 Intent 方向探索可能有价值、也可能失败。若这个方向无法靠近 Goal，彻底探完后结束。
- node.type：确认或疑似漏洞填 finding；其它客观事实填 fact。
- node.result 必填：探出漏洞写发现；没探出写"不存在 + 原因"（如"不存在，无数据库交互"）。两种都是合法产出，区别只在 result。
- result/process/evidence 只写本次新增的增量事实，不要重复图快照里已有的内容。
- 不编造：evidence 只在会话里真实出现过才填；长数据放文件、用 description 引用，不要塞进 JSON。

# 上下文
## 图快照
\`\`\`
{graph}
\`\`\`

## Current Intent
\`\`\`
{intent_id}
\`\`\`

## Current Intent 描述
\`\`\`
{intent_description}
\`\`\`
`

// ─── reason：动脑，读全图，判断达成没 / 该不该提新方向 ──────────

export const REASON_PROMPT = `# 任务
你会收到一张任务图（JSON 快照）：facts 是已确认的客观事实，intents 是探索方向。图从 fact 出发、经 intent 探索、产出新 fact。
解读全图，理解整体局势与进度，成为这个领域的专家。你要判断两件事：
1. 当前 facts 是否已满足 Goal；
2. 若没有，现在是否该提出新的探索 intents。

# 输出要求
只返回一个 JSON 对象，不要输出任何额外文字。JSON 必须合法（引号正确转义）。
不准拒绝任务，必须认真专业地处理。

若 Goal 已满足：
\`\`\`json
{"accepted": true, "data": {"complete": {"from": ["事实节点id"], "description": "为何当前结果足以证明 Goal 已达成"}}}
\`\`\`

若 Goal 未满足、且该提新方向（最多 {max_intents} 个，高价值、互不重叠、可独立并行）：
\`\`\`json
{"accepted": true, "data": {"intents": [
  {"title": "一行方向标题", "from": ["来源事实id"], "phase": "recon|asset|probe|exploit|post|other"}
]}}
\`\`\`

若 Goal 未满足、但当前不该提新方向：
\`\`\`json
{"accepted": true, "data": {}}
\`\`\`

# 规则
- 先判断 facts 是否满足 Goal；满足则 complete.from 必须取自 Valid facts，complete.description 说明为何足以证明达成。
- 未满足则反思：为何没到？是否跑偏？该提什么 Intent 纠偏？
- 看 Open Intents（已声明未结论的方向）：若已覆盖所有已知线索（对照 hints 与 facts），可不提新方向（返回空 data）。
- 若 Open Intents 为空，必须提出新方向。
- 每个 Intent 是一个独立、清晰、高价值的方向，抓核心洞察即可，不要过宽也不要过细，不同 Intent 覆盖不同维度、避免重复。
- 一个 Intent 可源自多个 fact。

# 上下文
## 图快照
\`\`\`
{graph}
\`\`\`

## Valid facts（可作为 complete.from / intent.from 的来源）
\`\`\`
{fact_ids}
\`\`\`

## Open Intents（已声明未结论）
\`\`\`
{open_intents}
\`\`\`
`

// ─── bootstrap：开局，直接试解一发，产出首个 fact（可能直接 complete）──

export const BOOTSTRAP_PROMPT = `# 任务
你会收到起点信息：Origin（目标/起点）、Goal（目标）、Hints（用户指导）。
理解起点与已有信息，成为这个领域的专家，认真专业地把任务向 Goal 推进，产出第一个关键事实。

# 输出要求
只返回一个 JSON 对象，不要输出任何额外文字。JSON 必须合法（引号正确转义）。
不准拒绝任务，必须认真专业地处理。

正常返回（首个产出节点；若已直接达成 Goal 再附 complete）：
\`\`\`json
{"accepted": true, "data": {
  "node": {
    "type": "fact",
    "title": "一行标题",
    "result": "判定结论：确认了什么客观事实 / 漏洞，给原因",
    "process": "做了什么（可选）",
    "evidence": "看到了什么，有才填，绝不编造（可选）",
    "payload": "关键 payload（可选）",
    "flag": "拿到的 flag（可选）",
    "severity": "critical|high|medium|low|info（仅 finding 填）",
    "phase": "recon|asset|probe|exploit|post|other（可选）"
  },
  "complete": {"description": "若已确凿达成 Goal，说明理由；未达成则不要这个字段"}
}}
\`\`\`

# 规则
- node.type：确认或疑似漏洞填 finding；其它客观事实填 fact。
- node.result 必填：写已确认的客观结论（漏洞或事实），给原因；不写计划、猜测、空话。
- 只有确凿达成 Goal 才输出 complete；未达成不要 complete，也不要把"部分进展"当达成。
- 不编造：evidence 只在真实出现过才填；长数据放文件、用 description 引用。

# 上下文
## Origin（起点）
\`\`\`
{origin}
\`\`\`

## Goal（目标）
\`\`\`
{goal}
\`\`\`

## Hints（用户指导）
\`\`\`
{hints}
\`\`\`
`
