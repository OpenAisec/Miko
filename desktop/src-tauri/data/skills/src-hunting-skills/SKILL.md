---
name: src-hunting-skills
description: 面向授权 SRC / bounty 实战的执行型技能。只要任务是在授权范围内实际推进赏金挖掘、验证目标面、选择主线、收集证据、判断是否继续深挖、整理可提交报告材料，就应使用这个技能。它不是用来泛讲漏洞定义、生成答题式 checklist 或整理长文，而是用来驱动 agent 在安全边界内行动。
compatibility:
  tools: Read, Write, Edit, Glob, Grep, Bash
---

# src-hunting-skills

这个技能不是问答手册，而是 **agent 在授权 SRC / bounty 实战中的执行手册**。

它不替代 `src-workflow`：
- `src-workflow` 更偏 **范围确认、资产盘点、规则核对、推进表维护**
- 本技能更偏 **进入具体目标面后的选线、验证、留证、判断是否继续、整理报告材料**

如果任务同时需要“先确认范围/资产/规则”再“实际开测”，先用 `src-workflow` 打底，再用本技能进入执行循环。

## 先记住这件事

本技能的目标不是让 agent 回答得像实战手册，而是让 agent 在授权前提下更快完成这几件事：
- 选对高价值主线
- 用低影响动作先拿到边界失效信号
- 及时记录证据，避免测完只剩印象
- 及时判断这条线该 deepen、切线还是停止
- 最后留下能进报告的材料，而不是一堆零散猜测

## Preflight：开测前必须先过这 6 个门

### 1. 授权与范围门

先确认：
- 当前任务是否明确属于授权 SRC / 众测 / bounty / 防御研究场景
- 当前目标、域名、资产、产品线是否在范围内
- 当前项目是否有禁止项：DoS、暴力破解、批量骚扰、社工、真实用户影响、付款影响、邮件/SMS轰炸、第三方越权等

如果授权、范围、禁止项不清楚，先停，回到 `src-workflow` 或让用户补足。

### 2. 资产与入口门

先确认：
- 测的是哪个 asset / 子域 / app / 页面 / API / 管理后台
- 这个入口属于哪个业务面：登录、邀请、导出、上传、GraphQL、支付、客服后台等
- 是否已经有本地资料、历史记录、Quake 结果、公开报告、源码泄露、抓包记录可复用

### 3. 角色与前置条件门

先确认：
- 当前测试需要单账号、双账号、双角色还是管理角色
- 是否依赖特定对象状态：已邀请、已导出、已上传、已退款、已审批、已缓存
- 是否需要浏览器登录态、移动端态、企业租户态、嵌入式 iframe 态

### 4. 影响边界门

先确认：
- 允许做到什么程度才算安全验证
- 这条线是否能只用低影响动作先证明边界失效
- 如果进一步验证可能碰到真实资金、真实订单、真实用户数据、真实第三方资源，优先停在边界证明，不要先冲最终利用

### 5. 工具门

优先这样选工具：
- 范围、规则、资产、活动整理 → `src-workflow`
- 本地资料、历史报告、缓存正文、分析表 → `Read` / `Grep` / `Glob`
- 被动或低影响 HTTP 验证 → `Bash` 跑 curl / 脚本
- 需要登录态、真实页面消费面、iframe、postMessage、后台页面流转 → `web-access`

不要为了“更像实战”就一上来做高风险动作。先选择能最小代价证明边界问题的方式。

### 6. 记录门

在真正开测前，先决定证据要落到哪里。每一条主线至少要能留下：
- asset / URL / endpoint
- 角色和前置条件
- 请求/响应或页面证据
- 观察到的异常
- 初步影响判断

如果没有证据计划，就很容易测完无法成稿。

## Hunt loop：默认执行循环

每进入一条主线，都按下面 6 步走，不要跳步。

### 1. 选主线

优先把目标归入这些高价值主线之一：
1. 认证与账户恢复链
2. 对象级授权 / API / GraphQL 边界
3. 上传 / 导入 / 渲染 / 解析链
4. 缓存 / CDN / 代理 / 网关链
5. 第三方资产 / 子域 / CI / 包管理 / 供应链
6. 业务逻辑与状态机
7. 文件 / 路径 / 对象引用
8. 管理后台 / 客服后台 / 内部消费面板

如果一个信号同时落在两条线，优先跟更靠近高权限消费面或高价值终局的那条线。

### 2. 先做低影响验证

每条线先找 **最低成本、最低影响、最能证明边界失效** 的动作，不要一上来追最终利用。

优先证明：
- 对象边界错了
- 状态迁移乱了
- 同一对象可经另一条路径拿到
- 低权限输入能流向高权限消费面
- 多层解释不一致
- token / session / 绑定关系错了

### 3. 立即留证

一旦出现异常，马上记录：
- 测试时间、asset、页面/API、角色
- 请求前状态 vs 请求后状态
- 预期行为 vs 实际行为
- 最小复现步骤
- 还能不能稳定复现

不要等到“测完再整理”。

### 4. 判断是否值得 deepen

只有在出现下面这些信号时才继续深挖：
- 边界失效可稳定复现
- 能明确指向更高价值角色 / 更高价值对象 / 更高价值消费面
- 已经能从单点扩展到列表、导出、批处理、后台、协作、登录资产、租户边界
- 只差一两个可控条件就能形成报告级影响

如果只有弱猜测、一次性抖动、解释不唯一、或需要高风险动作才能继续，先停或切线。

### 5. 决定继续 / 切线 / 停止

- **继续**：已有稳定信号，且下一步仍可低影响推进
- **切线**：这条线有弱信号，但复现成本高、依赖苛刻、价值不如另一条线
- **停止**：未授权、疑似越界、风险过高、只有猜测无证据、或已足够形成报告不必再扩大影响

### 6. 整理 report-ready 材料

每一轮结束都问自己：
- 现在是否已经有一版可交给用户继续写报告的材料
- 还差的是“边界证明”还是“影响证明”
- 如果现在停，用户能否靠现有证据继续推进

## User-facing output contract：对用户输出时默认用这组字段

当任务是在让 agent 选线、安排验证、说明证据、判断是否继续时，默认不要写成长篇散文；优先用下面这组**固定字段名**输出，便于继续执行、留证和 benchmark 区分：

- `scope_gate`：范围、资产、禁止项、允许动作
- `roles`：需要的账号 / 角色 / 组织关系
- `chosen_line`：本轮唯一主线；不要平铺多个主线
- `local_hits`：2-4 个与主线直接相关的本地高频入口，尽量写精确词组
- `first_actions`：第一批最小动作，按顺序列
- `evidence`：这一轮必须留下的请求/响应、截图、状态对照、对象映射等材料
- `continue_if`：什么信号出现后值得继续 deepen
- `stop_or_switch_if`：什么情况下停止或切到次优主线
- `report_artifacts`：这一轮结束后至少应能交出的成稿材料

使用这些字段时，遵守下面 6 条：
1. 这些字段名默认按**字面小写**输出，不要随意改名成近义词
2. `chosen_line` 只能有一条主线；备选线只放进 `stop_or_switch_if`
3. `local_hits` 不要写大类名，优先写精确入口，如 `node(id:)`、`nodes`、`search/export/preview`、`stale confirmation link`、`support/admin viewer`、`cancel-one-keep-many`
4. `evidence` 和 `report_artifacts` 里必须落到客观材料，不要只写“留证据”或“整理报告”
5. `continue_if` 和 `stop_or_switch_if` 要写**具体判据**，不要只写“有信号就继续”或“风险高就停止”
6. 如果某个字段当前缺前置条件，也要显式写出来，不要直接省略该字段

默认模板可直接这样用：

```text
scope_gate
- ...

roles
- ...

chosen_line
- ...

local_hits
- ...
- ...

first_actions
1. ...
2. ...

evidence
- ...

continue_if
- ...

stop_or_switch_if
- ...

report_artifacts
- ...
```

如果用户只问某一条子线（例如 auth、GraphQL、upload、race），也尽量保留这组字段；缺项时写明缺什么，不要把信息埋进散文里。

默认不要这样输出：
- 先写一大段方法论，再零散补几个动作
- 同时推荐两三条“都值得打”的主线，却没有唯一 `chosen_line`
- 在 `local_hits` 里写“认证问题 / GraphQL 风险 / 上传问题”这种大类名
- 在 `evidence` 里只写“抓包、截图、留证”，不写具体对象或材料

如果你发现自己开始这样写，立刻收回到上面的固定模板。

## Evidence contract：每条线至少要留下这些材料

### 必留字段
- `asset`：域名 / 页面 / API / app / 功能点
- `surface`：登录、GraphQL、导出、上传、后台、iframe、缓存等
- `roles`：单账号 / 双账号 / 双角色 / 管理角色
- `preconditions`：对象状态、缓存状态、邀请状态、上传状态、租户状态
- `steps`：最小复现步骤
- `observed`：实际观测到的异常
- `expected`：预期应该怎样
- `impact_path`：为什么它能升级到更高价值影响
- `evidence`：请求/响应、截图、页面文本、导出文件、差异记录
- `confidence`：稳定 / 条件成立 / 需进一步确认

### 证据质量要求
- 尽量保留对照：正常对象 vs 越界对象，普通角色 vs 高价值对象，前后状态对比
- 能用低影响 PoC 证明，就不要做高风险放大
- 如果某一步仍是推测，要显式写“这是推测，不是已证实影响”

## Stop / switch conditions

出现下面情况时，优先停止或切线：
- 授权或范围不清楚
- 继续验证需要 destructive、批量化、真实用户影响或明显越界动作
- 只有一条异常日志或一次性页面波动，无法形成稳定信号
- 解释空间太大，暂时无法证明是边界问题而不是正常业务条件
- 当前线投入继续上升，但已有另一条更值钱、更可复现的线

不要因为“看起来像个洞”就一直硬挖。执行型 skill 的关键是资源分配和停损。

## Deliverables：结束时应该交出什么

默认交付物不是长篇分析，而是可继续推进的 bounty 材料包：
- 当前目标和测试范围
- 已测主线
- 已确认信号 / 已排除信号
- 关键证据位置
- 最小复现步骤
- 初步影响判断
- 还缺什么证据
- 建议下一步：继续 / 切线 / 停止 / 写报告

如果已经足够 report-ready，再补：
- 漏洞标题候选
- 影响摘要
- 复现步骤骨架
- 受影响角色 / 对象 / 边界
- 为什么这是高价值而不是低危原语

## 8 条主线的执行模板

下面不是给用户看的解释，而是 agent 开测时的默认 playbook。

### 1. 认证与账户恢复链

什么时候进入：
- 登录、找回、改绑、邀请、OTP、magic link、OAuth、SSO、MFA、组织切换
- 双身份体系：owner/staff、partner/store、local account/SSO account、普通账号/帮助台账号
- 任何“未验证 -> 已验证”“待确认 -> 已绑定”“旧身份 -> 新身份”的转换点

高频入口：
- 邮箱改绑后旧验证链接仍可用
- 邮箱确认 race、双 tab 并发修改绑定关系
- password reset recipient tampering、数组/对象参数污染收件人
- MFA reset/cancel race、重绑 MFA 后旧恢复流程仍活着
- SSO/helpdesk/第三方身份系统按 email/domain 错绑账号
- 密码重置、MFA 开启、组织切换后旧 session 不失效

优先检查：
- 当前动作是否真的绑定当前用户、当前会话、当前邮箱/手机号、当前身份提供方
- 系统信任的是 `email`、`sub`、`issuer` 还是某个可错绑字段
- 角色切换、组织切换、重置、改绑后旧 token/session 是否继续有效
- 是否存在旧接口、兼容接口、partner/staff 管理接口与主站登录体系并存

第一批低影响动作：
- 改绑后先做 identity-binding matrix，对照 `email`、`sub`、`issuer`、local account id、tenant/org id、session id、refresh token、旧/新验证材料是否仍指向同一主体
- 先检查旧确认链接、旧 session、旧 refresh token 是否仍有效，再比较它们是否仍作用到旧身份或旧组织
- 不触碰真实用户前提下比较同一账号不同身份路径的绑定结果
- 检查 MFA 关闭、重绑 MFA、邀请确认是否要求重新验证
- 对比 local account 与 SSO account 的 merge / convert / upgrade 路径
- 在双 tab / 双会话下测试验证链接、找回链接、2FA reset/cancel 是否相互清理

高价值消费面：
- owner/admin/staff 这类高权限身份
- SSO / helpdesk / support 这些跨系统身份桥
- 恢复页、账号设置页、安全设置页、身份映射后台

证据要点：
- identity-binding matrix：`email`、`sub`、`issuer`、local account id、tenant/org id、session id、refresh token、旧/新验证材料的前后对照
- token/session 是否失效的客观证据
- 绑定关系错位的 request/response 对照
- 不同身份系统返回的 subject/account id 差异

升级路径：
- 邮箱确认或 reset 流程错绑 -> ATO / 租户接管 / 商家接管
- Open Redirect / callback / token 泄露 -> takeover
- SSO/helpdesk 身份错绑 -> 内部工单/支持后台访问
- 旧 session 不失效 -> 绕过安全加固持续接管

弱信号过滤：
- 只有邮件文案或前端展示异常，不代表真正绑定错位
- 只有 token 泄露线索，没有证明 token 真能作用到目标身份
- 只有一次 race，不足以说明稳定状态机缺陷

该停/切线的信号：
- 只有前端展示异常，没有后端身份结果变化
- 需要真实用户交互才能验证且无法安全替代
- 所有关键动作都已重新绑定当前 subject 且旧 session/token 被可靠失效

报告 framing：
- 不要写成“链接还能用”或“token 没过期”，而要写成“安全敏感动作没有绑定正确身份主体/会话状态，导致账号边界失效”。

### 2. 对象级授权 / API / GraphQL 边界

什么时候进入：
- REST、RPC、GraphQL、BFF、search、export、preview、report、team、invite、batch
- 任何一个对象存在多种访问路径：列表、详情、导出、预览、子对象、统计、搜索、GraphQL 节点查询

高频入口：
- GraphQL `node(id:)`、`nodes` vs `edges`
- search / export / preview / connection 这类辅助路径
- 主对象受限，但子对象字段、附件、统计、评论、私有字段没受限
- import / restore / clone 流程里 foreign key poisoning
- 顶层字段被封，嵌套 `attributes` 仍可带入关系对象

优先检查：
- 同一对象是否能通过另一条查询路径拿到
- 列表限制了，详情、导出、统计、附件、子对象字段是否也限制了
- GraphQL 是否存在字段级授权、嵌套对象遍历、alias/batch、隐藏 mutation
- 同一 action 在 REST 与 GraphQL 上的授权是否一致

第一批低影响动作：
- 先给同一对象做 cross-surface object mapping，至少对上 `REST id`、`GraphQL global id`、`node(id:)` / `nodes`、search hit、export row、preview URL、nested child object 里的两个以上表面
- 先做同对象不同访问路径对照
- 先比较普通对象和不该访问对象的最小字段差异
- 先用 search/export/preview/connection 这类低成本路径找错位
- 先试 `node(id:)`、`nodes`、nested child object，不急着扫全 schema
- 对 import/restore 先改关系对象引用，不先改业务字段

高价值消费面：
- export / preview / report / batch
- invite / collaborator / team / tenant admin
- GraphQL 隐藏字段和后台 BFF
- clone/import/restore pipeline

证据要点：
- object mapping：`REST id`、`GraphQL id`、search hit、export row、preview URL、nested child object 之间的对应关系
- 同对象多路径对照
- 主对象和子对象字段差异
- 普通角色 vs 越界对象的响应差异
- restore/import 前后关系对象归属变化

升级路径：
- 单对象读 -> 批量导出 / 批量对象 / 跨租户对象
- 子对象错位 -> 私有评论、附件、报表、内部字段暴露
- import relation poisoning -> 恢复不属于当前用户的关系对象
- 读路径错位 -> 写路径、分享、邀请、后台消费面

弱信号过滤：
- 只有空字段或 null/not null 差异，不一定构成真实越界
- 只能靠大量猜 id 爆破才能推进，优先级应降低
- 只是返回对象存在性差异，尚未拿到边界外数据

该停/切线的信号：
- 只有空字段差异，无法证明真实越界
- 只能靠猜 id 爆破才能推进
- 所有 alternate path 在服务端都复用了相同授权检查

报告 framing：
- 不要写成“某接口没鉴权”，而要写成“同一业务对象在另一条访问路径/恢复路径上未继承主边界，导致对象授权模型失效”。

### 3. 上传 / 导入 / 渲染 / 解析链

什么时候进入：
- 文件上传、头像、附件、导入器、Markdown、SVG、富文本、OCR、PDF/Office 转换
- 客服/审核/后台会查看用户上传内容
- 后台 worker、导入器、预览器、转换器会处理用户可控文件或文本

高频入口：
- 文件名、元数据、alt text、Markdown、SVG、富文本进入后台消费面
- upload -> support/admin/moderation/review 二次查看
- remote attachment / import URL / archive import
- 文档预览器、缩略图器、OCR、Mermaid、Kroki、PDF/Office 转换器
- 导出再导入、模板复制、项目迁移把旧附件与边界一起带走

优先检查：
- 文件名、扩展名、MIME、内容、元数据分别在哪被消费
- 上传后是否存在低权限写入、高权限查看
- 导入/复制是否会把旧对象附件和权限边界一起带走
- 哪些功能实际上在调用隐藏解析器或后台转换器

第一批低影响动作：
- 先用无害内容验证渲染和消费链，不先追危险 payload
- 先把 chain hop 证出来：输入点 -> 存储对象/中间表示 -> preview/parser/import/conversion worker -> support/admin/report/audit consumer
- 先验证不同角色页面是否会再次消费同一输入
- 先看是否存在隐藏解析器被展示功能带出
- 先追“谁会看/谁会解析”，再决定是否继续打 blind XSS / parser
- 对 import 先试 remote URL、archive metadata、copy/import relation，不先追最终 RCE

高价值消费面：
- support / admin / moderation / audit viewers
- import / restore / conversion workers
- document preview / report preview / file rewrite pipeline

证据要点：
- 输入点 -> 存储对象/中间表示 -> 消费点的 chain hop 证据
- 普通查看者 vs 高权限查看者的差异
- 导入/复制前后附件归属变化
- 后台解析或转换痕迹

升级路径：
- 低权限上传 -> 高权限消费面 -> blind XSS / 会话窃取 / 后台动作
- import / converter / preview -> SSRF / parser execution / arbitrary file read
- 导入复制边界错位 -> 读到别人的附件/历史文件

弱信号过滤：
- 只有上传校验绕过，但没有任何二次消费面
- 只有文件被接受，不代表有高价值渲染或后台解析
- 只有“理论 parser”存在，没有任何实际调用证据

该停/切线的信号：
- 只在上传环节有轻微校验异常，但没有实际消费点
- 无法证明任何高权限角色或后台 worker 会接触到该输入

报告 framing：
- 不要写成“上传 XSS”或“SVG 可执行”，而要写成“低权限可控内容流入高权限消费面/后台解析链，导致权限边界后移”。

### 4. 缓存 / CDN / 代理 / 网关链

什么时候进入：
- 登录页、重定向、静态 JS、共享缓存资源、请求走私、多层代理、边缘缓存
- 任何看起来“不是主应用”的 login-adjacent asset、CDN alias、信任子域

高频入口：
- 登录页或登录邻近静态资源
- 302/404/错误页被共享缓存
- secondary domain / asset host / CDN alias 上的 request smuggling
- CSRF token、auth challenge、signin 页面内容与 cache 交叉
- Host header / TE / hop-by-hop header / source-vs-CDN 解释差异

优先检查：
- 哪些资源会跨用户共享缓存
- 登录页依赖哪些静态资源
- CDN、WAF、源站对 URL/header/TE/hop-by-hop header 是否理解一致
- 是否存在“外围域名”但仍承载登录或认证资产信任

第一批低影响动作：
- 先找 shared cache key 和对照对象，不先做复杂利用
- 先打 secondary trusted domain / asset host / CDN alias / login-adjacent asset，不一定从主站开始
- 先看 302/404/错误页/静态资源是否可形成全局异常
- 先比较不同请求形态下返回差异
- 先证明跨用户 cacheability，再追 login asset 影响

高价值消费面：
- signin / reset / payment / auth challenge 页面
- 共用静态 JS、redirector、trusted asset 域
- 后台用户必经页面或认证静态依赖

证据要点：
- 命中缓存的客观证据
- 多层解释差异的 request/response 对照
- secondary trusted domain / login-adjacent asset 与主认证链的关系
- 登录页或认证资产是否受影响

升级路径：
- request smuggling -> cache poisoning -> login/static asset compromise
- cache deception / poisoned redirect -> token/session theft
- auth token/CSRF cache 交叉 -> ATO 或跨用户敏感数据读

弱信号过滤：
- 一次性缓存抖动不等于稳定 poisoning
- 只有完整性异常，不代表已碰到认证资产
- 只是外围域名异常，不代表可作用于主认证链

该停/切线的信号：
- 只有一次性缓存抖动，没有稳定复现
- 无法证明任何共享跨用户或 trusted asset 复用
- 解释差异存在，但不能落到高价值消费面

报告 framing：
- 不要写成“缓存异常”或“TE 解析不同”，而要写成“共享缓存/多层解释差异作用于登录或受信任资产，导致跨用户认证完整性受损”。

### 5. 第三方资产 / 子域 / CI / 包管理 / 供应链

什么时候进入：
- 子域接管、云资源悬挂绑定、公开仓库、内部包名、CI、制品库、暴露面板
- Zendesk/Jira/Confluence/GitHub/Jenkins/Grafana/npm/pip 等外部系统与主业务存在信任桥

高频入口：
- 已释放但仍被信任的子域、bucket、CDN mapping
- 公共仓库中的 API token、CI config、内部 panel URL、internal package name
- internal package name 可被 public registry 占用
- 帮助台 / 工单 / Jira app / 插件通过弱身份条件发 token 或给权限

优先检查：
- 子域是否仍指向已释放资源
- 是否存在可公开注册的内部包名
- 仓库、脚本、构建产物是否泄露 key、token、内部面板、包名、环境信息
- 第三方系统是否按 email/domain 等弱标识信任用户身份

第一批低影响动作：
- 先做被动验证和归属确认
- 先确认资源是否真可接管、包名是否真可占用、面板是否真暴露敏感配置
- 先看第三方 app config / integration endpoint 是否给低权限用户不该拿到的 token
- 不直接做会影响生产的供应链动作

高价值消费面：
- build pipeline / artifact / dependency resolution
- support/helpdesk / Jira / Confluence / integration app
- auth/static-serving trusted subdomain

证据要点：
- 资源归属和释放状态
- 泄露材料截图/文本
- 能否通向内部系统或制品的证据
- 第三方系统 token / app 权限对照

升级路径：
- subdomain/bucket takeover -> auth/static asset abuse / build compromise
- dependency confusion -> developer/build execution
- 第三方 app token leakage -> 内部 issue/helpdesk/Jira 数据与动作

弱信号过滤：
- 只有模糊 banner 或历史残留，没有归属证据
- 只有 repo 里疑似 token，没证明还活着或有价值权限
- 只有旧 DNS 记录，没有可 reclaim 资源

该停/切线的信号：
- 只有模糊 banner 或历史残留，无明确归属和利用路径
- registry/panel/bucket 都不能形成实际信任链或执行链

报告 framing：
- 不要写成“暴露了某个第三方面板”，而要写成“边缘信任组件仍被主系统信任，导致开发链/支持链/认证链被外部接管或越权消费”。

### 6. 业务逻辑与状态机

什么时候进入：
- 邀请、审批、优惠券、退款、提现、余额、订单、工单流转、角色变更、结算
- 任何存在 pending -> active、单次动作、额度/次数、取消/恢复、异步确认的流程

高频入口：
- 优惠券、礼品卡、余额、workspace create、invitation accept、2FA reset、approval/cancel
- cancel 一次却没清理 sibling request
- duplicate redemption、parallel limit bypass、单次动作非原子
- async replay window：检查通过后到异步 worker 真正落库之间仍可重放
- clone/template/import 把不该继承的对象/权限带过去

优先检查：
- 哪些动作本该单次执行，却能重放、乱序、并发或跨对象复用
- 前一步绑定了谁，后一步是否还绑定同一用户/租户/订单/角色
- 异步任务、补偿逻辑、批处理是否会在检查后再次改对象
- cancel / rollback 是否真清理同批其它 pending 操作

第一批低影响动作：
- 先验证状态错位，不先追最终资金或最终业务损失
- 先做单对象、单优惠、单审批的最小复现
- 先用双会话、双端、重放、延迟触发方式验证状态机稳不稳
- 先测 `duplicate redemption`、`parallel limit bypass`、`cancel-one-keep-many`、`async replay window` 这类高频模式
- 先记前态、并发顺序、后态，不接受只看到 UI 抖动就继续 deepen

高价值消费面：
- 金额、额度、订单、审批权、角色、邀请、租户资源
- 任何状态机一旦乱了会让低权限拿到更高价值业务对象

证据要点：
- 状态前后变化
- 是否可重复执行
- 是否可跨对象或跨角色放大
- cancel / replay / parallel request 之间的关联关系

升级路径：
- 单次动作失效 -> 重复领取 / 重复退款 / 重复创建 / 重复审批
- 状态迁移乱序 -> 越过校验、跨对象复用、额度/角色/订单异常放大
- clone/template/import -> 继承不属于当前用户的资源或权限

弱信号过滤：
- 只是 UI 状态混乱，没有后端状态错位
- 只是时序异常，没有实际额度/角色/对象影响
- 只有一次 race 命中，没有稳定复现路径

该停/切线的信号：
- 只是 UI 状态混乱，没有后端状态错位
- 无法从状态异常落到业务对象、额度、角色或订单影响

报告 framing：
- 不要写成“有 race condition”或“可重放”，而要写成“本应单次/有序/绑定前态的业务状态迁移未在服务端保持原子与一致，导致业务边界失效”。

### 7. 文件 / 路径 / 对象引用

什么时候进入：
- 下载、导出、预览、附件、对象存储 key、文件定位、日志文件、模板文件、历史文件
- secret path、tokenized URL、object key、archive entry 被当成授权边界

高频入口：
- `/uploads/<secret>/<file>` 这类 secret path retrieval
- 对象存储 key、导出包、预览链接、历史版本、日志文件
- import/move/migration/copy 里的 file/object reference drift
- zip entry、symlink、template path、bucket/object reference 继承错位

优先检查：
- 文件权限是靠数据库对象控制，还是靠 path/key/filename 这种二级引用控制
- 主对象权限过了，附件、导出包、缩略图、日志、历史版本是否也跟着过
- zip entry、模板路径、对象 key 是否会绕开主对象边界
- secret/path/token 是否只是定位器，不是真授权

第一批低影响动作：
- 先做同对象主文件 vs 附件/预览/导出物对照
- 先做 permission-decay 检查：revoke、move、clone/copy、tenant change、history/version change、export/import round-trip 之后旧 locator/path/key 是否仍可读
- 先看对象引用错位，不先追本地路径极限利用
- 先看导出/复制/模板下载是否带出不该带出的文件
- 先测试 file id/path/key 的组合，而不是只扫 traversal payload

高价值消费面：
- download/export/preview handlers
- import/move/migration jobs
- object store / historical version / logs / templates

证据要点：
- 文件归属与对象归属对照
- revoke / move / clone / tenant change / history/version / round-trip 前后 locator、path、key 的可达性对照
- 主对象与二级引用之间的权限差异
- 导出/预览前后文件范围差异
- locator 和 auth 之间错位的证据

升级路径：
- object reference drift -> 读到别人的附件/历史版本/日志/模板
- traversal / archive trick -> arbitrary file read
- file/object path primitive + import/parser -> 更深层执行或敏感配置读

弱信号过滤：
- 只有文件名猜测空间，没有明确越界结果
- 只有 unguessable secret 看起来弱，但若可复用/可枚举/可继承仍值得继续
- 只有路径异常回显，不代表真实文件边界已破

该停/切线的信号：
- 只有文件名猜测空间，没有明确越界结果
- 所有文件访问最终仍绑定主对象授权，二级引用无法绕开

报告 framing：
- 不要写成“path traversal”或“secret 泄露”，而要写成“文件/对象引用被当成授权依据，导致对象边界外文件可被解析、导出或读取”。

### 8. 管理后台 / 客服后台 / 内部消费面板

什么时候进入：
- 审核台、客服台、报表后台、申诉单、工单、运营台、内部 BFF、批处理台、审计页
- 任何低权限输入最终会进入高权限人员日常工作流的地方

高频入口：
- support/admin/moderation/export/audit 这类内部高权限消费者
- 工单、聊天、申诉、备注、附件、用户名、组织名、报告内容进入后台消费面
- 前台被拦，后台 search/export/reporting/internal API 仍可调
- blind XSS、批量导出、内部接口绕权都常发生在这里

优先检查：
- 低权限输入会不会在高权限消费面被查看、导出、审核、批处理
- 前台动作受限后，后台接口或内部任务接口是否仍可直接调用
- 搜索、导出、报表、审计接口是否拥有比前台更松的边界
- 是否存在 helpdesk / support / internal tool 与主站授权模型不一致

第一批低影响动作：
- 先找普通用户可控输入进入后台的路径
- 先把 chain hop 证出来：输入点 -> 存储对象/队列/预览 -> support/admin/export/report/audit consumer
- 先找后台查询/导出面和前台边界的不一致
- 先证明高权限消费面存在，不急着打磨 payload
- 先看 export/report/audit/preview，比直接打 admin action 更稳

高价值消费面：
- support、ops、admin、moderation、audit、reporting
- 批处理工具、内部 BFF、导出中心、报表中心

证据要点：
- 输入点 -> 存储对象/队列/预览 -> 后台消费点的 chain hop 证据
- 前台接口 vs 后台接口边界差异
- 高权限角色确实会碰到该对象/输入的证据
- 后台导出/报表可读范围与前台差异

升级路径：
- 低权限输入 -> blind XSS -> 内部高权限动作
- 后台 export/reporting -> 批量数据读取
- support/internal API gap -> 越权读写或内部角色滥用

弱信号过滤：
- 只知道后台存在，但没有任何证据说明目标输入会流进去
- 只有“理论 admin 会看到”，没有消费路径证据
- 只有后台页面标题、路由，不代表有边界错位

该停/切线的信号：
- 后台消费面存在但无法证明任何高权限角色会接触到目标输入
- 找不到任何前台/后台边界不一致或消费链证据

报告 framing：
- 不要写成“后台有 XSS”或“后台接口没鉴权”，而要写成“低权限可控输入/对象被高权限内部消费者处理，导致消费面权限明显高于输入面权限”。

## 选线 heuristics

### 漏洞类型如何映射成行动

- **XSS** → 先找高权限查看者、二次渲染、导入/审核/客服消费面
- **IDOR / 越权** → 先找同对象多路径、主对象和子对象、列表与导出
- **SSRF** → 先找服务端代发请求点、内部面、能否控 method/header/body
- **SQLi / SSTI / RCE / XXE** → 先找隐藏解析器、模板/转换链、低权限触发高权限执行面
- **CSRF** → 先找高价值已登录动作，不停在 token 有无
- **JWT / Session / Token** → 先找绑定关系、失效逻辑、组织/角色切换后的残留会话
- **CORS / postMessage** → 先找浏览器信任边界误判、后台 iframe、嵌入页面
- **Race Condition** → 先找一次性动作、异步任务、双会话可放大的状态迁移
- **Request Smuggling / Web Cache** → 先找共享缓存和多层解释差异，再看是否能碰认证资产

### 哪些终局最值钱

优先考虑是否能通向：
- 账号接管
- 提权 / 后台触达
- 敏感数据读取
- 批量用户 / 批量租户影响
- 供应链 / 开发链影响
- 登录页 / 静态资源 / 缓存层完整性破坏

### 哪些信号更值得继续投入

优先继续：
- 能稳定复现的边界错位
- 能证明高权限消费面存在
- 能从单点扩到列表 / 导出 / 批处理 / 协作 / 后台
- 只差少量补充证据即可成稿
- 命中本地语料里反复出现的高频入口：email verify race、node/nodes、export/preview、import relation、support consumer、login-adjacent asset、cancel-one-keep-many

优先放弃或延后：
- 只有异常提示，没有客观对象差异
- 需要高风险动作才能验证
- 解释空间太大，暂时无法证明安全边界失效
- 不符合本地高频升级路径，只剩单点低价值原语

## 本项目里的可复用资料

如果当前工作目录下存在这些文件，优先读取并引用作为行动依据：
- `E:/src/hackerone-reports-master/SRC_HUNTING_SKILLS.md`
- `E:/src/hackerone-reports-master/REPORT_ACCESS_SUMMARY_TOP100.md`
- `E:/src/hackerone-reports-master/REPORT_CONTENT_SUMMARY_TOP100.md`
- `E:/src/hackerone-reports-master/_analysis_reports_top100.json`
- `E:/src/hackerone-reports-master/REPORT_CONTENT_SUMMARY.md`

这些资料的作用不是让 agent 复述，而是帮助：
- 选主线
- 找高价值消费面
- 借代表案例判断是否值得 deepen
- 补充影响路径和报告表达
- 识别本地高频入口是否已经命中

## 失败模式提醒

出现这些倾向时要主动纠正：
- 只回答“怎么挖”，却不实际推进验证
- 只列 checklist，不做 evidence plan
- 只讲洞名，不讲对象、状态、消费面
- 一上来追最终利用，不先做低影响边界证明
- 明明只有弱信号，却不愿意切线或停止
- 测完没有留下能继续写报告的材料
- 执行框架是对的，但思路密度太稀，看不出来自大量报告蒸馏

## 最后的目标

这个技能的目标不是让 agent 看起来更懂 SRC，而是让 agent 在授权实战里更像一个靠谱的 bounty 执行者：
- 会先确认边界
- 会选更值钱的线
- 会优先命中高频入口
- 会及时留证
- 会控制风险
- 会判断何时继续、何时停
- 会把结果整理成可提交材料
