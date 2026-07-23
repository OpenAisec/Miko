/**
 * 受保护的内置资源名单 —— 用户不可删除（A 档保护）。
 *
 * 思路（照 securityProjectService 的 BUILTIN_CATEGORIES 范本）：内置随平台分发的核心
 * 能力登记在这里，删除入口前置守卫命中即拒；用户自建的不在此列，可正常增删。
 * 名单是**代码常量**（不是配置文件）—— 常量本身改不到、删不掉，比放 data 里更硬。
 *
 * 扩展点：后续新增内置 agent / skill / mcp，只在对应数组里加名字即可，删除逻辑无需再动。
 *
 * 边界（诚实说明）：守卫挡的是 UI 删除按钮 + 删除 API；挡不住手动 rm / 清空 data 目录。
 * 要物理防删（清 data 也在）需把核心能力随包发到 data 之外的只读区，那是另一档（C），本档不做。
 */

/** 内置 Agent：探索架构命脉 + 上游内置 agent。用户垃圾（test1/test2 之类）不在此列、可删。 */
export const PROTECTED_AGENTS: readonly string[] = [
  '__probe_protected__', // 验证探针，验证完即移除
  'security-explore', // 探索模式的执行子 agent，整个路 A 架构的命脉
  'Explore',
  'Plan',
  'general-purpose',
  'verification',
  'skill-creator-agent',
  'skill-editor',
  'statusline-setup',
]

/**
 * 内置 Skill：随包预置到 data/skills 的 skill。用户自加的领域 skill 不在此列、可删。
 *
 * 注意：当前打包策略会把内置 skill 和运行期用户 skill 放在同一个 data/skills 目录，
 * 因此这里不能用“目录级只读”粗暴判断，只能按内置名称登记。
 */
export const PROTECTED_SKILLS: readonly string[] = [
  'android-reverse-engineering',
  'audit-skills',
  'browser-use',
  'bypassav-skills',
  'cloud',
  'code-audit',
  'code-audit-workspace',
  'code-review-skill',
  'ctf-ai-ml',
  'ctf-crypto',
  'ctf-forensics',
  'ctf-malware',
  'ctf-misc',
  'ctf-osint',
  'ctf-pwn',
  'ctf-reverse',
  'ctf-web',
  'ctf-writeup',
  'game-hacking',
  'libtv-cli',
  'medical-cybersecurity-report',
  'open-source',
  'pentest-api',
  'pentest-js',
  'pentest-login',
  'pentest-main',
  'pentest-recon',
  'pentest-rules',
  'pentest-tools',
  'pentest-vulns',
  'php-deep-audit-workspace',
  'qa',
  'remote-browser',
  'rev-dex-dumper',
  'rev-frida',
  'rev-idapython',
  'rev-ios-dump',
  'rev-struct',
  'rev-symbol',
  'rev-u3d-dump',
  'rev-unicorn-debug',
  'reverse-engineering',
  'shellcode-loader',
  'skill-creator',
  'solve-challenge',
  'web-access',
  'threat-modeling',
  'x402',
]

/**
 * 内置 MCP：当前为空 —— board-mcp / catalog-mcp 都是会话启动时 --mcp-config 注入式拉起，
 * 不落持久配置、不在可删注册表，故天然安全、无需登记。
 * 这是**备用占位**：将来若把某个内置 MCP 预置进 .mcp.json/settings（开箱即用、随包发），
 * 在此登记其名字即可立即受保护，删除守卫已就位、无需再改。
 */
export const PROTECTED_MCPS: readonly string[] = []

/**
 * 内置工具（台账，data/tools/*.yaml）：随平台分发的核心安全工具，用户不可删。
 * 当前为空 —— 待 CSAI 89 工具迁入并标 builtin:true 后，把内置工具 id 登记于此。
 * 用户自加的工具不在此列、可正常删除。删除守卫（catalog.ts DELETE）已就位。
 */
export const PROTECTED_TOOLS: readonly string[] = []

/** 大小写不敏感匹配，避免 explore/Explore 之类的平凡绕过。 */
function includesCI(list: readonly string[], name: string): boolean {
  const lower = name.toLowerCase()
  return list.some((n) => n.toLowerCase() === lower)
}

export function isProtectedAgent(name: string): boolean {
  return includesCI(PROTECTED_AGENTS, name)
}

export function isProtectedSkill(name: string): boolean {
  return includesCI(PROTECTED_SKILLS, name)
}

export function isProtectedMcp(name: string): boolean {
  return includesCI(PROTECTED_MCPS, name)
}

export function isProtectedTool(name: string): boolean {
  return includesCI(PROTECTED_TOOLS, name)
}
