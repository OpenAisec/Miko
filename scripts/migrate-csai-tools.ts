/**
 * 迁移脚本：CyberStrikeAI 的 tools/*.yaml → kimo 工具台账 data/tools/*.yaml
 *
 * 见 [[工具生态-工具清单逐项归类]]：89 个工具，迁 84（跳过 5 个 utility）。
 * 归类映射逐项内嵌（已校验合计 84）。两种工具形态分别处理：
 *   - 真二进制（command=sqlmap/ghidra…）：bin = command，which(bin) 探 PATH。
 *   - python3/sh 内联脚本（fofa/metasploit/impacket…，CSAI 运行时胶水）：bin = id 兜底；
 *     已知 API 类（fofa/shodan/quake/zoomeye/dnslog，需 API key、无本地二进制）留空 bin。
 *
 * 用法：bun run scripts/migrate-csai-tools.ts [--only binary,web] [--dry]
 *   --only  只迁指定分类（逗号分隔），验证用；缺省全迁。
 *   --dry   只打印不写盘。
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { parseYaml } from '../src/utils/yaml.js'

const CSAI_TOOLS_DIR = 'D:\\code\\agent\\miko\\cank\\CyberStrikeAI-1.6.39\\tools'
const OUT_DIR = path.resolve(import.meta.dir, '..', 'data', 'tools')

/** id → category（逐项归类文档，已校验 84 项；不在此表 = 跳过）。 */
const CATEGORY: Record<string, string> = {
  // binary (14)
  angr: 'binary', checksec: 'binary', gdb: 'binary', ghidra: 'binary', 'libc-database': 'binary',
  objdump: 'binary', 'one-gadget': 'binary', pwninit: 'binary', pwntools: 'binary', radare2: 'binary',
  ropgadget: 'binary', ropper: 'binary', strings: 'binary', xxd: 'binary',
  // web (24)
  'api-schema-analyzer': 'web', arjun: 'web', dalfox: 'web', dirsearch: 'web', dnslog: 'web',
  dotdotpwn: 'web', feroxbuster: 'web', ffuf: 'web', gobuster: 'web', 'graphql-scanner': 'web',
  hashpump: 'web', 'http-framework-test': 'web', jaeles: 'web', 'jwt-analyzer': 'web', katana: 'web',
  nikto: 'web', nuclei: 'web', paramspider: 'web', sqlmap: 'web', wafw00f: 'web',
  wpscan: 'web', x8: 'web', xsser: 'web', zap: 'web',
  // asset (16)
  amass: 'asset', 'arp-scan': 'asset', dnsenum: 'asset', fierce: 'asset', fofa_search: 'asset',
  fscan: 'asset', gau: 'asset', masscan: 'asset', nbtscan: 'asset', nmap: 'asset',
  quake_search: 'asset', rustscan: 'asset', shodan_search: 'asset', subfinder: 'asset',
  waybackurls: 'asset', zoomeye_search: 'asset',
  // redteam (13)
  bloodhound: 'redteam', 'enum4linux-ng': 'redteam', hashcat: 'redteam', hydra: 'redteam',
  impacket: 'redteam', john: 'redteam', linpeas: 'redteam', metasploit: 'redteam', msfvenom: 'redteam',
  netexec: 'redteam', responder: 'redteam', rpcclient: 'redteam', smbmap: 'redteam',
  // cloud (11)
  checkov: 'cloud', clair: 'cloud', cloudmapper: 'cloud', falco: 'cloud', 'kube-bench': 'cloud',
  'kube-hunter': 'cloud', pacu: 'cloud', prowler: 'cloud', 'scout-suite': 'cloud', terrascan: 'cloud',
  trivy: 'cloud',
  // forensics (6)
  binwalk: 'forensics', exiftool: 'forensics', foremost: 'forensics', steghide: 'forensics',
  volatility3: 'forensics', zsteg: 'forensics',
}

/** 跳过的 5 个 utility（与 kimo 既有 Bash/执行原语重叠，或用途不明）。 */
const SKIP = new Set(['exec', 'execute-python-script', 'install-python-package', 'query-execution-result', 'lightx'])

/** API 搜索类：无本地二进制（需 API key），bin 留空、状态恒未知。 */
const NO_BIN = new Set(['fofa_search', 'shodan_search', 'quake_search', 'zoomeye_search', 'dnslog'])

/** command 是脚本宿主、非真二进制。 */
const SCRIPT_HOSTS = new Set(['python3', 'python', 'sh', '/bin/bash', 'bash'])

type CsaiTool = {
  name?: string
  command?: string
  short_description?: string
  description?: string
  parameters?: Array<{ name?: string; flag?: string; required?: boolean; format?: string }>
}

/** 把 CSAI parameters 折叠成一句起手式 usage（required 优先，列名+flag）。 */
function foldUsage(bin: string, params: CsaiTool['parameters']): string {
  if (!params || params.length === 0) return bin
  const parts = params
    .filter((p) => p.name)
    .map((p) => {
      const ph = `<${p.name}>`
      const seg = p.flag ? `${p.flag} ${ph}` : ph
      return p.required ? seg : `[${seg}]`
    })
  return `${bin} ${parts.join(' ')}`.trim()
}

/** 生成我们的 yaml 文本（手写而非 stringify，控制字段顺序 + 值带引号防 ... 坑）。 */
function emitYaml(t: {
  id: string; category: string; name: string; short: string; description: string
  invoke: string; bin?: string; usage: string; mcpServer?: string
}): string {
  const q = (s: string) => `'${String(s).replace(/'/g, "''")}'`
  const lines = [
    `id: ${t.id}`,
    `category: ${t.category}`,
    `name: ${q(t.name)}`,
    `short_description: ${q(t.short)}`,
    'description: |',
    ...t.description.split('\n').map((l) => `  ${l}`),
    `invoke: ${t.invoke}`,
  ]
  if (t.bin) lines.push(`bin: ${q(t.bin)}`)
  if (t.mcpServer) lines.push(`mcpServer: ${t.mcpServer}`)
  lines.push(`usage: ${q(t.usage)}`)
  lines.push('builtin: true')
  return lines.join('\n') + '\n'
}

async function main() {
  const argv = process.argv.slice(2)
  const dry = argv.includes('--dry')
  const onlyIdx = argv.indexOf('--only')
  const only = onlyIdx >= 0 ? new Set(argv[onlyIdx + 1]?.split(',') ?? []) : null

  const files = (await fs.readdir(CSAI_TOOLS_DIR)).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
  if (!dry) await fs.mkdir(OUT_DIR, { recursive: true })

  let migrated = 0, skipped = 0
  const byCat: Record<string, number> = {}

  for (const file of files) {
    const id = file.replace(/\.ya?ml$/, '')
    if (SKIP.has(id)) { skipped++; continue }
    const category = CATEGORY[id]
    if (!category) { console.warn(`[migrate] no category for ${id}, skipping`); skipped++; continue }
    if (only && !only.has(category)) continue

    let raw: CsaiTool
    try {
      const parsed = parseYaml(await fs.readFile(path.join(CSAI_TOOLS_DIR, file), 'utf-8'))
      raw = (Array.isArray(parsed) ? parsed[0] : parsed) as CsaiTool
    } catch (err) {
      console.warn(`[migrate] parse fail ${file}: ${err instanceof Error ? err.message : String(err)}`)
      skipped++; continue
    }

    const command = (raw.command ?? '').trim()
    const isScript = SCRIPT_HOSTS.has(command)
    // bin：真二进制用 command；脚本宿主类用 id 兜底；API 类留空。
    const bin = NO_BIN.has(id) ? undefined : isScript ? id : (command || id)
    const short = raw.short_description?.trim() || (raw.description?.split('\n')[0]?.trim() ?? id)
    const description = (raw.description?.trim() || short)
    const usage = isScript
      ? `（CSAI 封装的${command}脚本工具，经 Bash 调用；详见 description）`
      : foldUsage(command || id, raw.parameters)

    const yaml = emitYaml({
      id, category, name: raw.name?.trim() || id, short, description,
      invoke: 'cli', bin, usage,
    })

    if (dry) {
      console.log(`--- ${id} (${category})${bin ? '' : ' [no-bin]'} ---`)
    } else {
      await fs.writeFile(path.join(OUT_DIR, `${id}.yaml`), yaml, 'utf-8')
    }
    migrated++
    byCat[category] = (byCat[category] ?? 0) + 1
  }

  console.log(`\n[migrate] ${dry ? 'DRY ' : ''}done: migrated=${migrated} skipped=${skipped}`)
  console.log('[migrate] by category:', JSON.stringify(byCat))
}

main().catch((err) => {
  console.error('[migrate] fatal:', err)
  process.exit(1)
})
