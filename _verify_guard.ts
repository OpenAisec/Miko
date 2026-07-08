// 一次性验证守卫：直接调 AgentService.deleteAgent，建临时 dummy 文件试删。不碰 server、不碰真实 agent。
import { AgentService } from './src/server/services/agentService.js'
import { isProtectedAgent } from './src/server/services/protectedResources.js'
import { getDataDir } from './src/utils/kimoPaths.js'
import { promises as fs } from 'node:fs'
import path from 'node:path'

const svc = new AgentService()
const dir = path.join(getDataDir(), 'agents')
const PROTECTED = '__probe_protected__'   // 已加入 PROTECTED_AGENTS
const NORMAL = '__probe_normal_xyz__'     // 不在名单，应可正常删

const pFile = path.join(dir, `${PROTECTED}.md`)
const nFile = path.join(dir, `${NORMAL}.md`)
const dummy = '---\nname: probe\ndescription: throwaway probe\n---\nbody\n'

await fs.mkdir(dir, { recursive: true })
await fs.writeFile(pFile, dummy, 'utf-8')
await fs.writeFile(nFile, dummy, 'utf-8')

console.log('isProtectedAgent(probe)  =', isProtectedAgent(PROTECTED), '(期望 true)')
console.log('isProtectedAgent(normal) =', isProtectedAgent(NORMAL), '(期望 false)')

// 1) 试删受保护的 → 期望抛错、文件还在
let blocked = false
try { await svc.deleteAgent(PROTECTED) } catch (e: any) { blocked = true; console.log('删受保护 → 抛错:', e?.message || e) }
const pStillThere = await fs.access(pFile).then(() => true).catch(() => false)
console.log('受保护：被拦=' + blocked + '，文件仍在=' + pStillThere, (blocked && pStillThere) ? '✓ PASS' : '✗ FAIL')

// 2) 试删普通的 → 期望成功删除
let normalDeleted = false
try { await svc.deleteAgent(NORMAL); normalDeleted = true } catch (e: any) { console.log('删普通 → 意外抛错:', e?.message || e) }
const nGone = await fs.access(nFile).then(() => false).catch(() => true)
console.log('普通：删除成功=' + normalDeleted + '，文件已无=' + nGone, (normalDeleted && nGone) ? '✓ PASS' : '✗ FAIL')

// 清理：受保护探针文件守卫删不掉，手动清
await fs.rm(pFile, { force: true })
await fs.rm(nFile, { force: true })
console.log('清理完成')
