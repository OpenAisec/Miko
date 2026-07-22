import { afterEach, describe, expect, it } from 'bun:test'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { runWithCwdOverride } from '../../utils/cwd.js'
import { setDataDir } from '../../utils/kimoPaths.js'
import {
  addMcpConfig,
  getMcpConfigsByScope,
  getManualMcpFilePath,
} from './config.js'

const tempDirs: string[] = []

async function makeTempRoots(): Promise<{ dataDir: string; cwd: string }> {
  const root = await mkdtemp(join(tmpdir(), 'miko-mcp-config-'))
  const dataDir = join(root, 'data')
  const cwd = join(root, 'project')
  tempDirs.push(root)
  setDataDir(dataDir)
  await mkdir(dataDir, { recursive: true })
  await mkdir(cwd, { recursive: true })
  return { dataDir, cwd }
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map(dir => rm(dir, { recursive: true, force: true })))
})

describe('MCP config data path', () => {
  it('loads manual MCP servers from data/mcp.json instead of cwd .mcp.json', async () => {
    const { dataDir, cwd } = await makeTempRoots()
    await writeFile(
      join(dataDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          dataServer: { type: 'stdio', command: 'node', args: ['data.js'] },
        },
      }),
      'utf-8',
    )
    await writeFile(
      join(cwd, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          legacyServer: { type: 'stdio', command: 'node', args: ['legacy.js'] },
        },
      }),
      'utf-8',
    )

    const { servers } = runWithCwdOverride(cwd, () => getMcpConfigsByScope('project'))

    expect(Object.keys(servers)).toEqual(['dataServer'])
    expect(servers.dataServer?.command).toBe('node')
  })

  it('writes new project-scope MCP servers to data/mcp.json', async () => {
    const { cwd } = await makeTempRoots()

    await runWithCwdOverride(cwd, () =>
      addMcpConfig(
        'newServer',
        { type: 'stdio', command: 'node', args: ['server.js'] },
        'project',
      ),
    )

    const content = JSON.parse(await readFile(getManualMcpFilePath(), 'utf-8'))
    expect(content.mcpServers.newServer).toEqual({
      type: 'stdio',
      command: 'node',
      args: ['server.js'],
    })
    await expect(readFile(join(cwd, '.mcp.json'), 'utf-8')).rejects.toThrow()
  })
})
