import { afterEach, describe, expect, it } from 'bun:test'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { setOriginalCwd } from '../bootstrap/state.js'
import { getMemoryFiles } from './claudemd.js'
import { setDataDir } from './kimoPaths.js'

const tempDirs: string[] = []

async function makeTempRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'miko-memory-files-'))
  tempDirs.push(dir)
  return dir
}

afterEach(async () => {
  getMemoryFiles.cache.clear?.()
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

describe('Miko memory files', () => {
  it('loads MIKO.md instead of same-scope legacy CLAUDE.md', async () => {
    const root = await makeTempRoot()
    const dataDir = join(root, 'data')
    const projectDir = join(root, 'project')
    await mkdir(dataDir, { recursive: true })
    await mkdir(projectDir, { recursive: true })
    await writeFile(join(projectDir, 'MIKO.md'), 'new project prompt', 'utf-8')
    await writeFile(join(projectDir, 'CLAUDE.md'), 'legacy project prompt', 'utf-8')
    setDataDir(dataDir)
    setOriginalCwd(projectDir)
    getMemoryFiles.cache.clear?.()

    const files = await getMemoryFiles()
    const contents = files.map((file) => file.content)

    expect(contents).toContain('new project prompt')
    expect(contents).not.toContain('legacy project prompt')
  })
})
