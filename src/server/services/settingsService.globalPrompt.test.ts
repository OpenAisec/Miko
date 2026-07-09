import { afterEach, describe, expect, it } from 'bun:test'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { setDataDir } from '../../utils/kimoPaths.js'
import { SettingsService } from './settingsService.js'

const tempDirs: string[] = []

async function makeTempDataDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'miko-global-prompt-'))
  tempDirs.push(dir)
  setDataDir(dir)
  return dir
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

describe('SettingsService global prompt', () => {
  it('reads legacy content when MIKO.md does not exist', async () => {
    const dataDir = await makeTempDataDir()
    await writeFile(join(dataDir, 'CLAUDE.md'), 'legacy prompt', 'utf-8')

    const result = await new SettingsService().getGlobalPrompt()

    expect(result).toEqual({
      content: 'legacy prompt',
      path: join(dataDir, 'CLAUDE.md'),
      source: 'legacy',
    })
  })

  it('writes MIKO.md and lets an empty MIKO.md suppress legacy content', async () => {
    const dataDir = await makeTempDataDir()
    await writeFile(join(dataDir, 'CLAUDE.md'), 'legacy prompt', 'utf-8')
    const service = new SettingsService()

    await service.updateGlobalPrompt('')

    expect(await readFile(join(dataDir, 'MIKO.md'), 'utf-8')).toBe('')
    expect(await service.getGlobalPrompt()).toEqual({
      content: '',
      path: join(dataDir, 'MIKO.md'),
      source: 'miko',
    })
  })
})
