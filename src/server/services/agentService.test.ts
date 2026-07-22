import { afterEach, describe, expect, it } from 'bun:test'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { setDataDir } from '../../utils/kimoPaths.js'
import {
  clearAgentDefinitionsCache,
  getAgentDefinitionsWithOverrides,
} from '../../tools/AgentTool/loadAgentsDir.js'
import { AgentService } from './agentService.js'

const tempDirs: string[] = []

async function makeTempDataDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'miko-agent-service-'))
  tempDirs.push(dir)
  setDataDir(dir)
  return dir
}

afterEach(async () => {
  clearAgentDefinitionsCache()
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

describe('AgentService', () => {
  it('ignores legacy yaml files when creating agents', async () => {
    const dataDir = await makeTempDataDir()
    const agentsDir = join(dataDir, 'agents')
    await mkdir(agentsDir, { recursive: true })
    await writeFile(
      join(agentsDir, 'test.yaml'),
      'name: test\ndescription: legacy yaml\nsystemPrompt: old\n',
      'utf-8',
    )

    const service = new AgentService()
    await service.createAgent({
      name: 'test',
      description: 'new md agent',
      systemPrompt: 'new prompt',
    })

    const content = await readFile(join(agentsDir, 'test.md'), 'utf-8')
    expect(content).toContain('name: test')
    expect(content).toContain('new prompt')
    expect(await service.listAgents()).toEqual([
      {
        name: 'test',
        description: 'new md agent',
        systemPrompt: 'new prompt',
        model: undefined,
        tools: undefined,
        skills: undefined,
        mcpServers: undefined,
        color: undefined,
      },
    ])
  })

  it('rejects invalid names instead of normalizing them', async () => {
    await makeTempDataDir()
    const service = new AgentService()

    await expect(
      service.createAgent({
        name: 'new agent',
        description: 'invalid',
        systemPrompt: 'prompt',
      }),
    ).rejects.toThrow('Agent name must start with a letter or number')
  })

  it('requires a description when creating agents', async () => {
    await makeTempDataDir()
    const service = new AgentService()

    await expect(
      service.createAgent({
        name: 'missing-description',
        description: '   ',
        systemPrompt: 'prompt',
      }),
    ).rejects.toThrow('Agent description is required')
  })

  it('requires a system prompt when creating agents', async () => {
    await makeTempDataDir()
    const service = new AgentService()

    await expect(
      service.createAgent({
        name: 'missing-prompt',
        description: 'description',
        systemPrompt: '   ',
      }),
    ).rejects.toThrow('Agent system prompt is required')
  })

  it('writes markdown agents that are visible to the runtime loader', async () => {
    const dataDir = await makeTempDataDir()
    const service = new AgentService()

    await service.createAgent({
      name: 'fresh-agent',
      description: 'Fresh test agent',
      systemPrompt: 'Respond as the fresh test agent.',
    })
    clearAgentDefinitionsCache()

    const { activeAgents } = await getAgentDefinitionsWithOverrides(dataDir)
    const agent = activeAgents.find(agent => agent.agentType === 'fresh-agent')

    expect(agent).toBeDefined()
    expect(agent?.whenToUse).toBe('Fresh test agent')
    expect(agent?.getSystemPrompt()).toBe('Respond as the fresh test agent.')
  })

  it('treats case-only name differences as existing agents', async () => {
    const dataDir = await makeTempDataDir()
    const agentsDir = join(dataDir, 'agents')
    await mkdir(agentsDir, { recursive: true })
    await writeFile(
      join(agentsDir, 'FreshAgent.md'),
      '---\nname: FreshAgent\ndescription: existing\n---\n\nprompt\n',
      'utf-8',
    )

    const service = new AgentService()
    await expect(
      service.createAgent({
        name: 'freshagent',
        description: 'duplicate',
        systemPrompt: 'prompt',
      }),
    ).rejects.toThrow('Agent already exists: freshagent')
  })
})
