import * as fs from 'fs/promises'
import * as path from 'path'
import YAML from 'yaml'
import { getAgentsDir } from '../../utils/kimoPaths.js'
import { ApiError } from '../middleware/errorHandler.js'
import { isProtectedAgent } from './protectedResources.js'

const AGENT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]*$/
const AGENT_NAME_RULE =
  'Agent name must start with a letter or number and contain only letters, numbers, hyphens, or underscores'
const DESCRIPTION_REQUIRED = 'Agent description is required'
const SYSTEM_PROMPT_REQUIRED = 'Agent system prompt is required'

export type AgentDefinition = {
  name: string
  description?: string
  model?: string
  tools?: string[]
  systemPrompt?: string
  color?: string
  skills?: string[]
  mcpServers?: string[]
}

export class AgentService {
  private getAgentsDir(): string {
    return getAgentsDir()
  }

  async listAgents(): Promise<AgentDefinition[]> {
    const dir = this.getAgentsDir()

    try {
      await fs.access(dir)
    } catch {
      return []
    }

    const entries = await fs.readdir(dir, { withFileTypes: true })
    const agents: AgentDefinition[] = []

    for (const entry of entries) {
      if (!entry.isFile()) continue
      if (path.extname(entry.name) !== '.md') continue

      try {
        const agent = await this.loadAgentFile(path.join(dir, entry.name))
        if (agent) agents.push(agent)
      } catch {
        // Skip invalid agent definitions.
      }
    }

    return agents
  }

  async getAgent(name: string): Promise<AgentDefinition | null> {
    const filePath = await this.findAgentFile(name)
    if (!filePath) return null
    return this.loadAgentFile(filePath)
  }

  async createAgent(agent: AgentDefinition): Promise<void> {
    const name = this.normalizeAgentName(agent.name)
    const description = this.normalizeRequiredText(
      agent.description,
      DESCRIPTION_REQUIRED,
    )
    const systemPrompt = this.normalizeRequiredText(
      agent.systemPrompt,
      SYSTEM_PROMPT_REQUIRED,
    )

    const existing = await this.findAgentFile(name)
    if (existing) {
      throw ApiError.conflict(`Agent already exists: ${name}`)
    }

    const dir = this.getAgentsDir()
    await fs.mkdir(dir, { recursive: true })

    const filePath = path.join(dir, `${name}.md`)
    await this.writeAgentFile(filePath, {
      ...agent,
      name,
      description,
      systemPrompt,
    })
  }

  async updateAgent(
    name: string,
    updates: Partial<AgentDefinition>,
  ): Promise<void> {
    const agentName = this.normalizeAgentName(name)
    const filePath = await this.findAgentFile(agentName)
    if (!filePath) {
      throw ApiError.notFound(`Agent not found: ${agentName}`)
    }

    const current = await this.loadAgentFile(filePath)
    if (!current) {
      throw ApiError.notFound(`Agent not found: ${agentName}`)
    }

    const merged: AgentDefinition = {
      ...current,
      ...updates,
      name: current.name,
      description: this.normalizeRequiredText(
        updates.description ?? current.description,
        DESCRIPTION_REQUIRED,
      ),
      systemPrompt: this.normalizeRequiredText(
        updates.systemPrompt ?? current.systemPrompt,
        SYSTEM_PROMPT_REQUIRED,
      ),
    }
    await this.writeAgentFile(filePath, merged)
  }

  async deleteAgent(name: string): Promise<void> {
    const agentName = this.normalizeAgentName(name)
    if (isProtectedAgent(agentName)) {
      throw ApiError.badRequest(`Protected agent cannot be deleted: ${agentName}`)
    }

    const filePath = await this.findAgentFile(agentName)
    if (!filePath) {
      throw ApiError.notFound(`Agent not found: ${agentName}`)
    }

    await fs.unlink(filePath)
  }

  private async findAgentFile(name: string): Promise<string | null> {
    const dir = this.getAgentsDir()
    const targetName = this.normalizeAgentName(name).toLowerCase()

    let entries: Awaited<ReturnType<typeof fs.readdir>>
    try {
      entries = await fs.readdir(dir, { withFileTypes: true })
    } catch (error) {
      if (isNodeError(error) && error.code === 'ENOENT') return null
      throw error
    }

    for (const entry of entries) {
      if (!entry.isFile()) continue
      if (path.extname(entry.name) !== '.md') continue

      const baseName = path.basename(entry.name, '.md')
      if (baseName.toLowerCase() === targetName) {
        return path.join(dir, entry.name)
      }
    }

    return null
  }

  private async loadAgentFile(
    filePath: string,
  ): Promise<AgentDefinition | null> {
    if (path.extname(filePath) !== '.md') return null

    const raw = await fs.readFile(filePath, 'utf-8')
    return this.parseMarkdownFrontmatter(raw, filePath)
  }

  private parseMarkdownFrontmatter(
    content: string,
    filePath: string,
  ): AgentDefinition | null {
    const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/)
    if (!fmMatch) return null

    const data = YAML.parse(fmMatch[1]) as Record<string, unknown>
    if (!data || typeof data !== 'object') return null

    const body = content.slice(fmMatch[0].length).trim()
    if (body && !data.systemPrompt) {
      data.systemPrompt = body
    }

    return this.toAgentDefinition(data, filePath)
  }

  private toAgentDefinition(
    data: Record<string, unknown>,
    filePath: string,
  ): AgentDefinition {
    const baseName = path.basename(filePath, '.md')
    return {
      name: typeof data.name === 'string' ? data.name : baseName,
      description:
        typeof data.description === 'string' ? data.description : undefined,
      model: typeof data.model === 'string' ? data.model : undefined,
      tools: Array.isArray(data.tools)
        ? (data.tools as string[])
        : undefined,
      skills: Array.isArray(data.skills)
        ? (data.skills as string[])
        : undefined,
      mcpServers: Array.isArray(data.mcpServers)
        ? (data.mcpServers as string[])
        : undefined,
      systemPrompt:
        typeof data.systemPrompt === 'string' ? data.systemPrompt : undefined,
      color: typeof data.color === 'string' ? data.color : undefined,
    }
  }

  private async writeAgentFile(
    filePath: string,
    agent: AgentDefinition,
  ): Promise<void> {
    if (path.extname(filePath) !== '.md') {
      throw ApiError.badRequest('Agent definitions must be Markdown files')
    }

    const data: Record<string, unknown> = { name: agent.name }
    data.description = this.normalizeRequiredText(
      agent.description,
      DESCRIPTION_REQUIRED,
    )
    if (agent.model !== undefined) data.model = agent.model
    if (agent.tools !== undefined) data.tools = agent.tools
    if (agent.color !== undefined) data.color = agent.color
    if (agent.skills !== undefined) data.skills = agent.skills
    if (agent.mcpServers !== undefined) data.mcpServers = agent.mcpServers

    const yamlStr = YAML.stringify(data)
    let content = `---\n${yamlStr}---\n`
    content += `\n${this.normalizeRequiredText(agent.systemPrompt, SYSTEM_PROMPT_REQUIRED)}\n`
    await fs.writeFile(filePath, content, 'utf-8')
  }

  private normalizeAgentName(name: string): string {
    const trimmed = name?.trim() ?? ''
    if (!trimmed) {
      throw ApiError.badRequest('Agent name is required')
    }
    if (!AGENT_NAME_PATTERN.test(trimmed)) {
      throw ApiError.badRequest(AGENT_NAME_RULE)
    }
    return trimmed
  }

  private normalizeRequiredText(value: string | undefined, message: string): string {
    const trimmed = value?.trim() ?? ''
    if (!trimmed) {
      throw ApiError.badRequest(message)
    }
    return trimmed
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error
}
