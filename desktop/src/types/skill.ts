export type SkillSource = 'project' | 'plugin' | 'mcp' | 'bundled' | 'user'

export type SkillMeta = {
  name: string
  displayName?: string
  description: string
  source: SkillSource
  userInvocable: boolean
  version?: string
  contentLength: number
  hasDirectory: boolean
  pluginName?: string
  /** 内置受保护 skill（A 档保护）—— true 时隐藏删除入口。 */
  protected?: boolean
  /** 是否允许客户端直接修改元数据或打开编辑入口。 */
  canEdit?: boolean
  /** 领域分类（web/audit/asset/mobile/binary/redteam/forensics/cloud/custom）。
   *  缺失兜底 'custom'。前端据此分组展示，与设置-工具页面保持一致。 */
  category?: string
}

export type FileTreeNode = {
  name: string
  path: string
  type: 'file' | 'directory'
  children?: FileTreeNode[]
}

export type SkillFrontmatter = Record<string, unknown>

export type SkillFile = {
  path: string
  content: string
  language: string
  frontmatter?: SkillFrontmatter
  body?: string
  isEntry?: boolean
}

export type SkillDetail = {
  meta: SkillMeta
  tree: FileTreeNode[]
  files: SkillFile[]
  skillRoot: string
}
