/**
 * 共享分类常量 —— project / agent / skill / tool 四类资源共用同一套 category 枚举。
 *
 * 出处：原定义在 securityProjectService.ts，工具生态引入后抽到此处共享（[[工具生态-台账与分级披露方案]] §四）。
 * 一处定义、四处 import，避免各拷一份漂移。自定义分类（用户增删）仍存 index.json，由 securityProjectService 管。
 */

/** 内置分类 id（取代 priority 当主维度；旧项目无此字段时读取默认 custom）。
 *  注：自定义分类的 id 是动态字符串，所以消费方的 category 字段用 string，不绑死此 union。 */
export type ProjectCategory =
  | 'web'
  | 'audit'
  | 'asset'
  | 'mobile'
  | 'binary'
  | 'redteam'
  | 'forensics'
  | 'cloud'
  | 'custom'

/** 分类定义（注册表项）。内置分类是代码常量，自定义分类存 index.json。 */
export type CategoryDef = {
  id: string
  label: string
  color: string
  /** 内置分类不可删除/改名。 */
  builtin?: boolean
}

/** 内置分类（顺序即默认显示顺序）。custom 永远兜底存在、排最后。
 *  redteam/forensics/cloud 是工具生态引入时新增（CSAI 89 工具溢出原 6 类的部分）。 */
export const BUILTIN_CATEGORIES: CategoryDef[] = [
  { id: 'web', label: 'Web 渗透', color: '#6c5ce7', builtin: true },
  { id: 'audit', label: '代码审计', color: '#45aaf2', builtin: true },
  { id: 'asset', label: '资产收集', color: '#2ed573', builtin: true },
  { id: 'mobile', label: '移动端', color: '#ffa502', builtin: true },
  { id: 'binary', label: '二进制', color: '#ff4757', builtin: true },
  { id: 'redteam', label: '红队·横向', color: '#c23616', builtin: true },
  { id: 'forensics', label: '取证·隐写', color: '#00cec9', builtin: true },
  { id: 'cloud', label: '云·容器', color: '#0984e3', builtin: true },
  { id: 'custom', label: '自定义', color: '#6b7087', builtin: true },
]
