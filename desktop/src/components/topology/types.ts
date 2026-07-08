/** 拓扑图节点类型 */
export type TopologyNodeGroup = 'start' | 'fact' | 'intent' | 'finding'

/** 拓扑图节点 */
export type TopologyNode = {
  id: string
  label: string
  group: TopologyNodeGroup
  title?: string // hover tooltip
}

/** 拓扑图边 */
export type TopologyEdge = {
  from: string
  to: string
  label?: string
  color?: string
}
