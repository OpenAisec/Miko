import { useState, useMemo } from 'react'
import type { SessionBoardSnapshot } from '../../api/security'

// 探索节点（统一模型）
type ExploreNode = {
  id: string
  type: 'asset' | 'fact' | 'intent' | 'finding'
  title: string
  parentId?: string
  data: any  // 原始数据（fact/intent）
}

// 树节点（带子节点）
type TreeNode = ExploreNode & {
  children: TreeNode[]
}

// 转换 SessionBoardSnapshot → 单棵树（带虚拟根节点）
function buildExplorationTree(snap: SessionBoardSnapshot): TreeNode {
  // 创建虚拟根节点
  const root: TreeNode = {
    id: '__root__',
    type: 'asset',
    title: `开始：${snap.target || snap.goal || '测试目标'}`,
    data: { goal: snap.goal, target: snap.target },
    children: [],
  }

  // 合并 facts + intents 为统一节点列表
  const allNodes: ExploreNode[] = [
    ...snap.facts.map(f => ({
      id: f.id,
      type: (f.type === 'finding' ? 'finding' : f.type === 'asset' ? 'asset' : 'fact') as ExploreNode['type'],
      title: f.title,
      parentId: f.parentId,
      data: f,
    })),
    ...snap.intents.map(it => ({
      id: it.id,
      type: 'intent' as const,
      title: it.title,
      parentId: it.parentId ?? it.from?.[0],  // 优先 parentId（asset 骨架），回退 from
      data: it,
    })),
  ]

  // 构建节点 Map
  const nodeMap = new Map<string, TreeNode>()
  allNodes.forEach(node => {
    nodeMap.set(node.id, { ...node, children: [] })
  })

  // 构建父子关系
  allNodes.forEach(node => {
    const treeNode = nodeMap.get(node.id)!
    if (!node.parentId || !nodeMap.has(node.parentId)) {
      // 根节点（无 parentId 或 parentId 不在列表）挂到虚拟根
      root.children.push(treeNode)
    } else {
      // 挂到父节点
      const parent = nodeMap.get(node.parentId)!
      parent.children.push(treeNode)
    }
  })

  return root
}

// ═══════════════════════════════════════════════════════════
// 递归树节点组件
// ═══════════════════════════════════════════════════════════

function TreeNodeComponent({ node, depth = 0, isLast = false, onSelectNode }: {
  node: TreeNode
  depth?: number
  isLast?: boolean
  onSelectNode?: (nodeId: string) => void
}) {
  const [collapsed, setCollapsed] = useState(false)
  const hasChildren = node.children.length > 0

  // 节点类型颜色（单色点）
  const typeDots = {
    asset: 'bg-blue-500',
    fact: 'bg-indigo-500',
    intent: 'bg-amber-500',
    finding: 'bg-red-500',
  }

  // intent 状态标签
  const intentStatus = node.type === 'intent' ? (node.data.status || node.data.graphStatus || 'open') : null
  const statusLabels: Record<string, string> = {
    open: '待探',
    pending: '待探',
    running: '中',
    exploring: '中',
    done: '完',
    completed: '完',
    failed: '失败',
  }

  // finding 严重度标签
  const severity = node.type === 'finding' ? node.data.severity : null
  const severityColors: Record<string, string> = {
    critical: 'bg-red-600',
    high: 'bg-red-500',
    medium: 'bg-orange-500',
    low: 'bg-yellow-600',
    info: 'bg-gray-500',
  }

  return (
    <div className="relative">
      {/* 树状连线（CSS） */}
      {depth > 0 && (
        <>
          {/* 竖线（从上方延伸到节点中间） */}
          <div
            className="absolute top-0 w-px bg-slate-700"
            style={{
              left: `${(depth - 1) * 20 + 10}px`,
              height: '12px',
            }}
          />
          {/* 横线（从竖线到节点） */}
          <div
            className="absolute bg-slate-700"
            style={{
              left: `${(depth - 1) * 20 + 10}px`,
              top: '12px',
              width: '10px',
              height: '1px',
            }}
          />
          {/* 竖线延续（如果不是最后一个子节点，继续向下） */}
          {!isLast && (
            <div
              className="absolute bg-slate-700"
              style={{
                left: `${(depth - 1) * 20 + 10}px`,
                top: '12px',
                bottom: '0',
                width: '1px',
              }}
            />
          )}
        </>
      )}

      {/* 节点行 */}
      <div
        className="flex items-center gap-2 py-1 hover:bg-slate-800 cursor-pointer transition-colors rounded relative"
        style={{ paddingLeft: `${depth * 20 + 22}px` }}
        onClick={() => {
          if (hasChildren) setCollapsed(!collapsed)
          if (onSelectNode) onSelectNode(node.id)
        }}
      >
        {/* 折叠图标 */}
        {hasChildren && (
          <span className={`text-[10px] text-slate-400 transition-transform ${collapsed ? '' : 'rotate-90'}`}>
            ▸
          </span>
        )}
        {!hasChildren && <span className="w-2" />}

        {/* 节点类型点 */}
        <span className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${typeDots[node.type]}`} />

        {/* 节点标题 */}
        <span className="flex-1 text-xs text-slate-200 truncate leading-tight">{node.title}</span>

        {/* intent 状态 */}
        {intentStatus && (
          <span className="text-[10px] text-slate-400 flex-shrink-0">
            {statusLabels[intentStatus] || intentStatus}
          </span>
        )}

        {/* finding 严重度 */}
        {severity && (
          <span className={`inline-block w-1 h-1 rounded-full flex-shrink-0 ${severityColors[severity] || 'bg-gray-500'}`} />
        )}

        {/* 子节点计数 */}
        {hasChildren && (
          <span className="text-[10px] text-slate-400 flex-shrink-0">
            {node.children.length}
          </span>
        )}
      </div>

      {/* 递归渲染子节点 */}
      {hasChildren && !collapsed && (
        <div>
          {node.children.map((child, index) => (
            <TreeNodeComponent
              key={child.id}
              node={child}
              depth={depth + 1}
              isLast={index === node.children.length - 1}
              onSelectNode={onSelectNode}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
// 探索树主组件
// ═══════════════════════════════════════════════════════════

export function ExplorationTree({
  snapshot,
  onSelectNode,
  className = '',
}: {
  snapshot: SessionBoardSnapshot
  onSelectNode?: (nodeId: string) => void
  className?: string
}) {
  // 构建树结构（useMemo 缓存，避免频繁重建）
  const rootNode = useMemo(() => buildExplorationTree(snapshot), [snapshot])

  if (rootNode.children.length === 0) {
    return (
      <div className={`flex items-center justify-center h-full ${className}`}>
        <div className="text-center text-slate-500">
          <div className="text-xs">暂无探索数据</div>
        </div>
      </div>
    )
  }

  return (
    <div className={`overflow-y-auto px-3 py-2 ${className}`}>
      {/* 渲染根节点及其所有子树 */}
      <TreeNodeComponent
        node={rootNode}
        depth={0}
        isLast={false}
        onSelectNode={onSelectNode}
      />
    </div>
  )
}
