import { useEffect, useRef } from 'react'
import { Network } from 'vis-network/standalone'
import type { TopologyNode, TopologyEdge } from './types'

type TopologyGraphProps = {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  onSelectNode?: (nodeId: string) => void
  className?: string
}

const groupStyles = {
  start: { color: { background: '#10b981', border: '#059669' }, font: { color: '#fff', size: 13 } },
  fact: { color: { background: '#6366f1', border: '#4f46e5' }, font: { color: '#fff', size: 12 } },
  intent: { color: { background: '#f59e0b', border: '#d97706' }, font: { color: '#fff', size: 11 } },
  finding: { color: { background: '#ef4444', border: '#dc2626' }, font: { color: '#fff', size: 12 } },
}

/**
 * 通用拓扑图组件（基于 vis-network）
 * - 简单重建方案（每次数据变化重新创建 network）
 * - 力导向布局（physics + barnesHut）
 * - 节点会有 1-2 秒的稳定动画（这是力导向布局的正常表现）
 * - 简单可靠，兼容 React Strict Mode
 */
export function TopologyGraph({ nodes, edges, onSelectNode, className = '' }: TopologyGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const networkRef = useRef<Network | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    // 转换为 vis-network 数据格式
    const visNodes = nodes.map((n) => {
      const marginValue = n.group === 'start' ? 10 : n.group === 'intent' ? 6 : 8
      return {
        id: n.id,
        label: n.label,
        group: n.group,
        title: n.title,
        shape: n.group === 'intent' ? 'ellipse' : n.group === 'finding' ? 'diamond' : 'box',
        margin: { top: marginValue, right: marginValue, bottom: marginValue, left: marginValue },
      }
    })

    const visEdges = edges.map((e) => ({
      id: `${e.from}-${e.to}`,
      from: e.from,
      to: e.to,
      label: e.label,
      color: e.color || '#94a3b8',
      arrows: 'to',
    }))

    const options = {
      groups: groupStyles,
      physics: {
        enabled: true,
        barnesHut: {
          springLength: 180,
          centralGravity: 0.2,
          gravitationalConstant: -3000,
        },
        stabilization: {
          enabled: true,
          iterations: 100, // 减少迭代次数，加快稳定速度
          updateInterval: 25,
        },
      },
      nodes: {
        borderWidth: 1.5,
        shadow: true,
        font: { size: 11, face: 'monospace' },
      },
      edges: {
        width: 1.5,
        smooth: { enabled: true, type: 'diagonalCross', roundness: 0.5 },
        font: { size: 9, color: '#64748b', align: 'middle' },
      },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        dragNodes: true,
        dragView: true,
        zoomView: true,
      },
    }

    // 销毁旧 network（如果存在）
    if (networkRef.current) {
      networkRef.current.destroy()
    }

    // 创建新 network，直接传入数据
    const network = new Network(
      containerRef.current,
      { nodes: visNodes, edges: visEdges },
      options
    )
    networkRef.current = network

    // 稳定后自动关闭 physics（防止节点一直动）
    network.once('stabilizationIterationsDone', () => {
      network.setOptions({ physics: { enabled: false } })
    })

    // 点击节点事件
    if (onSelectNode) {
      network.on('selectNode', (params: { nodes: (string | number)[] }) => {
        if (params.nodes.length > 0) {
          onSelectNode(params.nodes[0] as string)
        }
      })
    }

    return () => {
      // 组件卸载时销毁
      if (networkRef.current) {
        networkRef.current.destroy()
        networkRef.current = null
      }
    }
  }, [nodes, edges, onSelectNode])

  return (
    <div className="relative w-full h-full">
      <div ref={containerRef} className={className} style={{ background: '#f8fafc', width: '100%', height: '100%' }} />

      {/* 图例浮层（左下角） */}
      <div className="absolute bottom-4 left-4 bg-slate-800/90 border border-slate-700 rounded-lg p-3 text-xs space-y-1.5 z-10">
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-emerald-500 rounded"></div>
          <span className="text-slate-300">起点 / 核心目标</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-indigo-600 rounded"></div>
          <span className="text-slate-300">已确认事实 (Fact)</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-amber-500 rounded"></div>
          <span className="text-slate-300">探测意图 (Intent)</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-red-500 rounded" style={{ transform: 'rotate(45deg)' }}></div>
          <span className="text-slate-300">发现 (Finding)</span>
        </div>
      </div>
    </div>
  )
}
