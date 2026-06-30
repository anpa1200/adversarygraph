import '@xyflow/react/dist/style.css';
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from '@xyflow/react';

export function EntityGraph({
  nodes,
  edges,
  fitView = true,
}: {
  nodes: Node[];
  edges: Edge[];
  fitView?: boolean;
}) {
  return (
    <div className="h-full min-h-[360px] overflow-hidden rounded border border-gray-800 bg-gray-950">
      <ReactFlow nodes={nodes} edges={edges} fitView={fitView} colorMode="dark">
        <Background color="#1f2937" gap={18} />
        <MiniMap pannable zoomable className="!bg-gray-950" />
        <Controls className="!border-gray-800 !bg-gray-950 !text-gray-200" />
      </ReactFlow>
    </div>
  );
}
