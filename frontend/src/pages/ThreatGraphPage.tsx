import React, { useEffect, useMemo, useState } from "react";
import { Plus, ZoomIn, ZoomOut } from "lucide-react";
import { apiRequest } from "../services/api";
import { GraphEdge, GraphNode, Severity } from "../types";
import { PageHeader, SeverityBadge } from "../components/ui/Badges";
import { useAuth } from "../context/AuthContext";

const TYPE_COLORS: Record<string, string> = {
  CAMPAIGN: "#EC4899",
  EMAIL: "#F59E0B",
  URL: "#06B6D4",
  DOMAIN: "#8B5CF6",
  IP: "#EF4444",
  CVE: "#F97316",
  ASSET: "#10B981",
};

export const ThreatGraphPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>("ALL");
  const [zoom, setZoom] = useState(1);
  const [showAdd, setShowAdd] = useState(false);

  const [sourceType, setSourceType] = useState("DOMAIN");
  const [sourceValue, setSourceValue] = useState("");
  const [targetType, setTargetType] = useState("IP");
  const [targetValue, setTargetValue] = useState("");
  const [relation, setRelation] = useState("RESOLVES_TO");
  const [severity, setSeverity] = useState<Severity>("HIGH");

  const loadGraph = async () => {
    const res = await apiRequest<{ nodes: GraphNode[]; edges: GraphEdge[] }>(
      "/api/graph"
    );
    setNodes(res.nodes);
    setEdges(res.edges);
    if (!selectedNode && res.nodes.length > 0) {
      setSelectedNode(res.nodes[0]);
    }
  };

  useEffect(() => {
    void loadGraph();
  }, []);

  const visibleNodes = useMemo(() => {
    if (filterType === "ALL") return nodes;
    return nodes.filter((n) => n.type === filterType);
  }, [nodes, filterType]);

  const positionedNodes = useMemo(() => {
    const cx = 430;
    const cy = 260;
    const count = Math.max(1, visibleNodes.length);
    return visibleNodes.map((n, index) => {
      const ringRadius = count <= 6 ? 175 : index % 2 === 0 ? 195 : 115;
      const angle = (2 * Math.PI * index) / count - Math.PI / 2;
      return {
        ...n,
        x: cx + ringRadius * Math.cos(angle),
        y: cy + ringRadius * Math.sin(angle),
      };
    });
  }, [visibleNodes]);

  const posMap = useMemo(
    () => new Map(positionedNodes.map((n) => [n.id, n])),
    [positionedNodes]
  );

  const handleAddRelation = async (e: React.FormEvent) => {
    e.preventDefault();
    await apiRequest("/api/graph/relations", {
      method: "POST",
      body: JSON.stringify({
        sourceType,
        sourceValue,
        targetType,
        targetValue,
        relation,
        severity,
      }),
    });
    setSourceValue("");
    setTargetValue("");
    setShowAdd(false);
    void loadGraph();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Relationship Graph"
        subtitle="Interactive entity-link visualization correlating campaigns, phishing senders, malicious URLs, domains, C2 IPs, CVEs, and assets."
        badge={`${nodes.length} NODES · ${edges.length} LINKS`}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setZoom((z) => Math.max(0.7, +(z - 0.15).toFixed(2)))}
              className="p-2 rounded-lg bg-soc-panel border border-slate-700 text-slate-300"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.min(1.5, +(z + 0.15).toFixed(2)))}
              className="p-2 rounded-lg bg-soc-panel border border-slate-700 text-slate-300"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            {canMutate && (
              <button
                onClick={() => setShowAdd(!showAdd)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold bg-cyan-500 text-slate-950"
              >
                <Plus className="w-4 h-4" /> Add Link
              </button>
            )}
          </div>
        }
      />

      {showAdd && (
        <form
          onSubmit={handleAddRelation}
          className="bg-soc-panel border border-cyan-500/40 rounded-xl p-5 grid grid-cols-1 md:grid-cols-6 gap-3 items-end"
        >
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">
              Source Type
            </label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
              className="w-full px-2.5 py-2 rounded bg-slate-950 border border-slate-800 text-xs text-white"
            >
              {Object.keys(TYPE_COLORS).map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">
              Source Value
            </label>
            <input
              required
              value={sourceValue}
              onChange={(e) => setSourceValue(e.target.value)}
              placeholder="login-verify.xyz"
              className="w-full px-2.5 py-2 rounded bg-slate-950 border border-slate-800 text-xs text-white"
            />
          </div>
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">
              Relation
            </label>
            <input
              required
              value={relation}
              onChange={(e) => setRelation(e.target.value)}
              className="w-full px-2.5 py-2 rounded bg-slate-950 border border-slate-800 text-xs text-white"
            />
          </div>
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">
              Target Type
            </label>
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              className="w-full px-2.5 py-2 rounded bg-slate-950 border border-slate-800 text-xs text-white"
            >
              {Object.keys(TYPE_COLORS).map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">
              Target Value
            </label>
            <input
              required
              value={targetValue}
              onChange={(e) => setTargetValue(e.target.value)}
              placeholder="91.92.240.58"
              className="w-full px-2.5 py-2 rounded bg-slate-950 border border-slate-800 text-xs text-white"
            />
          </div>
          <div className="flex gap-2">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity)}
              className="px-2 py-2 rounded bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="CRITICAL">CRIT</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MED</option>
            </select>
            <button
              type="submit"
              className="flex-1 py-2 rounded bg-cyan-500 text-slate-950 text-xs font-bold"
            >
              Save
            </button>
          </div>
        </form>
      )}

      {/* Filter Pills */}
      <div className="flex flex-wrap gap-2">
        {["ALL", ...Object.keys(TYPE_COLORS)].map((type) => (
          <button
            key={type}
            onClick={() => setFilterType(type)}
            className={`px-3 py-1 rounded-full text-xs font-mono border transition ${
              filterType === type
                ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                : "bg-soc-panel text-slate-400 border-slate-800 hover:text-white"
            }`}
          >
            {type}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Interactive SVG Canvas */}
        <div className="lg:col-span-2 bg-soc-panel/95 border border-slate-800 rounded-xl overflow-hidden relative">
          <svg
            viewBox="0 0 860 520"
            className="w-full h-[500px] select-none"
          >
            <defs>
              <marker
                id="arrowhead"
                markerWidth="8"
                markerHeight="6"
                refX="22"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#475569" />
              </marker>
            </defs>

            <g
              transform={`translate(430,260) scale(${zoom}) translate(-430,-260)`}
            >
              {/* Edges */}
              {edges.map((edge) => {
                const src = posMap.get(edge.source);
                const dst = posMap.get(edge.target);
                if (!src || !dst) return null;
                const midX = (src.x + dst.x) / 2;
                const midY = (src.y + dst.y) / 2;
                return (
                  <g key={edge.id}>
                    <line
                      x1={src.x}
                      y1={src.y}
                      x2={dst.x}
                      y2={dst.y}
                      stroke="#334155"
                      strokeWidth="1.8"
                      markerEnd="url(#arrowhead)"
                    />
                    <text
                      x={midX}
                      y={midY - 5}
                      textAnchor="middle"
                      fill="#94A3B8"
                      fontSize="9"
                      fontFamily="monospace"
                    >
                      {edge.relation}
                    </text>
                  </g>
                );
              })}

              {/* Nodes */}
              {positionedNodes.map((node) => {
                const color = TYPE_COLORS[node.type] || "#06B6D4";
                const isSelected = selectedNode?.id === node.id;
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x},${node.y})`}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer"
                  >
                    {isSelected && (
                      <circle
                        r="26"
                        fill="none"
                        stroke={color}
                        strokeWidth="2"
                        strokeDasharray="4 3"
                      />
                    )}
                    <circle
                      r="18"
                      fill="#0B1120"
                      stroke={color}
                      strokeWidth="2.5"
                    />
                    <text
                      y="3"
                      textAnchor="middle"
                      fill={color}
                      fontSize="8"
                      fontWeight="bold"
                      fontFamily="monospace"
                    >
                      {node.type.slice(0, 4)}
                    </text>
                    <text
                      y="32"
                      textAnchor="middle"
                      fill="#E2E8F0"
                      fontSize="10"
                      fontFamily="monospace"
                    >
                      {node.label.slice(0, 26)}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Node Inspector Panel */}
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Entity Intelligence Inspector
          </h3>

          {selectedNode ? (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-soc-card border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span
                    className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                    style={{
                      backgroundColor: `${
                        TYPE_COLORS[selectedNode.type] || "#06B6D4"
                      }22`,
                      color: TYPE_COLORS[selectedNode.type] || "#06B6D4",
                    }}
                  >
                    {selectedNode.type}
                  </span>
                  <SeverityBadge severity={selectedNode.severity} />
                </div>
                <p className="text-sm font-mono font-semibold text-white break-all">
                  {selectedNode.value}
                </p>
                <div className="text-xs font-mono text-slate-400">
                  Risk Score:{" "}
                  <strong className="text-white">
                    {selectedNode.riskScore}/100
                  </strong>
                  {selectedNode.isDemoData && " · [DEMO DATA]"}
                </div>
              </div>

              <div>
                <h4 className="text-xs font-mono text-slate-400 mb-2">
                  Connected Relationships
                </h4>
                <div className="space-y-2 max-h-72 overflow-y-auto">
                  {edges
                    .filter(
                      (e) =>
                        e.source === selectedNode.id ||
                        e.target === selectedNode.id
                    )
                    .map((e) => (
                      <div
                        key={e.id}
                        className="p-3 rounded-lg bg-soc-card border border-slate-800 text-xs font-mono space-y-1"
                      >
                        <div className="text-cyan-300 font-semibold">
                          {e.relation} ({e.confidence}% conf)
                        </div>
                        <div className="text-slate-300 break-all">
                          {e.source} → {e.target}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-400">
              Click any node in the graph to inspect connected threat infrastructure.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
