import React, { useMemo, useState } from 'react';
import { buildForceLayout, buildGraphLayout, buildRadialLayout, filterGraphData } from '../utils/securityTools.js';
import { riskColor } from './LoadingSpinner.jsx';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'NONE', 'UNKNOWN'];

export default function NetworkGraph({ report, mode = 'network', selectedId, onSelect, highlightedIds = [], mutedIds = [], scenarioStartId = '', showFilters = false, showViewToggle = false, emptyMessage = 'No resolved dependency relationships are present in this lockfile.' }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [scope, setScope] = useState('ALL');
  const [view, setView] = useState('graph');
  const [scale, setScale] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [drag, setDrag] = useState(null);
  const base = useMemo(() => mode === 'radial'
    ? buildRadialLayout(report, selectedId)
    : mode === 'network' ? buildForceLayout(report) : buildGraphLayout(report), [report, mode, selectedId]);
  const details = new Map(report.dependencies.map((dep) => [dep.id, dep]));
  const nodes = base.nodes.map((node) => {
    const detail = details.get(node.id);
    return { ...node, ...detail, riskLevel: detail?.riskLevel || node.riskLevel || 'UNKNOWN', vulnerabilities: detail?.vulnerabilities || [] };
  });
  const filtered = filterGraphData(nodes, base.edges, { query, severity, scope });
  const width = base.width;
  const height = base.height;
  const selectedNode = base.nodes.find((node) => node.id === selectedId);
  const radial = mode === 'radial' && selectedNode;
  const baseTranslate = (zoom) => radial
    ? { x: width / 2 - selectedNode.x * zoom, y: height / 2 - selectedNode.y * zoom }
    : { x: width * (1 - zoom) / 2, y: height * (1 - zoom) / 2 };
  const origin = baseTranslate(scale);
  const transform = `translate(${origin.x + pan.x} ${origin.y + pan.y}) scale(${scale})`;
  const visibleIds = new Set(filtered.nodes.map((node) => node.id));
  const edges = filtered.edges.filter((edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to));
  const noVisibleEdgesMessage = base.edges.length
    ? 'No resolved relationships connect the packages matching these filters.'
    : emptyMessage;
  const highlighted = new Set(highlightedIds);
  const muted = new Set(mutedIds);
  const advisoryCount = filtered.nodes.filter((node) => node.vulnerabilities.length).length;
  const fitView = () => {
    if (!filtered.nodes.length) { setScale(1); setPan({ x: 0, y: 0 }); return; }
    const xs = filtered.nodes.map((node) => node.x);
    const ys = filtered.nodes.map((node) => node.y);
    const minX = Math.min(...xs) - 55;
    const maxX = Math.max(...xs) + 55;
    const minY = Math.min(...ys) - 68;
    const maxY = Math.max(...ys) + 68;
    const next = Math.min(2.5, (width - 48) / Math.max(maxX - minX, 1), (height - 48) / Math.max(maxY - minY, 1));
    const nextOrigin = baseTranslate(next);
    setScale(next);
    setPan({ x: width / 2 - ((minX + maxX) / 2) * next - nextOrigin.x, y: height / 2 - ((minY + maxY) / 2) * next - nextOrigin.y });
  };
  const zoomAtPointer = (event) => {
    event.preventDefault();
    const rect = event.currentTarget.getBoundingClientRect();
    const unitsPerPixel = 1 / Math.min(rect.width / width, rect.height / height);
    const px = (event.clientX - rect.left - (rect.width - width / unitsPerPixel) / 2) * unitsPerPixel;
    const py = (event.clientY - rect.top - (rect.height - height / unitsPerPixel) / 2) * unitsPerPixel;
    const next = Math.max(.45, Math.min(2.5, scale * (event.deltaY < 0 ? 1.12 : 1 / 1.12)));
    const oldOrigin = baseTranslate(scale);
    const nextOrigin = baseTranslate(next);
    const ratio = next / scale;
    setPan({ x: px - (px - oldOrigin.x - pan.x) * ratio - nextOrigin.x, y: py - (py - oldOrigin.y - pan.y) * ratio - nextOrigin.y });
    setScale(next);
  };
  const beginPan = (event) => {
    if (event.target !== event.currentTarget) return;
    setDrag({ x: event.clientX, y: event.clientY, pan });
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };
  const movePan = (event) => {
    if (!drag) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const unitsPerPixel = 1 / Math.min(rect.width / width, rect.height / height);
    setPan({ x: drag.pan.x + (event.clientX - drag.x) * unitsPerPixel, y: drag.pan.y + (event.clientY - drag.y) * unitsPerPixel });
  };

  return <section className="network-visual" aria-label="Dependency graph visualization">
    <div className="network-toolbar">
      {showFilters && <>
        <label>Search<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Package name" /></label>
        <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option>ALL</option>{SEVERITIES.map((level) => <option key={level}>{level}</option>)}</select></label>
        <label>Dependency scope<select value={scope} onChange={(event) => setScope(event.target.value)}><option value="ALL">All</option><option value="DIRECT">Direct</option><option value="TRANSITIVE">Transitive</option></select></label>
      </>}
      {showViewToggle && <div className="network-view-toggle" role="group" aria-label="Graph display mode"><button className={view === 'graph' ? 'active' : ''} onClick={() => setView('graph')}>Network</button><button className={view === 'list' ? 'active' : ''} onClick={() => setView('list')}>Compact list</button></div>}
      <div className="network-zoom"><button onClick={() => setScale((n) => Math.min(2.5, n + .15))} aria-label="Zoom in">+</button><button onClick={() => setScale((n) => Math.max(.45, n - .15))} aria-label="Zoom out">−</button><button onClick={fitView}>Fit view</button><button onClick={() => { setScale(1); setPan({ x: 0, y: 0 }); }}>Reset</button><span>{Math.round(scale * 100)}%</span></div>
      <span className="network-count">{filtered.nodes.length} nodes · {edges.length} edges · {advisoryCount} with advisories</span>
    </div>
    <div className="network-legend" aria-label="Graph legend">{SEVERITIES.map((level) => <span key={level}><i style={{ background: riskColor(level) }} />{level}</span>)}<span><i className="legend-direct" />Direct</span><span><i className="legend-transitive" />Transitive</span><span className="legend-direction">Arrow: dependent → dependency</span></div>
    {view === 'list' ? <div className="network-list">{filtered.nodes.map((node) => <button key={node.id} className={selectedId === node.id ? 'selected' : ''} onClick={() => onSelect?.(node.id)}><i style={{ background: riskColor(node.riskLevel) }} /><span><strong>{node.name}@{node.version || 'unknown'}</strong><small>{node.isDirect ? 'Direct' : 'Transitive'} · {node.riskLevel} · {node.vulnerabilities.length} confirmed advisories</small></span></button>)}</div>
      : !filtered.nodes.length ? <div className="network-empty" role="status">No package instances match these filters.</div>
      : <>
        {!edges.length && <div className="network-empty network-empty-inline" role="status"><strong>{noVisibleEdgesMessage}</strong><span>{base.edges.length ? 'Try broadening the filters to show other recorded relationships.' : 'Installed instances remain visible below. No dependency links have been inferred.'}</span></div>}
        <div className="network-canvas"><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${filtered.nodes.length} visible installed package instances, ${edges.length} resolved dependency edges`} onWheel={zoomAtPointer} onPointerDown={beginPan} onPointerMove={movePan} onPointerUp={() => setDrag(null)} onPointerCancel={() => setDrag(null)}>
          <defs><marker id="network-arrow" markerWidth="9" markerHeight="9" refX="8" refY="4" orient="auto"><path d="M0,0 L0,8 L8,4 z" fill="var(--accent)" /></marker><filter id="network-glow" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="4" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter></defs>
          <g transform={transform}>
            {edges.map((edge, index) => {
              const from = nodes.find((node) => node.id === edge.from);
              const to = nodes.find((node) => node.id === edge.to);
              if (!from || !to) return null;
              const dx = to.x - from.x;
              const dy = to.y - from.y;
              const bend = Math.min(58, Math.max(-58, dx * .12));
              const d = `M ${from.x} ${from.y} Q ${(from.x + to.x) / 2 - dy * .12 + bend} ${(from.y + to.y) / 2 + dx * .12} ${to.x} ${to.y}`;
              const activePath = highlighted.has(edge.from) && highlighted.has(edge.to);
              return <path key={`${edge.from}->${edge.to}-${index}`} d={d} className={`network-edge ${activePath ? 'path-active' : ''} ${scenarioStartId && !activePath ? 'path-muted' : ''}`} markerEnd="url(#network-arrow)"><title>{`${from.name} depends on ${to.name}${edge.range ? ` (${edge.range})` : ''}`}</title></path>;
            })}
            {filtered.nodes.map((node) => {
              const selected = node.id === selectedId;
              const isPath = highlighted.has(node.id);
              const radius = node.isDirect ? 22 : 16;
              return <g key={node.id} className={`network-node ${node.isDirect ? 'direct' : 'transitive'} ${selected ? 'selected' : ''} ${isPath ? 'path-active' : ''} ${node.isolated ? 'isolated' : ''} ${scenarioStartId === node.id ? 'scenario-start' : ''} ${scenarioStartId && isPath && scenarioStartId !== node.id ? 'scenario-affected' : ''} ${muted.has(node.id) ? 'muted' : ''}`} role="button" tabIndex={0} aria-label={`${node.name}@${node.version || 'unknown'}, ${node.riskLevel}, ${node.isDirect ? 'direct' : 'transitive'}, ${node.vulnerabilities.length} confirmed advisories`} onPointerDown={(event) => event.stopPropagation()} onClick={() => onSelect?.(node.id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect?.(node.id); } }}>
                <circle className="network-selection-ring" cx={node.x} cy={node.y} r={radius + 9} />
                <circle className="network-node-dot" cx={node.x} cy={node.y} r={radius} fill={riskColor(node.riskLevel)} />
                {node.vulnerabilities.length > 0 && <text className="network-advisory-count" x={node.x + radius * .68} y={node.y - radius * .62}>{node.vulnerabilities.length}</text>}
                <text className="network-label" x={node.x} y={node.y + radius + 18} textAnchor="middle">{node.name.length > 28 ? `${node.name.slice(0, 25)}…` : node.name}</text>
                <text className="network-version" x={node.x} y={node.y + radius + 34} textAnchor="middle">{node.version || 'unknown'} · {node.isDirect ? 'DIRECT' : 'TRANSITIVE'}{node.isolated ? ' · ISOLATED' : ''}</text>
                <title>{`${node.name}@${node.version || 'unknown'} · ${node.riskLevel} · ${node.vulnerabilities.length} confirmed advisories${node.isolated ? ' · no resolved edges' : ''}`}</title>
              </g>;
            })}
          </g>
        </svg></div>
      </>}
    <p className="network-footnote">Edges show only relationships resolved from the supplied lockfile. They do not establish runtime use or exploitability.</p>
  </section>;
}
