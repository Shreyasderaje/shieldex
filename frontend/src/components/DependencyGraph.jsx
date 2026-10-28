import React, { useMemo, useState } from 'react';
import { riskColor } from './LoadingSpinner.jsx';

// Dependency tree built from the backend's parsed relationships (install
// paths + resolved edges). Collapsible; every node shows the risk level that
// instance was scored at. Duplicate versions appear at their own paths.

function buildTree(graph, depsById) {
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  const childrenOf = new Map();
  for (const edge of graph.edges) {
    if (!childrenOf.has(edge.from)) childrenOf.set(edge.from, []);
    childrenOf.get(edge.from).push(edge.to);
  }
  const makeNode = (id) => {
    const meta = nodeById.get(id);
    const dep = depsById.get(id);
    const kids = (childrenOf.get(id) || [])
      .filter((childId) => nodeById.has(childId))
      .map(makeNode);
    return {
      id,
      name: meta ? meta.name : id,
      version: meta?.version,
      riskLevel: meta?.riskLevel || 'UNKNOWN',
      devOnly: meta?.devOnly,
      children: kids,
    }
  };
  // Roots: direct dependencies (resolved from the project root).
  const roots = (childrenOf.get('') || []).map(makeNode);
  return roots;
}

function TreeNode({ node, depth }) {
  const [open, setOpen] = useState(depth < 2);
  const hasKids = node.children.length > 0;
  return (
    <li className="tree-node">
      <div className="tree-row" style={{ paddingLeft: `${depth * 14}px` }}>
        {hasKids ? (
          <button className="tree-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? '−' : '+'}
          </button>
        ) : (
          <span className="tree-toggle leaf">·</span>
        )}
        <span className="dot" style={{ backgroundColor: riskColor(node.riskLevel) }} />
        <span className="tree-name">{node.name}</span>
        <span className="tree-version">{node.version ?? 'version unknown'}</span>
        {node.devOnly && <span className="badge dev">dev</span>}
        <span className="tree-risk" style={{ color: riskColor(node.riskLevel) }}>{node.riskLevel}</span>
      </div>
      {hasKids && (
        <div className={`tree-children ${open ? 'is-open' : ''}`} aria-hidden={!open} inert={!open}>
        <ul>
          {node.children.map((kid) => (
            <TreeNode key={kid.id} node={kid} depth={depth + 1} />
          ))}
        </ul>
        </div>
      )}
    </li>
  );
}

function DependencyGraph({ report }) {
  const [showAll, setShowAll] = useState(false);
  const depsById = useMemo(() => new Map(report.dependencies.map((d) => [d.id, d])), [report]);
  const roots = useMemo(() => buildTree(report.graph, depsById), [report, depsById]);

  const displayRoots = useMemo(() => {
    if (showAll) return roots;
    // Default: risk-relevant subtree = direct deps + any vulnerable instance.
    const important = (n) =>
      n.riskLevel !== 'NONE' && n.riskLevel !== 'UNKNOWN'
        ? true
        : n.children.some(important);
    return roots.filter((n) => important(n) || n.children.length === 0);
  }, [roots, showAll]);

  const orphanCount = report.graph.nodes.length - report.graph.edges.length - roots.length;

  return (
    <section className="card graph-card">
      <h3>Dependency tree (parsed from lockfile relationships)</h3>
      <p className="muted">
        {roots.length} direct dependency root(s), {report.graph.nodes.length} instances,
        {' '}{report.graph.edges.length} resolved edges.
        {report.duplicates.length > 0 && (
          <>
            {' '}Packages installed at multiple versions:{' '}
            {report.duplicates.map((d) => (
              <strong key={d.name}>{d.name} ({d.versions.join(', ')})</strong>
            )).reduce((acc, el) => (acc.length ? [...acc, ', ', el] : [el]), [])}
          </>
        )}
      </p>
      <label className="tree-filter">
        <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
        Show all nodes (default hides fully-clean subtrees)
      </label>
      <ul className="tree-root">
        {displayRoots.map((n) => <TreeNode key={n.id} node={n} depth={0} />)}
        {displayRoots.length === 0 && <li className="muted">No direct dependencies resolved.</li>}
      </ul>
      {orphanCount > 0 && (
        <p className="muted">
          {orphanCount} instance(s) are not reachable from declared dependencies (bundled/omitted) and are
          omitted from the tree — they are still listed and scored in the findings table.
        </p>
      )}
    </section>
  );
}

export default DependencyGraph;
