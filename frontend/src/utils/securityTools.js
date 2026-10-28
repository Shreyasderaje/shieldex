const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'NONE', 'UNKNOWN'];
const SEVERITY_RANK = { CRITICAL: 5, HIGH: 4, MODERATE: 3, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 };

export function buildGraphLayout(report) {
  if (!report?.graph || !Array.isArray(report.graph.nodes) || !Array.isArray(report.graph.edges)) {
    throw new Error('This scan does not contain dependency graph data. Upload a supported package-lock.json.');
  }
  const nodes = report.graph.nodes;
  const known = new Set(nodes.map((node) => node.id));
  const edges = report.graph.edges.filter((edge) => known.has(edge.from) && known.has(edge.to));
  const adjacency = new Map(nodes.map((node) => [node.id, []]));
  edges.forEach((edge) => adjacency.get(edge.from).push(edge.to));
  const level = new Map();
  const queue = nodes.filter((node) => node.isDirect).map((node) => node.id);
  queue.forEach((id) => level.set(id, 0));
  for (let i = 0; i < queue.length; i += 1) {
    const from = queue[i];
    for (const to of adjacency.get(from) || []) {
      if (!level.has(to)) { level.set(to, level.get(from) + 1); queue.push(to); }
    }
  }
  const maxLevel = Math.max(0, ...level.values());
  const unvisited = nodes.filter((node) => !level.has(node.id)).sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));
  unvisited.forEach((node) => level.set(node.id, maxLevel + 1));
  const groups = new Map();
  nodes.forEach((node) => {
    const x = level.get(node.id);
    if (!groups.has(x)) groups.set(x, []);
    groups.get(x).push(node);
  });
  const width = Math.max(680, (Math.max(...groups.keys(), 0) + 1) * 200 + 100);
  const height = Math.max(360, ...[...groups.values()].map((group) => group.length * 84 + 64));
  const positioned = new Map();
  const parents = new Map(nodes.map((node) => [node.id, []]));
  edges.forEach((edge) => parents.get(edge.to).push(edge.from));
  for (const depth of [...groups.keys()].sort((a, b) => a - b)) {
    const group = groups.get(depth);
    group.sort((a, b) => {
      const parentY = (node) => (parents.get(node.id) || []).map((id) => positioned.get(id)?.y).filter(Number.isFinite);
      const aParents = parentY(a); const bParents = parentY(b);
      const aCenter = aParents.length ? aParents.reduce((sum, y) => sum + y, 0) / aParents.length : Number.POSITIVE_INFINITY;
      const bCenter = bParents.length ? bParents.reduce((sum, y) => sum + y, 0) / bParents.length : Number.POSITIVE_INFINITY;
      return aCenter - bCenter || a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)) || a.id.localeCompare(b.id);
    });
    group.forEach((node, index) => positioned.set(node.id, {
      ...node,
      x: 70 + depth * 200,
      y: ((index + 1) * height) / (group.length + 1),
      isolated: unvisited.some((item) => item.id === node.id),
    }));
  }
  return { nodes: [...positioned.values()], edges, width, height };
}

// Stable, deterministic force layout for an at-a-glance network view. Seed
// positions come from the install-path identity; only observed edges attract.
export function buildForceLayout(report, width = 1000, height = 620) {
  const nodes = report?.graph?.nodes || [];
  width = Math.max(width, Math.sqrt(nodes.length) * 90);
  height = Math.max(height, Math.sqrt(nodes.length) * 66);
  const known = new Set(nodes.map((node) => node.id));
  const edges = (report?.graph?.edges || []).filter((edge) => known.has(edge.from) && known.has(edge.to) && edge.from !== edge.to);
  if (!nodes.length) return { nodes: [], edges, width, height };
  const connected = new Set(edges.flatMap((edge) => [edge.from, edge.to]));
  const coords = nodes.map((node, index) => {
    const angle = index * 2.399963229728653;
    const radius = 45 + 24 * Math.sqrt(index);
    return { ...node, x: width / 2 + Math.cos(angle) * radius, y: height / 2 + Math.sin(angle) * radius };
  });
  const indexById = new Map(coords.map((node, index) => [node.id, index]));
  // Bounded relaxation avoids physics jitter and gives repeatable positions.
  for (let step = 0; step < 90; step += 1) {
    const forces = coords.map(() => ({ x: 0, y: 0 }));
    const cellSize = 125;
    const cells = new Map();
    coords.forEach((node, index) => {
      const key = `${Math.floor(node.x / cellSize)},${Math.floor(node.y / cellSize)}`;
      if (!cells.has(key)) cells.set(key, []);
      cells.get(key).push(index);
    });
    for (const [key, members] of cells) {
      const [cx, cy] = key.split(',').map(Number);
      for (let ox = -1; ox <= 1; ox += 1) for (let oy = -1; oy <= 1; oy += 1) {
        for (const a of members) for (const b of cells.get(`${cx + ox},${cy + oy}`) || []) {
          if (b <= a) continue;
          let dx = coords[a].x - coords[b].x; let dy = coords[a].y - coords[b].y;
          const distance = Math.max(1, Math.hypot(dx, dy));
          const push = Math.min(2.8, 1800 / (distance * distance));
          dx = dx / distance * push; dy = dy / distance * push;
          forces[a].x += dx; forces[a].y += dy; forces[b].x -= dx; forces[b].y -= dy;
        }
      }
    }
    for (const edge of edges) {
      const a = indexById.get(edge.from); const b = indexById.get(edge.to);
      const dx = coords[b].x - coords[a].x; const dy = coords[b].y - coords[a].y;
      const distance = Math.max(1, Math.hypot(dx, dy)); const pull = (distance - 125) * .008;
      forces[a].x += dx / distance * pull; forces[a].y += dy / distance * pull;
      forces[b].x -= dx / distance * pull; forces[b].y -= dy / distance * pull;
    }
    const cooling = 1 - step / 105;
    coords.forEach((node, index) => {
      node.x = Math.max(65, Math.min(width - 65, node.x + forces[index].x * cooling));
      node.y = Math.max(65, Math.min(height - 65, node.y + forces[index].y * cooling));
    });
  }
  return { nodes: coords.map((node) => ({ ...node, isolated: !connected.has(node.id) })), edges, width, height };
}

export function buildRadialLayout(report, centerId, width = 900, height = 620) {
  const nodes = report?.graph?.nodes || [];
  const known = new Set(nodes.map((node) => node.id));
  const edges = (report?.graph?.edges || []).filter((edge) => known.has(edge.from) && known.has(edge.to));
  const distance = new Map();
  if (known.has(centerId)) {
    distance.set(centerId, 0);
    const queue = [centerId];
    while (queue.length) {
      const current = queue.shift();
      for (const edge of edges) {
        const next = edge.from === current ? edge.to : edge.to === current ? edge.from : null;
        if (next && !distance.has(next)) { distance.set(next, distance.get(current) + 1); queue.push(next); }
      }
    }
  }
  const groups = new Map();
  nodes.forEach((node) => {
    const level = distance.get(node.id) ?? -1;
    if (!groups.has(level)) groups.set(level, []);
    groups.get(level).push(node);
  });
  const positioned = [];
  for (const [level, group] of groups) {
    group.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    group.forEach((node, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(group.length, 1) - Math.PI / 2;
      const radius = level === 0 ? 0 : level < 0 ? Math.min(width, height) * .43 : 125 + (level - 1) * 100;
      positioned.push({ ...node, x: width / 2 + Math.cos(angle) * radius, y: height / 2 + Math.sin(angle) * radius, isolated: level < 0 });
    });
  }
  return { nodes: positioned, edges, width, height };
}

export function filterGraphData(nodes, edges, { query = '', severity = 'ALL', scope = 'ALL' } = {}) {
  const term = query.trim().toLocaleLowerCase();
  const visible = nodes.filter((node) => (!term || node.name.toLocaleLowerCase().includes(term)) &&
    (severity === 'ALL' || node.riskLevel === severity) &&
    (scope === 'ALL' || (scope === 'DIRECT' ? node.isDirect : !node.isDirect)));
  const ids = new Set(visible.map((node) => node.id));
  return { nodes: visible, edges: edges.filter((edge) => ids.has(edge.from) && ids.has(edge.to)) };
}

export function findDependents(report, selectedId) {
  const nodeIds = new Set(report?.graph?.nodes?.map((node) => node.id) || []);
  if (!nodeIds.has(selectedId)) return { direct: [], all: [], paths: [], known: false };
  const reverse = new Map([...nodeIds].map((id) => [id, []]));
  for (const edge of report.graph.edges || []) {
    if (reverse.has(edge.to) && reverse.has(edge.from)) reverse.get(edge.to).push(edge.from);
  }
  const direct = [...new Set(reverse.get(selectedId) || [])].filter((id) => id !== selectedId);
  const paths = [];
  const seen = new Set([selectedId]);
  const queue = direct.map((id) => ({ id, path: [selectedId, id] }));
  while (queue.length) {
    const current = queue.shift();
    if (seen.has(current.id)) continue;
    seen.add(current.id);
    paths.push(current);
    for (const parent of reverse.get(current.id) || []) {
      if (!seen.has(parent)) queue.push({ id: parent, path: [...current.path, parent] });
    }
  }
  return { direct, all: paths.map((item) => item.id), paths, known: true };
}

export function aggregateRisk(scores) {
  const known = scores.filter((score) => typeof score === 'number' && Number.isFinite(score));
  if (!known.length) return null;
  const sorted = [...known].sort((a, b) => b - a);
  const mean = (values) => values.reduce((sum, value) => sum + value, 0) / values.length;
  return Math.round(.5 * sorted[0] + .3 * mean(sorted.slice(0, 5)) + .2 * mean(known));
}

export function simulateRisk(report, remediatedIds) {
  const selected = new Set(remediatedIds);
  const hasCompleteFixEvidence = (dep) => {
    const upgrade = dep.remediation?.find((item) => item.type === 'upgrade');
    return dep.vulnerabilities?.length > 0 && dep.vulnerabilities.every((advisory) => upgrade?.resolvedAdvisories?.includes(advisory.id));
  };
  const baseline = report.dependencies.map((dep) => dep.riskScore);
  const projected = report.dependencies.map((dep) => (
    selected.has(dep.id) && hasCompleteFixEvidence(dep) && typeof dep.riskScore === 'number' ? 0 : dep.riskScore
  ));
  const baselineScore = aggregateRisk(baseline);
  const projectedScore = aggregateRisk(projected);
  return {
    baselineScore,
    projectedScore,
    delta: baselineScore === null || projectedScore === null ? null : baselineScore - projectedScore,
    projected,
    assumedRemediated: report.dependencies.filter((dep) => selected.has(dep.id) && hasCompleteFixEvidence(dep) && typeof dep.riskScore === 'number').map((dep) => dep.id),
  };
}

export function buildThreatSignals(report) {
  const timestamp = report.generatedAt || null;
  const signals = [];
  for (const dep of report.dependencies || []) {
    for (const advisory of dep.vulnerabilities || []) {
      signals.push({ kind: 'confirmed', label: 'Confirmed advisory', package: `${dep.name}@${dep.version || 'unknown'}`, source: 'OSV.dev', timestamp, confidence: advisory.severity?.label === 'UNKNOWN' ? 'medium' : 'high', evidence: `${advisory.id}: exact installed version matched OSV; severity ${advisory.severity?.label || 'UNKNOWN'}.`, advisory });
    }
    for (const warning of dep.warnings || []) {
      signals.push({ kind: 'heuristic', label: warning.category === 'maintenance' ? 'Metadata review' : 'Package review', package: `${dep.name}@${dep.version || 'unknown'}`, source: warning.category === 'lifecycle-script' ? 'package-lock.json' : 'npm registry', timestamp, confidence: 'low', evidence: warning.message });
    }
    if (dep.riskLevel === 'UNKNOWN' || dep.missingData?.length) {
      signals.push({ kind: 'insufficient', label: 'Coverage gap', package: `${dep.name}@${dep.version || 'unknown'}`, source: dep.missingData?.includes('vulnerability-scan') ? 'OSV.dev' : 'Scan metadata', timestamp, confidence: 'none', evidence: `Unknown results are not safe results. Missing: ${(dep.missingData || ['vulnerability data']).join(', ')}.` });
    }
  }
  if (report.coverage?.vulnerabilityStatus === 'partial' || report.coverage?.vulnerabilityStatus === 'unavailable') {
    signals.push({ kind: 'insufficient', label: 'Threat data incomplete', package: report.projectName, source: 'OSV.dev', timestamp, confidence: 'none', evidence: report.coverage.notes?.join(' ') || 'Some vulnerability queries did not complete.' });
  }
  return signals;
}

function editDistanceOne(a, b) {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  let i = 0; let j = 0; let edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { i += 1; j += 1; continue; }
    edits += 1;
    if (edits > 1) return false;
    if (a.length > b.length) i += 1;
    else if (b.length > a.length) j += 1;
    else { i += 1; j += 1; }
  }
  return edits + Number(i < a.length || j < b.length) === 1;
}

export function findNameConfusions(dependencies) {
  const direct = [...new Set(dependencies.filter((dep) => dep.isDirect).map((dep) => dep.name.toLowerCase()))];
  const pairs = new Set();
  const signals = [];
  for (const dep of dependencies) {
    const candidate = dep.name.toLowerCase();
    for (const known of direct) {
      if (candidate === known || candidate.length < 5 || known.length < 5 || !editDistanceOne(candidate, known)) continue;
      const key = `${candidate}|${known}`;
      if (pairs.has(key)) continue;
      pairs.add(key);
      signals.push({ package: dep.name, similarTo: known, evidence: `Name differs by one character from a direct dependency in this same lockfile (${known}). This is a low-confidence spelling heuristic, not a malicious-package finding.` });
    }
  }
  return signals;
}

function requireCompleteReport(report) {
  if (!report || !Array.isArray(report.dependencies) || report.dependencies.length === 0) throw new Error('A scan with installed dependency instances is required to generate an SBOM.');
  const missing = report.dependencies.filter((dep) => !dep.name || !dep.version);
  if (missing.length) throw new Error(`${missing.length} package instance(s) lack an exact version. Generate a lockfile and rescan before exporting an SBOM.`);
}

function packageUrl(dep) {
  const encodedName = dep.name.startsWith('@') ? `%40${dep.name.slice(1)}` : dep.name;
  return `pkg:npm/${encodedName}@${dep.version}?shieldex_path=${encodeURIComponent(dep.id)}`;
}

function graphEdges(report) {
  const valid = new Set(report.dependencies.map((dep) => dep.id));
  return (report.graph?.edges || []).filter((edge) => valid.has(edge.from) && valid.has(edge.to));
}

export function createCycloneDx(report, timestamp = new Date().toISOString()) {
  requireCompleteReport(report);
  const refById = new Map(report.dependencies.map((dep, index) => [dep.id, `shieldex:${index + 1}:${encodeURIComponent(dep.id)}`]));
  const edges = graphEdges(report);
  const rootRef = 'shieldex:project-root';
  const components = report.dependencies.map((dep) => ({
    type: 'library', 'bom-ref': refById.get(dep.id), name: dep.name, version: dep.version, purl: packageUrl(dep),
    ...(dep.license && dep.license !== 'unknown' ? { licenses: [{ license: { name: dep.license } }] } : {}),
    properties: [
      { name: 'shieldex:installPath', value: dep.id },
      { name: 'shieldex:scope', value: dep.isDirect ? 'direct' : 'transitive' },
      { name: 'shieldex:riskLevel', value: dep.riskLevel },
    ],
  }));
  // Root-to-direct relationships are supported by the parser's direct
  // dependency classification; all other edges below come from lockfile data.
  const deps = new Map([[rootRef, report.dependencies.filter((dep) => dep.isDirect).map((dep) => refById.get(dep.id))]]);
  report.dependencies.forEach((dep) => deps.set(refById.get(dep.id), []));
  edges.forEach((edge) => deps.get(refById.get(edge.from)).push(refById.get(edge.to)));
  const bom = {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${globalThis.crypto.randomUUID()}`, version: 1,
    metadata: { timestamp, tools: [{ vendor: 'SHIELDEX', name: 'SHIELDEX' }], component: { type: 'application', 'bom-ref': rootRef, name: report.projectName || 'Unknown project', ...(report.projectVersion && report.projectVersion !== 'unknown' ? { version: report.projectVersion } : {}) } },
    components,
    dependencies: [...deps].map(([ref, dependsOn]) => ({ ref, dependsOn: [...new Set(dependsOn)] })),
  };
  if (bom.components.some((component) => !component.purl || !component['bom-ref']) || bom.dependencies.some((item) => item.dependsOn.some((ref) => !deps.has(ref)))) throw new Error('CycloneDX validation failed: invalid package reference or dependency relationship.');
  return bom;
}

export function createSpdx(report, timestamp = new Date().toISOString()) {
  requireCompleteReport(report);
  const idByPath = new Map(report.dependencies.map((dep, index) => [dep.id, `SPDXRef-Package-${index + 1}`]));
  const projectPackage = {
    SPDXID: 'SPDXRef-Project', name: report.projectName || 'Unknown project', downloadLocation: 'NOASSERTION', filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION', primaryPackagePurpose: 'APPLICATION',
    ...(report.projectVersion && report.projectVersion !== 'unknown' ? { versionInfo: report.projectVersion } : {}),
  };
  const packages = [projectPackage, ...report.dependencies.map((dep) => ({
    SPDXID: idByPath.get(dep.id), name: dep.name, versionInfo: dep.version, downloadLocation: 'NOASSERTION', filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION', primaryPackagePurpose: 'LIBRARY',
    externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: packageUrl(dep) }],
    sourceInfo: `Installed instance recorded at ${dep.id}.`,
    ...(dep.license && dep.license !== 'unknown' ? { licenseComments: `npm registry reported license: ${dep.license}` } : {}),
  }))];
  const relationships = [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: projectPackage.SPDXID }];
  for (const dep of report.dependencies.filter((item) => item.isDirect)) relationships.push({ spdxElementId: projectPackage.SPDXID, relationshipType: 'DEPENDS_ON', relatedSpdxElement: idByPath.get(dep.id) });
  for (const edge of graphEdges(report)) relationships.push({ spdxElementId: idByPath.get(edge.from), relationshipType: 'DEPENDS_ON', relatedSpdxElement: idByPath.get(edge.to) });
  const document = {
    spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: `${report.projectName || 'Unknown project'} dependency inventory`, documentNamespace: `https://shieldex.invalid/spdx/${globalThis.crypto.randomUUID()}`,
    creationInfo: { created: timestamp, creators: ['Tool: SHIELDEX'] }, packages, relationships,
  };
  const packageIds = new Set(packages.map((pkg) => pkg.SPDXID));
  if (relationships.some((rel) => rel.relationshipType === 'DEPENDS_ON' && (!packageIds.has(rel.spdxElementId) || !packageIds.has(rel.relatedSpdxElement)))) throw new Error('SPDX validation failed: dependency relationship references an unknown package.');
  return document;
}

export function evaluateGate(report, { failOn = 'HIGH', unknown = 'warn' } = {}) {
  if (!report || !Array.isArray(report.dependencies)) throw new Error('A valid scan report with dependencies is required.');
  if (!['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'NONE'].includes(failOn)) throw new Error(`Unsupported severity threshold: ${failOn}`);
  if (!['warn', 'fail', 'ignore'].includes(unknown)) throw new Error(`Unsupported unknown policy: ${unknown}`);
  const threshold = SEVERITY_RANK[failOn];
  const findings = [];
  for (const dep of report.dependencies) for (const advisory of dep.vulnerabilities || []) {
    const severity = String(advisory.severity?.label || 'UNKNOWN').toUpperCase();
    if ((SEVERITY_RANK[severity] ?? 0) >= threshold) findings.push({ package: `${dep.name}@${dep.version || 'unknown'}`, advisory: advisory.id, severity });
  }
  const unknownPackages = report.dependencies.filter((dep) => dep.riskLevel === 'UNKNOWN' || dep.vulnerabilities?.some((item) => !item.severity?.label || item.severity.label === 'UNKNOWN')).map((dep) => `${dep.name}@${dep.version || 'unknown'}`);
  const unknownFailure = unknown === 'fail' && unknownPackages.length > 0;
  return { passed: findings.length === 0 && !unknownFailure, threshold: failOn, unknownPolicy: unknown, findings, unknownPackages, message: `${findings.length} advisory finding(s) at ${failOn} or above; ${unknownPackages.length} package(s) have unknown results.` };
}

export { SEVERITY_ORDER };
