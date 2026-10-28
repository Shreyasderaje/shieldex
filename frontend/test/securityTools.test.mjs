import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildGraphLayout, buildForceLayout, buildRadialLayout, filterGraphData, findDependents, simulateRisk, createCycloneDx, createSpdx,
  evaluateGate, findNameConfusions, buildThreatSignals,
} from '../src/utils/securityTools.js';

const report = {
  projectName: 'fixture-app', projectVersion: '1.0.0', generatedAt: '2026-01-01T00:00:00.000Z',
  projectRiskScore: 54, projectRiskLevel: 'HIGH', dataSource: 'live',
  coverage: { vulnerabilityStatus: 'ok', notes: [] },
  graph: {
    root: { id: '', name: 'fixture-app' },
    nodes: [
      { id: 'node_modules/express', name: 'express', version: '4.0.0', riskLevel: 'HIGH', isDirect: true },
      { id: 'node_modules/helper', name: 'helper', version: '1.0.0', riskLevel: 'NONE', isDirect: false },
      { id: 'node_modules/helper/node_modules/expresss', name: 'expresss', version: '1.0.0', riskLevel: 'NONE', isDirect: false },
    ],
    edges: [
      { from: 'node_modules/helper', to: 'node_modules/express' },
      { from: 'node_modules/helper', to: 'node_modules/helper/node_modules/expresss' },
    ],
  },
  dependencies: [
    { id: 'node_modules/express', name: 'express', version: '4.0.0', isDirect: true, riskLevel: 'HIGH', riskScore: 65, vulnerabilities: [{ id: 'OSV-1', severity: { label: 'HIGH' }, fixedVersions: ['4.1.0'] }], remediation: [{ type: 'upgrade', targetVersion: '4.1.0', resolvedAdvisories: ['OSV-1'] }], warnings: [], missingData: [], license: 'MIT' },
    { id: 'node_modules/helper', name: 'helper', version: '1.0.0', isDirect: false, riskLevel: 'NONE', riskScore: 0, vulnerabilities: [], remediation: [], warnings: [], missingData: [], license: 'unknown' },
    { id: 'node_modules/helper/node_modules/expresss', name: 'expresss', version: '1.0.0', isDirect: false, riskLevel: 'NONE', riskScore: 0, vulnerabilities: [], remediation: [], warnings: [{ category: 'lifecycle-script', message: 'Lockfile records install script.' }], missingData: [], license: 'unknown' },
  ],
};

test('graph layout uses only observed instances and lockfile edges', () => {
  const layout = buildGraphLayout(report);
  assert.equal(layout.nodes.length, 3);
  assert.equal(layout.edges.length, 2);
  assert.equal(layout.nodes.find((node) => node.id === 'node_modules/express').x, 70);
});

test('graph layout compacts dependency layers and keeps disconnected instances unconnected', () => {
  const layout = buildGraphLayout({ graph: {
    nodes: [
      { id: 'a', name: 'root-package', version: '1.0.0', isDirect: true },
      { id: 'b', name: 'middle-package', version: '1.0.0', isDirect: false },
      { id: 'c', name: 'leaf-package', version: '1.0.0', isDirect: false },
      { id: 'orphan', name: 'orphan-package', version: '1.0.0', isDirect: false },
    ],
    edges: [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }],
  } });
  const byId = new Map(layout.nodes.map((node) => [node.id, node]));
  assert.deepEqual(layout.edges, [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }]);
  assert.ok(byId.get('a').x < byId.get('b').x && byId.get('b').x < byId.get('c').x);
  assert.equal(byId.get('orphan').isolated, true);
  assert.equal(layout.width, 900);
});

test('force layout keeps actual connected edges only and places disconnected instances independently', () => {
  const data = { graph: {
    nodes: [{ id: 'a', name: 'alpha', isDirect: true }, { id: 'b', name: 'beta' }, { id: 'c', name: 'gamma' }],
    edges: [{ from: 'a', to: 'b' }, { from: 'missing', to: 'a' }],
  } };
  const layout = buildForceLayout(data);
  assert.deepEqual(layout.edges, [{ from: 'a', to: 'b' }]);
  assert.equal(layout.nodes.length, 3);
  assert.equal(new Set(layout.nodes.map((node) => `${node.x.toFixed(2)},${node.y.toFixed(2)}`)).size, 3);
  assert.deepEqual(buildForceLayout(data).nodes.map(({ x, y }) => [x, y]), layout.nodes.map(({ x, y }) => [x, y]));
});

test('radial layout centers the selected installed instance and retains disconnected nodes without edges', () => {
  const isolatedReport = { ...report, graph: { ...report.graph, nodes: [...report.graph.nodes, { id: 'orphan', name: 'orphan', version: '1.0.0' }] } };
  const radial = buildRadialLayout(isolatedReport, 'node_modules/express');
  const center = radial.nodes.find((node) => node.id === 'node_modules/express');
  const disconnected = radial.nodes.find((node) => node.id === 'orphan');
  assert.equal(center.x, radial.width / 2);
  assert.equal(center.y, radial.height / 2);
  assert.equal(disconnected.isolated, true);
  assert.equal(radial.edges.length, 2);
});

test('graph filters preserve node selection candidates and only edges whose endpoints remain visible', () => {
  const data = buildGraphLayout(report);
  const filtered = filterGraphData(data.nodes, data.edges, { query: 'helper', scope: 'TRANSITIVE' });
  assert.deepEqual(filtered.nodes.map((node) => node.id), ['node_modules/helper']);
  assert.deepEqual(filtered.edges, []);
  const severityFiltered = filterGraphData(data.nodes, data.edges, { severity: 'HIGH' });
  assert.deepEqual(severityFiltered.nodes.map((node) => node.id), ['node_modules/express']);
  assert.deepEqual(severityFiltered.edges, []);
});

test('reverse dependency exploration returns observed paths only', () => {
  const result = findDependents(report, 'node_modules/express');
  assert.deepEqual(result.direct, ['node_modules/helper']);
  assert.deepEqual(result.all, ['node_modules/helper']);
  assert.equal(findDependents(report, 'missing').known, false);
});

test('what-if projection leaves baseline score inputs untouched and follows project aggregation', () => {
  const before = report.dependencies.map((dep) => dep.riskScore);
  const result = simulateRisk(report, ['node_modules/express']);
  assert.equal(result.baselineScore, 43);
  assert.equal(result.projectedScore, 0);
  assert.deepEqual(report.dependencies.map((dep) => dep.riskScore), before);
});

test('what-if simulator leaves dependencies alone when a matched advisory lacks a complete fix', () => {
  const uncertain = { ...report, dependencies: [{ ...report.dependencies[0], vulnerabilities: [{ id: 'OSV-unknown', severity: { label: 'UNKNOWN' }, fixedVersions: [] }], remediation: [{ type: 'review-advisory', resolvedAdvisories: [] }] }] };
  const result = simulateRisk(uncertain, [uncertain.dependencies[0].id]);
  assert.equal(result.projectedScore, result.baselineScore);
  assert.deepEqual(result.assumedRemediated, []);
});

test('CycloneDX and SPDX exports preserve instances and only known graph relationships', () => {
  const cdx = createCycloneDx(report, '2026-01-01T00:00:00.000Z');
  assert.equal(cdx.specVersion, '1.5');
  assert.equal(cdx.components.length, 3);
  assert.equal(cdx.metadata.tools[0].name, 'SHIELDEX');
  assert.equal(cdx.metadata.tools[0].vendor, 'SHIELDEX');
  assert.equal(cdx.dependencies.find((item) => item.ref.includes('node_modules%2Fhelper')).dependsOn.length, 2);
  const spdx = createSpdx(report, '2026-01-01T00:00:00.000Z');
  assert.equal(spdx.spdxVersion, 'SPDX-2.3');
  assert.equal(spdx.creationInfo.creators[0], 'Tool: SHIELDEX');
  assert.match(spdx.documentNamespace, /^https:\/\/shieldex\.invalid\//);
  assert.equal(spdx.packages.length, 4);
  assert.equal(spdx.relationships.filter((item) => item.relationshipType === 'DEPENDS_ON').length, 3);
  assert.equal(spdx.packages.find((item) => item.name === 'helper').licenseDeclared, 'NOASSERTION');
});

test('SBOM generation refuses missing exact versions', () => {
  assert.throws(() => createCycloneDx({ ...report, dependencies: [{ ...report.dependencies[0], version: null }] }), /exact version/);
});

test('policy gate evaluates advisory threshold and unknown handling explicitly', () => {
  assert.equal(evaluateGate(report, { failOn: 'HIGH', unknown: 'fail' }).passed, false);
  assert.throws(() => evaluateGate(report, { failOn: 'URGENT' }), /Unsupported severity/);
  const unknownSeverity = { ...report, dependencies: [{ ...report.dependencies[0], vulnerabilities: [{ id: 'OSV-X', severity: { label: 'UNKNOWN' } }] }] };
  assert.equal(evaluateGate(unknownSeverity, { failOn: 'CRITICAL', unknown: 'fail' }).passed, false);
});

test('name similarity and signal center use explainable scan evidence', () => {
  assert.match(findNameConfusions(report.dependencies)[0].evidence, /one character/);
  const signals = buildThreatSignals(report);
  assert.ok(signals.some((item) => item.kind === 'confirmed' && item.source === 'OSV.dev'));
  assert.ok(signals.some((item) => item.kind === 'heuristic' && item.source === 'package-lock.json'));
});
