import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';
import { networkReport } from './fixtures/network-report.mjs';
import { buildForceLayout, filterGraphData, findDependents } from '../src/utils/securityTools.js';

test('local graph fixture supports filtering, selection, and evidence-backed path highlighting', () => {
  const layout = buildForceLayout(networkReport);
  assert.equal(layout.nodes.length, 4);
  assert.equal(layout.edges.length, 2);
  assert.equal(layout.nodes.find((node) => node.id.endsWith('/ash')).isolated, true);
  assert.deepEqual(filterGraphData(layout.nodes, layout.edges, { query: 'spruce' }).nodes.map((node) => node.name), ['spruce']);
  assert.deepEqual(findDependents(networkReport, 'node_modules/pine').all, ['node_modules/cedar/node_modules/spruce', 'node_modules/cedar']);
});

test('network component renders connected, selected, highlighted, and isolated fixture instances', async () => {
  const vite = await createServer({
    configFile: false,
    root: fileURLToPath(new URL('..', import.meta.url)),
    plugins: [react()],
    server: { middlewareMode: true },
    appType: 'custom',
  });
  try {
    const { default: NetworkGraph } = await vite.ssrLoadModule('/src/components/NetworkGraph.jsx');
    const markup = renderToStaticMarkup(React.createElement(NetworkGraph, {
      report: networkReport,
      selectedId: 'node_modules/cedar',
      highlightedIds: ['node_modules/cedar', 'node_modules/cedar/node_modules/spruce'],
      showFilters: true,
      showViewToggle: true,
    }));
    assert.equal((markup.match(/<g class="network-node /g) || []).length, 4);
    assert.equal((markup.match(/class="network-edge/g) || []).length, 2);
    assert.match(markup, /network-node direct selected path-active/);
    assert.match(markup, /network-node transitive .*path-active/);
    assert.match(markup, /ash@1\.0\.0/);
    assert.match(markup, /ISOLATED/);
    assert.match(markup, /Search/);
    assert.match(markup, /Compact list/);
  } finally {
    await vite.close();
  }
});

test('network component keeps isolated nodes rendered when no lockfile edges exist', async () => {
  const vite = await createServer({
    configFile: false,
    root: fileURLToPath(new URL('..', import.meta.url)),
    plugins: [react()],
    server: { middlewareMode: true },
    appType: 'custom',
  });
  try {
    const { default: NetworkGraph } = await vite.ssrLoadModule('/src/components/NetworkGraph.jsx');
    const emptyEdgesReport = { ...networkReport, graph: { ...networkReport.graph, edges: [] } };
    const markup = renderToStaticMarkup(React.createElement(NetworkGraph, { report: emptyEdgesReport }));
    assert.equal((markup.match(/<g class="network-node /g) || []).length, 4);
    assert.match(markup, /No resolved dependency relationships/);
    assert.match(markup, /Installed instances remain visible/);
  } finally {
    await vite.close();
  }
});
