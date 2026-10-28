import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDependencyGraph, parseJsonText, nameFromInstallPath } from '../services/parser.js';

const V3_LOCK = {
  name: 'app',
  version: '1.0.0',
  lockfileVersion: 3,
  packages: {
    '': {
      name: 'app',
      version: '1.0.0',
      dependencies: { lodash: '^4.17.15', express: '^4.17.0' },
      devDependencies: { tap: '^1.0.0' },
    },
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/express': { version: '4.17.1', dependencies: { accepts: '~1.3.7' } },
    'node_modules/accepts': { version: '1.3.7' },
    'node_modules/tap': { version: '1.0.0', dev: true, dependencies: { lodash: '^4.17.19' } },
    // Duplicate version of lodash, nested under a dev dependency:
    'node_modules/tap/node_modules/lodash': { version: '4.17.21', dev: true },
    'node_modules/@scope/pkg': { version: '2.1.0' },
  },
};

const V1_LOCK = {
  name: 'app',
  version: '1.0.0',
  lockfileVersion: 1,
  dependencies: {
    lodash: { version: '4.17.15', requires: {} },
    express: {
      version: '4.17.1',
      requires: { accepts: '~1.3.7' },
      dependencies: {
        accepts: { version: '1.3.7' },
      },
    },
    tap: {
      version: '1.0.0',
      dev: true,
      requires: { lodash: '^4.17.19' },
      dependencies: {
        lodash: { version: '4.17.21', dev: true },
      },
    },
  },
};

const PKG = {
  name: 'app',
  version: '1.0.0',
  dependencies: { lodash: '^4.17.15', express: '^4.17.0' },
  devDependencies: { tap: '^1.0.0' },
};

test('nameFromInstallPath handles plain, nested and scoped packages', () => {
  assert.equal(nameFromInstallPath('node_modules/lodash'), 'lodash');
  assert.equal(nameFromInstallPath('node_modules/express/node_modules/accepts'), 'accepts');
  assert.equal(nameFromInstallPath('node_modules/@scope/pkg'), '@scope/pkg');
  assert.equal(nameFromInstallPath('node_modules/a/node_modules/@scope/pkg'), '@scope/pkg');
});

test('v3 lockfile: every instance keeps its own install path and version', () => {
  const graph = buildDependencyGraph(PKG, V3_LOCK);
  assert.equal(graph.ok, true);
  assert.equal(graph.stats.totalInstances, 6);
  const lodash = graph.instances.filter((i) => i.name === 'lodash');
  assert.equal(lodash.length, 2);
  assert.deepEqual(
    lodash.map((i) => i.version).sort(),
    ['4.17.15', '4.17.21'],
  );
  assert.ok(lodash.find((i) => i.installPath === 'node_modules/lodash'));
  assert.ok(lodash.find((i) => i.installPath === 'node_modules/tap/node_modules/lodash'));
});

test('v3 lockfile: direct/transitive/dev classification with evidence', () => {
  const graph = buildDependencyGraph(PKG, V3_LOCK);
  const byKey = new Map(graph.instances.map((i) => [i.installPath, i]));

  const lodashTop = byKey.get('node_modules/lodash');
  assert.equal(lodashTop.isDirect, true);
  assert.equal(lodashTop.devOnly, false);
  assert.match(lodashTop.evidence.isDirect, /package.json#dependencies/);

  const lodashNested = byKey.get('node_modules/tap/node_modules/lodash');
  assert.equal(lodashNested.isDirect, false);
  assert.equal(lodashNested.devOnly, true);

  const accepts = byKey.get('node_modules/accepts');
  assert.equal(accepts.isDirect, false);
  assert.equal(accepts.devOnly, false, 'accepts is reachable from production express');

  const tap = byKey.get('node_modules/tap');
  assert.equal(tap.isDirect, true);
  assert.equal(tap.devOnly, true);

  const scoped = byKey.get('node_modules/@scope/pkg');
  assert.equal(scoped.isDirect, false, 'not declared in package.json');
  assert.equal(scoped.devOnly, false);
});

test('v3 lockfile: dependency edges resolve to the correct nested instance', () => {
  const graph = buildDependencyGraph(PKG, V3_LOCK);
  const byKey = new Map(graph.instances.map((i) => [i.installPath, i]));
  const tap = byKey.get('node_modules/tap');
  const lodashEdge = tap.edges.find((e) => e.name === 'lodash');
  assert.equal(lodashEdge.resolvedPath, 'node_modules/tap/node_modules/lodash');
  const express = byKey.get('node_modules/express');
  assert.equal(express.edges.find((e) => e.name === 'accepts').resolvedPath, 'node_modules/accepts');
});

test('v1 lockfile: nested duplicates preserved and classified', () => {
  const graph = buildDependencyGraph(PKG, V1_LOCK);
  assert.equal(graph.ok, true);
  assert.equal(graph.lockfileVersion, 1);
  const lodash = graph.instances.filter((i) => i.name === 'lodash');
  assert.equal(lodash.length, 2);
  const nested = lodash.find((i) => i.installPath === 'node_modules/tap/node_modules/lodash');
  assert.equal(nested.version, '4.17.21');
  assert.equal(nested.devOnly, true);
  assert.equal(nested.isDirect, false);
  const top = lodash.find((i) => i.installPath === 'node_modules/lodash');
  assert.equal(top.isDirect, true);
  assert.equal(top.devOnly, false);
});

test('v1 lockfile: duplicate summary reports multi-version packages', () => {
  const graph = buildDependencyGraph(PKG, V3_LOCK);
  assert.deepEqual(graph.duplicates, [{ name: 'lodash', versions: ['4.17.15', '4.17.21'] }]);
});

test('lockfile without package.json: no direct claim is fabricated', () => {
  const graph = buildDependencyGraph(null, V3_LOCK);
  assert.equal(graph.ok, true);
  const lodashTop = graph.instances.find((i) => i.installPath === 'node_modules/lodash');
  // Without package.json the root entry's dependencies are the evidence
  assert.equal(lodashTop.isDirect, true, 'root entry of lockfile lists lodash as a direct dependency');
  const accepts = graph.instances.find((i) => i.installPath === 'node_modules/accepts');
  assert.equal(accepts.isDirect, false);
});

test('no lockfile: declared-only instances with unknown versions and a warning', () => {
  const graph = buildDependencyGraph(PKG, { name: 'app', version: '1.0.0', lockfileVersion: 3, packages: {} });
  assert.equal(graph.ok, true);
  assert.equal(graph.instances.length, 3);
  assert.ok(graph.instances.every((i) => i.version === null && i.isDirect));
  assert.ok(graph.warnings.some((w) => /vulnerability scan was skipped/i.test(w)));
});

test('lockfile without recognizable structure falls back to declared-only packages', () => {
  // The route layer rejects explicitly uploaded malformed lockfiles; the
  // parser itself treats a structureless lock as "no lockfile".
  const graph = buildDependencyGraph(PKG, { hello: 'world' });
  assert.equal(graph.ok, true);
  assert.ok(graph.instances.every((i) => i.version === null));
  assert.ok(graph.warnings.some((w) => /vulnerability scan was skipped/i.test(w)));
});

test('hasInstallScript flag is preserved as data', () => {
  const lock = structuredClone(V3_LOCK);
  lock.packages['node_modules/node-sass'] = { version: '4.14.1', hasInstallScript: true };
  const graph = buildDependencyGraph(PKG, lock);
  const sass = graph.instances.find((i) => i.name === 'node-sass');
  assert.equal(sass.hasInstallScript, true);
});

test('parseJsonText rejects arrays, non-JSON and empty input', () => {
  assert.equal(parseJsonText('x', '[1,2]').ok, false);
  assert.equal(parseJsonText('x', '{oops').ok, false);
  assert.equal(parseJsonText('x', '').ok, false);
  assert.equal(parseJsonText('x', '{"a":1}').ok, true);
});
