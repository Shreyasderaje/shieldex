import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeProject } from '../routes/analyze.js';
import { createDemoServices, DEMO_PACKAGE_JSON, DEMO_LOCK_JSON } from '../services/demoFixtures.js';
import { DEMO_NOTICE } from '../services/demoFixtures.js';

// ---- Pipeline integration test with stubbed services ----

function makeStubServices({ osvFails = false, registryFails = false, partialBatchFail = false } = {}) {
  return {
    queryVulnIds: async (pairs) => {
      if (osvFails) return { byKey: new Map(), okKeys: new Set(), failedKeys: new Set(pairs.map((p) => `${p.name}@${p.version}`)) };
      const byKey = new Map();
      if (!partialBatchFail) {
        for (const p of pairs) byKey.set(`${p.name}@${p.version}`, p.name === 'lodash' ? ['GHSA-P6MC'] : []);
        return { byKey, okKeys: new Set(byKey.keys()), failedKeys: new Set() };
      }
      // First pair's batch fails, rest succeed
      let first = true;
      const okKeys = new Set();
      for (const p of pairs) {
        const key = `${p.name}@${p.version}`;
        if (first) { first = false; continue; }
        byKey.set(key, []);
        okKeys.add(key);
      }
      return { byKey, okKeys, failedKeys: new Set(pairs.slice(0, 1).map((p) => `${p.name}@${p.version}`)) };
    },
    fetchAdvisories: async (ids) => ({
      advisories: new Map(
        ids.map((id) => [
          id,
          { id, aliases: [], summary: 'stub', published: null, url: `https://osv.dev/vulnerability/${id}`, severity: { label: 'HIGH', score: null, source: 'advisory-database' }, fixedFor: { lodash: ['4.17.21'] } },
        ]),
      ),
      failures: [],
    }),
    fetchRegistryMeta: async (names) => {
      if (registryFails) return { byName: new Map(), failures: new Map(names.map((n) => [n, 'boom'])) };
      const byName = new Map(
        names.map((n) => [
          n,
          {
            status: 'ok',
            latestVersion: '9.9.9',
            latestPublishedAt: '2026-01-01T00:00:00Z',
            installedPublishedAt: '2020-01-01T00:00:00Z',
            installedDeprecated: n === 'request' ? 'deprecated' : null,
            installedLicense: n === 'node-forge' ? 'GPL-2.0' : 'MIT',
            maintainers: 3,
          },
        ]),
      );
      return { byName, failures: new Map() };
    },
  };
}

const PKG = JSON.stringify({
  name: 'app',
  version: '1.0.0',
  dependencies: { lodash: '^4.17.15' },
  devDependencies: { tap: '^1.0.0' },
});
const LOCK = JSON.stringify({
  name: 'app',
  lockfileVersion: 3,
  packages: {
    '': { dependencies: { lodash: '^4.17.15' }, devDependencies: { tap: '^1.0.0' } },
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/tap': { version: '1.0.0', dev: true, hasInstallScript: true, dependencies: { lodash: '^4.0.0' } },
  },
});

test('analyzeProject: full happy path with stub services', async () => {
  const result = await analyzeProject({ packageJsonText: PKG, lockJsonText: LOCK }, makeStubServices());
  assert.equal(result.ok, true);
  assert.equal(result.dataSource, 'live');
  assert.equal(result.dependencies.length, 2);

  const lodash = result.dependencies.find((d) => d.name === 'lodash');
  assert.equal(lodash.riskLevel, 'HIGH');
  assert.equal(lodash.isDirect, true);
  assert.equal(lodash.vulnerabilities.length, 1);
  assert.ok(lodash.remediation.some((r) => r.type === 'upgrade' && r.targetVersion === '4.17.21'));
  assert.equal(lodash.installedPublishedAt, '2020-01-01T00:00:00Z');
  assert.equal(lodash.latestPublishedAt, '2026-01-01T00:00:00Z');

  const tap = result.dependencies.find((d) => d.name === 'tap');
  assert.equal(tap.devOnly, true);
  assert.ok(tap.hasInstallScript);
  assert.ok(tap.warnings.some((w) => w.category === 'lifecycle-script'));

  assert.equal(result.coverage.vulnerabilityStatus, 'ok');
  // Documented aggregation: 0.5×worst + 0.3×mean(top5) + 0.2×mean(all)
  const scores = result.dependencies.map((d) => d.riskScore);
  assert.ok(scores.every((s) => typeof s === 'number'));
  const expectedProject = Math.round(
    0.5 * Math.max(...scores) +
    0.3 * (scores.slice().sort((a, b) => b - a).slice(0, 5).reduce((a, b) => a + b, 0) / scores.length) +
    0.2 * (scores.reduce((a, b) => a + b, 0) / scores.length),
  );
  assert.equal(result.projectRiskScore, expectedProject);
  assert.ok(result.graph.edges.some((e) => e.from === 'node_modules/tap' && e.to === 'node_modules/lodash'));
});

test('analyzeProject: total OSV failure => UNKNOWN scores, coverage explains', async () => {
  const result = await analyzeProject({ packageJsonText: PKG, lockJsonText: LOCK }, makeStubServices({ osvFails: true }));
  assert.equal(result.coverage.vulnerabilityStatus, 'unavailable');
  assert.ok(result.dependencies.every((d) => d.riskLevel === 'UNKNOWN' && d.riskScore === null));
  assert.equal(result.projectRiskScore, null);
  assert.ok(result.coverage.notes.some((n) => /OSV\.dev query failed entirely/.test(n)));
});

test('analyzeProject: partial failure => partial status and notes', async () => {
  const result = await analyzeProject({ packageJsonText: PKG, lockJsonText: LOCK }, makeStubServices({ partialBatchFail: true }));
  assert.equal(result.coverage.vulnerabilityStatus, 'partial');
  assert.equal(result.coverage.osvQueriesFailed, 1);
  const lodash = result.dependencies.find((d) => d.name === 'lodash');
  assert.equal(lodash.riskLevel, 'UNKNOWN', 'the failed package must not be assumed safe');
});

test('analyzeProject: registry failure => unknown metadata, scan still works', async () => {
  const result = await analyzeProject({ packageJsonText: PKG, lockJsonText: LOCK }, makeStubServices({ registryFails: true }));
  const lodash = result.dependencies.find((d) => d.name === 'lodash');
  assert.equal(lodash.latestVersion, 'unknown');
  assert.equal(lodash.installedPublishedAt, 'unknown');
  assert.equal(lodash.license, 'unknown');
  assert.ok(lodash.missingData.includes('npm-metadata'));
  assert.equal(lodash.riskLevel, 'HIGH', 'vulnerability scoring unaffected');
  assert.ok(result.coverage.registryFailures > 0);
});

test('analyzeProject: rejects invalid uploads', async () => {
  const bad1 = await analyzeProject({ packageJsonText: '{oops' }, makeStubServices());
  assert.equal(bad1.ok, false);
  assert.equal(bad1.status, 400);
  const bad2 = await analyzeProject({}, makeStubServices());
  assert.equal(bad2.ok, false);
  const bad3 = await analyzeProject({ packageJsonText: JSON.stringify({ name: 'x' }), lockJsonText: JSON.stringify({ nope: true }) }, makeStubServices());
  assert.equal(bad3.ok, false);
  const big = await analyzeProject(
    { packageJsonText: JSON.stringify({ name: 'x' }), lockJsonText: JSON.stringify({ junk: 'x'.repeat(5 * 1024 * 1024) }) },
    makeStubServices(),
  );
  assert.equal(big.ok, false);
  assert.match(big.error, /too large/);
});

test('analyzeProject: no lockfile => scan skipped with explicit note', async () => {
  const result = await analyzeProject({ packageJsonText: PKG, lockJsonText: null }, makeStubServices());
  assert.equal(result.ok, true);
  assert.equal(result.coverage.vulnerabilityStatus, 'skipped-no-exact-version');
  assert.ok(result.dependencies.every((d) => d.riskLevel === 'UNKNOWN'));
});

// ---- Demo pipeline runs end-to-end and is clearly labelled ----

test('demo fixtures: internally consistent scan through the real pipeline', async () => {
  const result = await analyzeProject(
    { packageJsonText: DEMO_PACKAGE_JSON, lockJsonText: DEMO_LOCK_JSON },
    createDemoServices(),
    { source: 'demo-fixture' },
  );
  assert.equal(result.ok, true);
  assert.equal(result.dataSource, 'demo-fixture');
  assert.equal(result.coverage.vulnerabilityStatus, 'ok');

  const byPath = new Map(result.dependencies.map((d) => [d.id, d]));

  // Root lodash 4.17.15 is affected by two HIGH advisories => HIGH risk
  const lodashTop = byPath.get('node_modules/lodash');
  assert.equal(lodashTop.version, '4.17.15');
  assert.equal(lodashTop.riskLevel, 'HIGH');
  assert.equal(lodashTop.vulnerabilities.length, 2);
  assert.ok(lodashTop.remediation.some((r) => r.type === 'upgrade' && r.targetVersion === '4.17.21'));

  // Nested lodash 4.17.21 (under webpack) is FIXED => NONE risk, separate row
  const lodashNested = byPath.get('node_modules/webpack/node_modules/lodash');
  assert.equal(lodashNested.version, '4.17.21');
  assert.equal(lodashNested.riskLevel, 'NONE');
  assert.equal(lodashNested.vulnerabilities.length, 0);
  assert.equal(lodashNested.devOnly, true);

  // request: SSRF advisory with no fixed version => uncertain remediation + deprecated warning
  const request = byPath.get('node_modules/request');
  assert.ok(request.remediation.some((r) => r.type === 'review-advisory' && r.uncertain));
  assert.ok(request.warnings.some((w) => w.id === 'deprecated'));

  // node-forge: GPL-2.0 in license => separate license-policy warning, score still vuln-only
  const forge = byPath.get('node_modules/node-forge');
  assert.equal(forge.license, 'BSD-3-Clause; GPL-2.0');
  assert.ok(forge.warnings.some((w) => w.category === 'license-policy'));
  assert.equal(forge.riskLevel, 'HIGH');

  // node-sass: hasInstallScript => lifecycle-script warning
  const sass = byPath.get('node_modules/node-sass');
  assert.ok(sass.warnings.some((w) => w.category === 'lifecycle-script'));

  // left-pad: published 2016 => stale warning with known date, but score NONE
  const leftPad = byPath.get('node_modules/left-pad');
  assert.ok(leftPad.warnings.some((w) => w.id === 'stale'));
  assert.equal(leftPad.riskLevel, 'NONE');

  // duplicates summary reflects the two lodash versions
  assert.ok(result.duplicates.some((d) => d.name === 'lodash'));
});

test('demo notice text clearly separates fixtures from live results', () => {
  assert.match(DEMO_NOTICE, /SIMULATED DEMO DATA/);
  assert.match(DEMO_NOTICE, /NOT from a live OSV/);
});
