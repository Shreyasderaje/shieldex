import test from 'node:test';
import assert from 'node:assert/strict';
import {
  scorePackage,
  aggregateProjectScore,
  projectRiskLevel,
} from '../services/scoring.js';
import { buildRecommendations, sortRecommendations } from '../services/recommendations.js';
import { summarizePackument } from '../services/npmMeta.js';

const okMeta = {
  status: 'ok',
  latestVersion: '4.17.21',
  latestPublishedAt: '2021-02-20T14:00:00Z',
  installedPublishedAt: '2019-07-13T18:00:00Z',
  installedDeprecated: null,
  installedLicense: 'MIT',
  maintainers: 2,
};

test('a single HIGH advisory drives a HIGH score with evidence', () => {
  const r = scorePackage({
    name: 'lodash',
    version: '4.17.15',
    vulnerabilities: [{ id: 'GHSA-35jh-r3h4-6jhm', severity: { label: 'HIGH', score: null } }],
    vulnStatus: 'ok',
    meta: okMeta,
  });
  assert.equal(r.riskScore, 65);
  assert.equal(r.riskLevel, 'HIGH');
  assert.equal(r.confidence, 'high');
  assert.match(r.factors[0].evidence[0], /GHSA-35jh-r3h4-6jhm — HIGH/);
  assert.match(r.factors[0].evidence[0], /lodash@4\.17\.15/);
});

test('multiple advisories add increments and cap at 100', () => {
  const vulns = [
    { id: 'A', severity: { label: 'CRITICAL', score: 9.8 } },
    { id: 'B', severity: { label: 'HIGH', score: null } },
    { id: 'C', severity: { label: 'LOW', score: null } },
  ];
  const r = scorePackage({ name: 'x', version: '1.0.0', vulnerabilities: vulns, vulnStatus: 'ok', meta: okMeta });
  assert.equal(r.riskScore, 100); // 90 + 5 + 5 capped
  const r2 = scorePackage({
    name: 'x',
    version: '1.0.0',
    vulnerabilities: [{ id: 'A', severity: { label: 'CRITICAL', score: null } }, { id: 'B', severity: { label: 'HIGH', score: null } }],
    vulnStatus: 'ok',
    meta: okMeta,
  });
  assert.equal(r2.riskScore, 95);
});

test('old + single maintainer + copyleft license + outdated = score 0, warnings only', () => {
  const r = scorePackage({
    name: 'oldpkg',
    version: '1.0.0',
    vulnerabilities: [],
    vulnStatus: 'ok',
    hasInstallScript: true,
    meta: { ...okMeta, latestVersion: '9.0.0', installedPublishedAt: '2016-07-13T14:00:00Z', installedLicense: 'GPL-2.0' },
    now: new Date('2026-10-28T00:00:00Z'),
  });
  assert.equal(r.riskScore, 0);
  assert.equal(r.riskLevel, 'NONE');
  const cats = r.warnings.map((w) => w.category);
  assert.ok(cats.includes('maintenance'), 'outdated + stale warnings');
  assert.ok(cats.includes('lifecycle-script'));
  assert.ok(cats.includes('license-policy'));
  // None of the warnings claim a vulnerability:
  assert.ok(r.warnings.every((w) => !/vulnerab/i.test(w.message)));
});

test('unknown publish date is NEVER treated as stale', () => {
  const r = scorePackage({
    name: 'x',
    version: '1.0.0',
    vulnerabilities: [],
    vulnStatus: 'ok',
    meta: { ...okMeta, installedPublishedAt: 'unknown' },
  });
  assert.equal(r.riskScore, 0);
  assert.ok(!r.warnings.some((w) => w.id === 'stale'));
  assert.ok(r.missingData.includes('installed-version-publish-date'));
});

test('no vulnerability data => UNKNOWN score, not zero', () => {
  const r = scorePackage({ name: 'x', version: '1.0.0', vulnerabilities: [], vulnStatus: 'unavailable', meta: null });
  assert.equal(r.riskScore, null);
  assert.equal(r.riskLevel, 'UNKNOWN');
  assert.ok(r.missingData.includes('vulnerability-scan'));
  assert.ok(r.factors[0].evidence[0].includes('unavailable'));
});

test('unknown advisory severity lowers confidence and flags missing data', () => {
  const r = scorePackage({
    name: 'x',
    version: '1.0.0',
    vulnerabilities: [{ id: 'GHSA-X', severity: { label: 'UNKNOWN', score: null } }],
    vulnStatus: 'ok',
    meta: okMeta,
  });
  assert.equal(r.riskScore, 30);
  assert.equal(r.factors[0].confidence, 'low');
  assert.ok(r.missingData.includes('advisory-severity'));
});

test('partial OSV scan => medium confidence, noted in evidence', () => {
  const r = scorePackage({ name: 'x', version: '1.0.0', vulnerabilities: [], vulnStatus: 'partial', meta: okMeta });
  assert.equal(r.riskScore, 0);
  assert.equal(r.confidence, 'medium');
  assert.match(r.factors[0].evidence[0], /some queries failed/);
});

test('deprecated package produces maintenance warning with the registry message', () => {
  const r = scorePackage({
    name: 'request',
    version: '2.88.2',
    vulnerabilities: [],
    vulnStatus: 'ok',
    meta: { ...okMeta, installedDeprecated: 'request has been deprecated, see ...' },
  });
  const dep = r.warnings.find((w) => w.id === 'deprecated');
  assert.ok(dep);
  assert.match(dep.message, /request has been deprecated/);
});

test('project aggregation: documented weighted formula', () => {
  // worst 95, top5 = [95, 65, 40], mean = 66.67; all mean = 66.67
  const agg = aggregateProjectScore([95, 65, 40]);
  const expected = Math.round(0.5 * 95 + 0.3 * 66.6667 + 0.2 * 66.6667);
  assert.equal(agg.score, expected);
  assert.equal(agg.packagesScored, 3);
  assert.equal(aggregateProjectScore([]).score, null);
  assert.equal(projectRiskLevel(null), 'UNKNOWN');
  // Nulls (unscored packages) are excluded, not counted as zero
  const agg2 = aggregateProjectScore([null, null, 80]);
  assert.equal(agg2.packagesScored, 1);
  assert.equal(agg2.score, 80);
});

test('recommendations: upgrade target from OSV fixed-version evidence', () => {
  const recs = buildRecommendations({
    name: 'lodash',
    version: '4.17.15',
    vulnerabilities: [
      { id: 'GHSA-p6mc-m468-83gw', url: 'u1', fixedFor: { lodash: ['4.17.19'] } },
      { id: 'GHSA-35jh-r3h4-6jhm', url: 'u2', fixedFor: { lodash: ['4.17.21'] } },
    ],
    meta: okMeta,
  });
  const upgrade = recs.find((r) => r.type === 'upgrade');
  assert.ok(upgrade);
  assert.equal(upgrade.targetVersion, '4.17.21', 'highest minimal fix wins so all advisories resolve');
  assert.equal(upgrade.confidence, 'high');
  assert.equal(upgrade.uncertain, false);
  assert.match(upgrade.message, /OSV lists fixed version 4\.17\.21/);
  assert.ok(!/latest version fixes/i.test(upgrade.message), 'never claims latest auto-fixes');
});

test('recommendations: advisory without fixed version is flagged UNCERTAIN', () => {
  const recs = buildRecommendations({
    name: 'request',
    version: '2.88.2',
    vulnerabilities: [{ id: 'GHSA-p8p7-x288-28g6', url: 'u', fixedFor: {} }],
    meta: { ...okMeta, installedDeprecated: 'deprecated' },
  });
  const review = recs.find((r) => r.type === 'review-advisory');
  assert.ok(review);
  assert.equal(review.uncertain, true);
  assert.match(review.message, /UNCERTAIN/);
  assert.match(review.message, /no fixed version/);
  const replace = recs.find((r) => r.type === 'replace-deprecated');
  assert.ok(replace);
  assert.equal(replace.uncertain, true);
});

test('recommendations: major-version jump is labelled', () => {
  const recs = buildRecommendations({
    name: 'tough-cookie',
    version: '2.4.3',
    vulnerabilities: [{ id: 'GHSA-72xf-g2v4-qvf3', url: 'u', fixedFor: { 'tough-cookie': ['4.1.3'] } }],
    meta: okMeta,
  });
  const upgrade = recs.find((r) => r.type === 'upgrade');
  assert.equal(upgrade.majorBump, true);
  assert.match(upgrade.message, /major-version jump/);
});

test('recommendations: outdated-but-clean package is explicitly not a security claim', () => {
  const recs = buildRecommendations({
    name: 'webpack',
    version: '4.43.0',
    vulnerabilities: [],
    meta: { ...okMeta, latestVersion: '5.88.2' },
  });
  const upd = recs.find((r) => r.type === 'update-optional');
  assert.ok(upd);
  assert.match(upd.message, /not a security claim/);
  assert.ok(!recs.some((r) => r.type === 'upgrade'));
});

test('recommendations: sorted by type priority', () => {
  const sorted = sortRecommendations([
    { type: 'update-optional' },
    { type: 'review-advisory' },
    { type: 'upgrade' },
  ]);
  assert.deepEqual(sorted.map((r) => r.type), ['upgrade', 'review-advisory', 'update-optional']);
});

test('summarizePackument keeps installed/latest fields distinct and marks unknown', () => {
  const s = summarizePackument(
    {
      'dist-tags': { latest: '2.29.4' },
      time: { '2.24.0': '2019-01-24T14:00:00Z', '2.29.4': '2022-07-06T15:00:00Z' },
      versions: { '2.24.0': { license: 'MIT', deprecated: 'old message' } },
    },
    '2.24.0',
  );
  assert.equal(s.installedPublishedAt, '2019-01-24T14:00:00Z');
  assert.equal(s.latestPublishedAt, '2022-07-06T15:00:00Z');
  assert.equal(s.installedDeprecated, 'old message');
  assert.equal(s.installedLicense, 'MIT');
  assert.equal(s.latestVersion, '2.29.4');

  const s2 = summarizePackument({ 'dist-tags': { latest: '2.0.0' }, time: {} }, '1.0.0');
  assert.equal(s2.installedPublishedAt, 'unknown');
  assert.equal(s2.installedLicense, 'unknown');
  assert.equal(s2.installedDeprecated, null);
});
