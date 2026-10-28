import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAdvisory, extractFixedVersions, normalizeSeverity, pairKey } from '../services/osv.js';
import { cvss3BaseScore, severityLabelFromScore } from '../services/cvss.js';

test('cvss3BaseScore computes the canonical CVSS:3.1 examples', () => {
  // A well-known example vector with published base score 9.8
  const score = cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(score, 9.8);
  assert.equal(severityLabelFromScore(score), 'CRITICAL');
});

test('cvss3BaseScore rejects non-v3 vectors and incomplete metrics', () => {
  assert.equal(cvss3BaseScore('CVSS:4.0/AV:N/AC:L/PR:N/UI:N'), null);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L'), null);
  assert.equal(cvss3BaseScore('not a vector'), null);
});

test('normalizeSeverity prefers reviewed database_specific severity', () => {
  const sev = normalizeSeverity({ database_specific: { severity: 'HIGH' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] });
  assert.equal(sev.label, 'HIGH');
  assert.equal(sev.source, 'advisory-database');
});

test('normalizeSeverity falls back to CVSS vector, and to UNKNOWN otherwise', () => {
  const sev = normalizeSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] });
  assert.equal(sev.label, 'CRITICAL');
  assert.equal(sev.score, 9.8);
  assert.equal(normalizeSeverity({}).label, 'UNKNOWN');
});

test('normalizeSeverity maps MEDIUM to MODERATE', () => {
  assert.equal(normalizeSeverity({ database_specific: { severity: 'MEDIUM' } }).label, 'MODERATE');
});

test('extractFixedVersions collects fixed events per affected package', () => {
  const raw = {
    affected: [
      { package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '4.0.0' }, { fixed: '4.17.19' }] }] },
      { package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ fixed: '4.17.21' }] }] },
      { package: { name: 'other', ecosystem: 'npm' }, ranges: [{ events: [{ fixed: '2.0.0' }] }] },
    ],
  };
  const fixed = extractFixedVersions(raw);
  assert.deepEqual(fixed.get('lodash'), ['4.17.19', '4.17.21']);
  assert.deepEqual(fixed.get('other'), ['2.0.0']);
  assert.equal(extractFixedVersions({}).size, 0);
});

test('normalizeAdvisory produces the stable internal shape', () => {
  const adv = normalizeAdvisory({
    id: 'GHSA-35jh-r3h4-6jhm',
    summary: 'Command Injection in lodash',
    aliases: ['CVE-2021-23337'],
    database_specific: { severity: 'HIGH' },
    affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ fixed: '4.17.21' }] }] }],
  });
  assert.equal(adv.id, 'GHSA-35jh-r3h4-6jhm');
  assert.deepEqual(adv.aliases, ['CVE-2021-23337']);
  assert.equal(adv.severity.label, 'HIGH');
  assert.equal(adv.url, 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm');
  assert.deepEqual(adv.fixedFor.lodash, ['4.17.21']);
  assert.equal(normalizeAdvisory(null), null);
  assert.equal(normalizeAdvisory({ nope: 1 }), null);
});

test('pairKey is a plain name@version string', () => {
  assert.equal(pairKey('lodash', '4.17.15'), 'lodash@4.17.15');
});
