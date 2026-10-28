import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicy } from '../services/policy.js';

const report = { dependencies: [
  { name: 'alpha', version: '1.0.0', riskLevel: 'HIGH', vulnerabilities: [{ id: 'OSV-A', severity: { label: 'HIGH' } }] },
  { name: 'beta', version: '2.0.0', riskLevel: 'UNKNOWN', vulnerabilities: [] },
] };

test('security policy fails at or above its configured severity threshold', () => {
  assert.equal(evaluatePolicy(report, { failOn: 'HIGH' }).passed, false);
  assert.equal(evaluatePolicy(report, { failOn: 'CRITICAL' }).passed, true);
});

test('unknown coverage can warn, fail, or be explicitly ignored', () => {
  assert.equal(evaluatePolicy(report, { failOn: 'CRITICAL', unknown: 'warn' }).passed, true);
  assert.equal(evaluatePolicy(report, { failOn: 'CRITICAL', unknown: 'fail' }).passed, false);
  assert.equal(evaluatePolicy(report, { failOn: 'CRITICAL', unknown: 'ignore' }).passed, true);
});

test('unknown advisory severity is handled as unknown scan evidence', () => {
  const unknownSeverity = { dependencies: [{ name: 'gamma', version: '1.0.0', riskLevel: 'MODERATE', vulnerabilities: [{ id: 'OSV-X', severity: { label: 'UNKNOWN' } }] }] };
  assert.equal(evaluatePolicy(unknownSeverity, { failOn: 'CRITICAL', unknown: 'fail' }).passed, false);
});

test('security policy rejects unsupported configuration', () => {
  assert.throws(() => evaluatePolicy(report, { failOn: 'URGENT' }), /Unsupported fail-on/);
  assert.throws(() => evaluatePolicy(report, { unknown: 'guess' }), /Unsupported unknown/);
});
