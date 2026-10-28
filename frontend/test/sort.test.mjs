import test from 'node:test';
import assert from 'node:assert/strict';
import { sortRows, compareValues, isUnknown } from '../src/utils/sort.js';

const rows = (vals) => vals.map((v, i) => ({ id: i, name: `pkg-${i}`, v }));

test('numeric sort orders by value with unknowns last in both directions', () => {
  const asc = sortRows(rows([null, 90, 10, 'unknown', 45]), (r) => r.v, 'asc');
  assert.deepEqual(asc.map((r) => r.v), [10, 45, 90, null, 'unknown']);
  const desc = sortRows(rows([null, 90, 10, 'unknown', 45]), (r) => r.v, 'desc');
  assert.deepEqual(desc.map((r) => r.v), [90, 45, 10, null, 'unknown']);
});

test('riskScore null (unscored packages) sorts last even in descending order', () => {
  const data = [
    { name: 'a', riskScore: 0 },
    { name: 'b', riskScore: null },
    { name: 'c', riskScore: 70 },
  ];
  const desc = sortRows(data, (r) => r.riskScore, 'desc');
  assert.deepEqual(desc.map((r) => r.name), ['c', 'a', 'b']);
});

test('text sort is case-insensitive and locale-aware', () => {
  const data = [
    { name: 'lodash' },
    { name: 'Express' },
    { name: 'accepts' },
    { name: 'unknown' },
  ];
  const asc = sortRows(data, (r) => r.name, 'asc');
  assert.deepEqual(asc.map((r) => r.name), ['accepts', 'Express', 'lodash', 'unknown']);
});

test('version sort is semver-aware, not lexicographic', () => {
  const data = [
    { name: 'a', version: '1.10.0' },
    { name: 'b', version: '1.9.2' },
    { name: 'c', version: '2.0.0' },
    { name: 'd', version: 'unknown' },
    { name: 'e', version: '1.9.10' },
  ];
  const asc = sortRows(data, (r) => r.version, 'asc');
  assert.deepEqual(asc.map((r) => r.version), ['1.9.2', '1.9.10', '1.10.0', '2.0.0', 'unknown']);
});

test('same-name rows (multiple installed versions) are never merged', () => {
  const data = [
    { name: 'lodash', version: '4.17.15' },
    { name: 'lodash', version: '4.17.21' },
    { name: 'lodash', version: '4.17.21' },
  ];
  const out = sortRows(data, (r) => r.version, 'desc');
  assert.equal(out.length, 3);
  assert.deepEqual(out.map((r) => r.version), ['4.17.21', '4.17.21', '4.17.15']);
});

test('compareValues handles mixed shapes predictably', () => {
  assert.equal(compareValues('2.0.0', '10.0.0') < 0, true);
  assert.equal(compareValues('a', 'B') < 0, true);
  assert.equal(compareValues(true, false) > 0, true);
  assert.equal(compareValues('unknown', '1.0.0') > 0, true);
  assert.equal(compareValues(null, null), 0);
});

test('isUnknown recognizes the unknown family', () => {
  assert.equal(isUnknown(null), true);
  assert.equal(isUnknown(undefined), true);
  assert.equal(isUnknown('unknown'), true);
  assert.equal(isUnknown(' UNKNOWN '), true);
  assert.equal(isUnknown(''), true);
  assert.equal(isUnknown(0), false);
  assert.equal(isUnknown('1.0.0'), false);
});
