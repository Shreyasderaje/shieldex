// OSV.dev client — REAL vulnerability detection.
//
// 1. POST /v1/querybatch with the exact resolved (name, version) pairs of
//    every installed package instance. This returns matching advisory IDs.
// 2. GET /v1/vulns/{id} for each unique advisory ID (deduplicated across
//    packages) to get severity and affected/fixed ranges.
//
// npm registry metadata is never treated as vulnerability data: if OSV
// cannot be reached, packages are reported as "vulnerability data
// unavailable", never as "no vulnerabilities".

import { fetchJson, mapPool, chunk } from './http.js';
import { cvss3BaseScore, severityLabelFromScore } from './cvss.js';

const OSV_BASE = process.env.OSV_BASE_URL || 'https://api.osv.dev';
const QUERYBATCH_SIZE = 100; // OSV allows up to 1000 queries per batch; stay small for reliability
const DETAIL_CONCURRENCY = 6;
const BATCH_CONCURRENCY = 3;
const TIMEOUT_MS = Number(process.env.OSV_TIMEOUT_MS || 15000);

export const pairKey = (name, version) => `${name}@${version}`;

/**
 * @param {Array<{name: string, version: string}>} pairs exact resolved versions
 * @returns {Promise<{byKey: Map<string, string[]>, okKeys: Set<string>, failedKeys: Set<string>}>}
 */
export async function queryVulnIds(pairs, { fetchImpl = globalThis.fetch, log = () => {} } = {}) {
  // Deduplicate identical (name, version) queries — many instances share one
  // package version (e.g. lodash installed once but required by 5 packages).
  const unique = new Map();
  for (const { name, version } of pairs) {
    if (!name || !version) continue;
    const key = pairKey(name, version);
    if (!unique.has(key)) unique.set(key, { key, name, version });
  }
  const list = [...unique.values()];
  const byKey = new Map();
  const failedKeys = new Set();

  if (list.length) {
    const batches = chunk(list, QUERYBATCH_SIZE);
    const results = await mapPool(batches, BATCH_CONCURRENCY, async (batch) => {
      const body = {
        queries: batch.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })),
      };
      const { json } = await fetchJson(`${OSV_BASE}/v1/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
      if (!json || !Array.isArray(json.results) || json.results.length !== batch.length) {
        throw new Error('querybatch response shape invalid (results array mismatch)');
      }
      return batch.map((p, i) => {
        const entry = json.results[i];
        const ids = entry && Array.isArray(entry.vulns)
          ? entry.vulns.map((v) => (v && typeof v.id === 'string' ? v.id : null)).filter(Boolean)
          : [];
        return { key: p.key, ids };
      });
    });

    for (const result of results) {
      if (result.ok) {
        for (const { key, ids } of result.value) byKey.set(key, ids);
      } else {
        // Graceful partial failure: the whole batch failed; mark those keys.
        log(`querybatch batch failed: ${result.error.message}`);
      }
    }
    for (const p of list) {
      if (!byKey.has(p.key)) failedKeys.add(p.key);
    }
  }

  return { byKey, okKeys: new Set(byKey.keys()), failedKeys };
}

/** Severity of an advisory, normalized to {label, score, source}. */
export function normalizeSeverity(raw) {
  const dbSpecific = raw && raw.database_specific ? raw.database_specific : null;
  if (dbSpecific && typeof dbSpecific.severity === 'string') {
    const label = dbSpecific.severity.toUpperCase();
    if (['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW', 'NONE'].includes(label)) {
      return { label: label === 'MEDIUM' ? 'MODERATE' : label, score: null, source: 'advisory-database' };
    }
  }
  if (Array.isArray(raw && raw.severities ? raw.severities : raw ? raw.severity : null)) {
    const severities = raw.severities || raw.severity;
    const cvssEntry = severities.find((s) => s && s.type === 'CVSS_V3' && typeof s.score === 'string');
    if (cvssEntry) {
      const score = cvss3BaseScore(cvssEntry.score);
      if (score !== null) return { label: severityLabelFromScore(score), score, source: 'cvss-v3' };
    }
  }
  if (raw && raw.cvss_score !== undefined && Number.isFinite(Number(raw.cvss_score))) {
    const score = Number(raw.cvss_score);
    return { label: severityLabelFromScore(score), score, source: 'advisory-database' };
  }
  return { label: 'UNKNOWN', score: null, source: null };
}

/**
 * Extracts, per affected package, the OSV-listed fixed versions
 * (affected[].ranges[].events[].fixed). This is the evidence base for
 * remediation advice.
 */
export function extractFixedVersions(raw) {
  const fixed = new Map();
  if (!raw || !Array.isArray(raw.affected)) return fixed;
  for (const affected of raw.affected) {
    const pkgName = affected && affected.package && affected.package.name;
    if (!pkgName) continue;
    const versions = fixed.get(pkgName) || [];
    if (Array.isArray(affected.ranges)) {
      for (const range of affected.ranges) {
        if (!range || !Array.isArray(range.events)) continue;
        for (const event of range.events) {
          if (event && typeof event.fixed === 'string') versions.push(event.fixed);
        }
      }
    }
    fixed.set(pkgName, versions);
  }
  return fixed;
}

/** Normalizes a raw OSV /v1/vulns/{id} document into our advisory shape. */
export function normalizeAdvisory(raw) {
  if (!raw || typeof raw.id !== 'string') return null;
  const severity = normalizeSeverity(raw);
  return {
    id: raw.id,
    aliases: Array.isArray(raw.aliases) ? raw.aliases : [],
    summary: typeof raw.summary === 'string' ? raw.summary : typeof raw.details === 'string' ? raw.details.slice(0, 200) : '',
    published: typeof raw.published === 'string' ? raw.published : null,
    url: raw.id && typeof raw.id === 'string' && raw.id.startsWith('GHSA-')
      ? `https://github.com/advisories/${raw.id}`
      : `https://osv.dev/vulnerability/${raw.id}`,
    severity,
    fixedFor: Object.fromEntries(extractFixedVersions(raw)),
  };
}

/**
 * Fetches full advisory documents for unique IDs with bounded concurrency.
 * @returns {Promise<{advisories: Map<string, object>, failures: Array<{id: string, error: string}>}>}
 */
export async function fetchAdvisories(ids, { fetchImpl = globalThis.fetch, log = () => {} } = {}) {
  const uniqueIds = [...new Set(ids)].filter((id) => typeof id === 'string' && id);
  const advisories = new Map();
  const failures = [];
  const results = await mapPool(uniqueIds, DETAIL_CONCURRENCY, async (id) => {
    const { json } = await fetchJson(`${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`, {
      headers: { Accept: 'application/json' },
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
    if (!json || typeof json.id !== 'string') throw new Error('advisory response shape invalid');
    return normalizeAdvisory(json);
  });
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (result.ok && result.value) advisories.set(uniqueIds[i], result.value);
    else {
      failures.push({ id: uniqueIds[i], error: result.error ? result.error.message : 'unknown' });
      log(`advisory fetch failed for ${uniqueIds[i]}: ${result.error && result.error.message}`);
    }
  }
  return { advisories, failures };
}
