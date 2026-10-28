// POST /api/analyze — orchestrates: parse → OSV scan → npm metadata →
// scoring → recommendations → project aggregate → response with coverage.
//
// The live OSV/registry service implementations are injected so the demo
// endpoint and the test suite can run the same pipeline against fixtures.
//
// SECURITY: uploaded content is only ever JSON.parse()'d. No code from the
// upload is executed, no dependencies are installed, no lifecycle scripts
// are run, and no commands are derived from user input.

import express from 'express';
import { parseJsonText, buildDependencyGraph } from '../services/parser.js';
import { queryVulnIds as liveQueryVulnIds, fetchAdvisories as liveFetchAdvisories, pairKey } from '../services/osv.js';
import { fetchRegistryMeta as liveFetchRegistryMeta, summarizePackument } from '../services/npmMeta.js';
import { scorePackage, aggregateProjectScore, projectRiskLevel, DEFAULT_LICENSE_POLICY } from '../services/scoring.js';
import { buildRecommendations, sortRecommendations } from '../services/recommendations.js';
import { createDemoServices, DEMO_NOTICE, DEMO_PACKAGE_JSON, DEMO_LOCK_JSON } from '../services/demoFixtures.js';

const MAX_FILE_BYTES = 4 * 1024 * 1024; // 4 MB per uploaded file
const LICENSE_POLICY = process.env.LICENSE_POLICY
  ? process.env.LICENSE_POLICY.split(',').map((s) => s.trim()).filter(Boolean)
  : DEFAULT_LICENSE_POLICY;

function fileSizeOk(label, text, errors) {
  const bytes = typeof text === 'string' ? Buffer.byteLength(text, 'utf8') : 0;
  if (bytes > MAX_FILE_BYTES) {
    errors.push(`${label} is too large (${(bytes / 1024 / 1024).toFixed(1)} MB, limit 4 MB)`);
    return false;
  }
  return true;
}

export async function analyzeProject({ packageJsonText, lockJsonText }, svc, { source = 'live' } = {}) {
  const coverage = {
    source,
    lockfileVersion: null,
    totalInstances: 0,
    uniquePackages: 0,
    uniqueNameVersionPairs: 0,
    osvQueriesSent: 0,
    osvQueriesFailed: 0,
    advisoriesMatched: 0,
    advisoryDetailFailures: 0,
    registryLookups: 0,
    registryFailures: 0,
    vulnerabilityStatus: 'ok',
    notes: [],
  };

  const errors = [];
  const pkgParsed = packageJsonText ? parseJsonText('package.json', packageJsonText) : null;
  if (packageJsonText && !pkgParsed.ok) errors.push(pkgParsed.error);
  const lockParsed = lockJsonText ? parseJsonText('package-lock.json', lockJsonText) : null;
  if (lockJsonText && !lockParsed.ok) errors.push(lockParsed.error);
  if (!packageJsonText && !lockJsonText) errors.push('Upload at least one of package.json or package-lock.json');
  if (errors.length) return { ok: false, status: 400, error: errors.join('; ') };

  fileSizeOk('package.json', packageJsonText, errors);
  fileSizeOk('package-lock.json', lockJsonText, errors);
  if (errors.length) return { ok: false, status: 400, error: errors.join('; ') };

  const pkg = pkgParsed ? pkgParsed.value : null;
  const lock = lockParsed ? lockParsed.value : null;

  // An explicitly uploaded lockfile must actually look like one (v1/v2/v3).
  if (lock && !lock.packages && !lock.dependencies) {
    return { ok: false, status: 400, error: 'package-lock.json does not look like an npm lockfile (missing `packages` or `dependencies` map)' };
  }

  // Structural validation of the lockfile happens inside buildDependencyGraph.
  const graph = buildDependencyGraph(pkg, lock);
  if (!graph.ok) return { ok: false, status: 400, error: graph.error };
  const { instances } = graph;
  coverage.lockfileVersion = graph.lockfileVersion;
  coverage.totalInstances = graph.stats.totalInstances;
  coverage.uniquePackages = graph.stats.uniquePackages;
  coverage.notes.push(...graph.warnings);

  const scannable = instances.filter((inst) => inst.version);
  const declaredOnly = instances.filter((inst) => !inst.version);
  if (declaredOnly.length) {
    coverage.notes.push(
      `${declaredOnly.length} declared package(s) have no exact installed version (no lockfile) — they were not vulnerability-scanned.`,
    );
  }

  // ---- 1. OSV querybatch on exact resolved versions ----
  const pairs = scannable.map((inst) => ({ name: inst.name, version: inst.version }));
  coverage.osvQueriesSent = new Set(pairs.map((p) => pairKey(p.name, p.version))).size;
  const { byKey, okKeys, failedKeys } = pairs.length
    ? await svc.queryVulnIds(pairs)
    : { byKey: new Map(), okKeys: new Set(), failedKeys: new Set() };
  coverage.osvQueriesFailed = pairs.length
    ? new Set(pairs.map((p) => pairKey(p.name, p.version))).size - okKeys.size
    : 0;

  // ---- 2. Advisory details (deduplicated across packages) ----
  const allIds = [...new Set([...byKey.values()].flat())];
  coverage.advisoriesMatched = allIds.length;
  const { advisories, failures: advisoryFailures } = allIds.length
    ? await svc.fetchAdvisories(allIds)
    : { advisories: new Map(), failures: [] };
  coverage.advisoryDetailFailures = advisoryFailures.length;
  if (advisoryFailures.length) {
    coverage.notes.push(
      `${advisoryFailures.length} advisory detail(s) could not be fetched (${advisoryFailures.map((f) => f.id).join(', ')}); affected packages may be undercounted.`,
    );
  }

  // Global + per-instance vulnerability status
  const totalQueryKeys = new Set(pairs.map((p) => pairKey(p.name, p.version))).size;
  if (totalQueryKeys === 0) {
    coverage.vulnerabilityStatus = declaredOnly.length ? 'skipped-no-exact-version' : 'ok';
  } else if (okKeys.size === 0) {
    coverage.vulnerabilityStatus = 'unavailable';
    coverage.notes.push('OSV.dev query failed entirely — packages are reported as UNKNOWN, not as vulnerability-free.');
  } else if (coverage.osvQueriesFailed > 0 || advisoryFailures.length > 0) {
    coverage.vulnerabilityStatus = 'partial';
  }

  // ---- 3. npm metadata for installed + latest versions ----
  const names = [...new Set(instances.map((inst) => inst.name))];
  coverage.registryLookups = names.length;
  const { byName: metaByName, failures: registryFailures } = names.length
    ? await svc.fetchRegistryMeta(names)
    : { byName: new Map(), failures: new Map() };
  coverage.registryFailures = registryFailures.size;
  if (registryFailures.size) {
    coverage.notes.push(
      `npm registry metadata unavailable for ${registryFailures.size} package(s): ${[...registryFailures.keys()].join(', ')}. Fields are marked unknown.`,
    );
  }

  // ---- 4. Score every instance ----
  const dependencies = [];
  const licensePolicy = LICENSE_POLICY;
  for (const inst of instances) {
    const key = inst.version ? pairKey(inst.name, inst.version) : null;
    const matchedIds = key ? byKey.get(key) || [] : [];
    const vulnerabilities = matchedIds
      .map((id) => advisories.get(id))
      .filter(Boolean);

    let vulnStatus;
    if (!inst.version) vulnStatus = 'skipped-no-exact-version';
    else if (!okKeys.has(key)) vulnStatus = 'unavailable';
    else vulnStatus = 'ok';

    const rawMeta = metaByName.get(inst.name);
    // Live registry lookups return raw packuments — derive per-version fields
    // for the installed version. Service stubs/demo fixtures return already
    // summarized objects (status field set) and pass through unchanged.
    const meta = rawMeta
      ? rawMeta.status === 'ok' || rawMeta.status === 'not_found'
        ? rawMeta
        : summarizePackument(rawMeta, inst.version)
      : null;

    const scored = scorePackage({
      name: inst.name,
      version: inst.version,
      vulnerabilities,
      vulnStatus,
      meta,
      hasInstallScript: inst.hasInstallScript,
      licensePolicy,
    });

    const remediation = sortRecommendations(
      buildRecommendations({ name: inst.name, version: inst.version, vulnerabilities, meta }),
    );

    dependencies.push({
      id: inst.installPath,
      name: inst.name,
      version: inst.version,
      declaredRange: inst.declaredRange || null,
      isDirect: inst.isDirect,
      devOnly: inst.devOnly,
      optional: inst.optionalFlag,
      hasInstallScript: inst.hasInstallScript,
      evidence: inst.evidence,
      latestVersion: meta && meta.status === 'ok' ? meta.latestVersion : 'unknown',
      installedPublishedAt: meta && meta.status === 'ok' ? meta.installedPublishedAt : 'unknown',
      latestPublishedAt: meta && meta.status === 'ok' ? meta.latestPublishedAt : 'unknown',
      installedDeprecated: meta && meta.status === 'ok' ? meta.installedDeprecated : null,
      license: meta && meta.status === 'ok' ? meta.installedLicense : 'unknown',
      vulnerabilities: vulnerabilities.map((v) => ({
        id: v.id,
        aliases: v.aliases,
        summary: v.summary,
        severity: v.severity,
        fixedVersions: v.fixedFor?.[inst.name] || [],
        url: v.url,
      })),
      riskScore: scored.riskScore,
      riskLevel: scored.riskLevel,
      factors: scored.factors,
      warnings: scored.warnings,
      confidence: scored.confidence,
      missingData: scored.missingData,
      explanation: scored.explanation,
      remediation,
    });
  }

  dependencies.sort((a, b) => {
    if (a.riskScore === null && b.riskScore === null) return a.name.localeCompare(b.name);
    if (a.riskScore === null) return 1;
    if (b.riskScore === null) return -1;
    return b.riskScore - a.riskScore || a.name.localeCompare(b.name);
  });

  // ---- 5. Project aggregate (documented method) ----
  const aggregation = aggregateProjectScore(dependencies.map((d) => d.riskScore));

  // ---- 6. Dependency graph payload (parsed relationships) ----
  const nodes = dependencies.map((d) => ({
    id: d.id,
    name: d.name,
    version: d.version,
    riskLevel: d.riskLevel,
    isDirect: d.isDirect,
    devOnly: d.devOnly,
  }));
  const edgeSet = new Map();
  for (const inst of instances) {
    for (const edge of inst.edges) {
      if (!edge.resolvedPath) continue;
      const id = `${inst.installPath}->${edge.resolvedPath}`;
      if (!edgeSet.has(id)) edgeSet.set(id, { from: inst.installPath, to: edge.resolvedPath, range: edge.range });
    }
  }

  return {
    ok: true,
    projectName: graph.projectName,
    projectVersion: graph.projectVersion,
    generatedAt: new Date().toISOString(),
    dataSource: source,
    coverage,
    projectRiskScore: aggregation.score,
    projectRiskLevel: projectRiskLevel(aggregation.score),
    aggregation,
    byRiskLevel: {
      CRITICAL: dependencies.filter((d) => d.riskLevel === 'CRITICAL').length,
      HIGH: dependencies.filter((d) => d.riskLevel === 'HIGH').length,
      MODERATE: dependencies.filter((d) => d.riskLevel === 'MODERATE').length,
      LOW: dependencies.filter((d) => d.riskLevel === 'LOW').length,
      NONE: dependencies.filter((d) => d.riskLevel === 'NONE').length,
      UNKNOWN: dependencies.filter((d) => d.riskLevel === 'UNKNOWN').length,
    },
    duplicates: graph.duplicates,
    dependencies,
    graph: { root: { id: '', name: graph.projectName, version: graph.projectVersion }, nodes, edges: [...edgeSet.values()] },
  };
}

export function createAnalyzeRouter(overrides = {}) {
  const svc = {
    queryVulnIds: overrides.queryVulnIds || liveQueryVulnIds,
    fetchAdvisories: overrides.fetchAdvisories || liveFetchAdvisories,
    fetchRegistryMeta: overrides.fetchRegistryMeta || liveFetchRegistryMeta,
  };
  const router = express.Router();

  router.post('/api/analyze', async (req, res) => {
    try {
      const { packageJson, lockJson } = req.body || {};
      const result = await analyzeProject({ packageJsonText: packageJson, lockJsonText: lockJson }, svc);
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      res.json(result);
    } catch (err) {
      console.error('analyze failed:', err);
      res.status(500).json({ error: 'Analysis failed. Check service availability and try again.' });
    }
  });

  router.get('/api/demo', async (req, res) => {
    try {
      const result = await analyzeProject(
        { packageJsonText: DEMO_PACKAGE_JSON, lockJsonText: DEMO_LOCK_JSON },
        createDemoServices(),
        { source: 'demo-fixture' },
      );
      if (!result.ok) return res.status(500).json({ error: result.error });
      result.demo = true;
      result.notice = DEMO_NOTICE;
      res.json(result);
    } catch (err) {
      console.error('demo scan failed:', err);
      res.status(500).json({ error: 'Demo scan failed. Please try again.' });
    }
  });

  return router;
}
