// Risk scoring — replacement formula per project requirements.
//
// PRINCIPLES:
//  1. The ONLY thing that raises a package's risk score is CONFIRMED
//     vulnerability evidence from OSV.dev (advisory IDs matched against the
//     exact installed version). Package age, maintainer count, or license
//     choice NEVER produce a "vulnerable" score.
//  2. Maintenance, lifecycle-script, and license-policy observations are
//     reported as separate warnings, not folded into the score.
//  3. Unknown data is never interpreted as bad data: an unknown publish
//     date is not "stale"; missing metadata is listed under missingData.
//  4. Every score ships with factors, evidence, confidence, and
//     missing-data indicators so it can be explained line by line.

import { compareVersions } from './semver.js';

export const SEVERITY_BASE_POINTS = {
  CRITICAL: 90,
  HIGH: 65,
  MODERATE: 40,
  MEDIUM: 40, // normalized upstream to MODERATE, kept for safety
  LOW: 15,
  NONE: 0,
  UNKNOWN: 30, // confirmed advisory whose severity we could not determine
};

const DAY_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_LICENSE_POLICY = ['GPL', 'AGPL', 'LGPL', 'SSPL'];

export function severityRank(label) {
  return { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, UNKNOWN: 1.5, NONE: 0 }[label] ?? 0;
}

function daysAgo(isoDate, now) {
  const t = Date.parse(isoDate);
  if (Number.isNaN(t)) return null;
  return Math.floor((now - t) / DAY_MS);
}

function humanizeDays(days) {
  if (days >= 730) return `${Math.floor(days / 365)} years`;
  if (days >= 60) return `${Math.floor(days / 30)} months`;
  return `${days} days`;
}

/**
 * Scores one installed package instance.
 *
 * @param {object} input
 *   name, version
 *   vulnerabilities: normalized confirmed advisories [{id, severity:{label,score}, summary, aliases, url}]
 *   vulnStatus: 'ok' | 'unavailable' | 'partial' | 'skipped-no-exact-version'
 *   meta: npm metadata summary (see npmMeta.summarizePackument) or null
 *   hasInstallScript: boolean from the lockfile
 *   licensePolicy: string[] of license fragments to flag (policy, not legality)
 *   now: Date override for tests
 */
export function scorePackage({
  name,
  version,
  vulnerabilities = [],
  vulnStatus = 'ok',
  meta = null,
  hasInstallScript = false,
  licensePolicy = DEFAULT_LICENSE_POLICY,
  now = new Date(),
}) {
  const factors = [];
  const warnings = [];
  const missingData = [];

  // ---- Scored factor: confirmed vulnerabilities only ----
  if (vulnStatus === 'ok' || vulnStatus === 'partial') {
    const vulns = (vulnerabilities || []).filter((v) => v && v.id);
    const withSeverity = vulns.filter((v) => v.severity && v.severity.label);
    const topLabel = vulns.reduce(
      (best, v) => (severityRank(v.severity.label) > severityRank(best) ? v.severity.label : best),
      'NONE',
    );

    if (vulns.length === 0) {
      factors.push({
        id: 'confirmed-vulnerabilities',
        label: 'Confirmed vulnerabilities',
        points: 0,
        evidence: vulnStatus === 'partial'
          ? ['No advisories matched the installed version among the OSV queries that succeeded; some queries failed (see coverage).']
          : [`OSV.dev querybatch matched no advisories against the exact installed version${version ? ` ${version}` : ''}.`],
        confidence: vulnStatus === 'partial' ? 'medium' : 'high',
        missingData: [],
      });
    } else {
      const base = SEVERITY_BASE_POINTS[topLabel] ?? SEVERITY_BASE_POINTS.UNKNOWN;
      const points = Math.min(100, base + 5 * (vulns.length - 1));
      const unknownSev = vulns.filter((v) => v.severity.label === 'UNKNOWN').length;
      factors.push({
        id: 'confirmed-vulnerabilities',
        label: 'Confirmed vulnerabilities',
        points,
        evidence: vulns.map((v) => {
          const sev = v.severity.label === 'UNKNOWN'
            ? 'severity not stated by advisory'
            : `${v.severity.label}${v.severity.score !== null ? ` (CVSS ${v.severity.score})` : ''}`;
          return `${v.id} — ${sev} — affects ${name}${version ? `@${version}` : ''}${v.summary ? `: ${v.summary}` : ''}`;
        }),
        confidence: unknownSev === vulns.length ? 'low' : unknownSev > 0 ? 'medium' : 'high',
        missingData: unknownSev > 0 ? ['advisory-severity'] : [],
      });
      if (unknownSev > 0) missingData.push('advisory-severity');
    }
  } else {
    // No real vulnerability data: score is UNKNOWN, never zero-by-assumption.
    factors.push({
      id: 'confirmed-vulnerabilities',
      label: 'Confirmed vulnerabilities',
      points: null,
      evidence: [
        vulnStatus === 'skipped-no-exact-version'
          ? 'Vulnerability scan skipped: no lockfile, so exact installed versions are unknown.'
          : 'Vulnerability data unavailable: OSV.dev could not be queried for this package.',
      ],
      confidence: 'none',
      missingData: ['vulnerability-scan'],
    });
    missingData.push('vulnerability-scan');
  }

  // ---- Unscored warnings: maintenance ----
  if (meta && meta.status === 'ok') {
    if (meta.installedDeprecated) {
      warnings.push({
        category: 'maintenance',
        severity: 'warning',
        id: 'deprecated',
        message: `Package is deprecated${typeof meta.installedDeprecated === 'string' && meta.installedDeprecated !== 'deprecated' ? `: “${meta.installedDeprecated}”` : ''}.`,
        evidence: [`npm registry marks ${name}${version ? `@${version}` : ''} as deprecated`],
      });
    }
    if (meta.latestVersion !== 'unknown' && version && compareVersions(meta.latestVersion, version) > 0) {
      warnings.push({
        category: 'maintenance',
        severity: 'info',
        id: 'outdated',
        message: `Outdated: installed ${version}, latest ${meta.latestVersion}.`,
        evidence: [`npm registry dist-tags.latest = ${meta.latestVersion}`],
      });
    }
    const lastPublishDays = daysAgo(meta.installedPublishedAt, now);
    if (lastPublishDays === null) {
      missingData.push('installed-version-publish-date');
    } else if (lastPublishDays > 730) {
      warnings.push({
        category: 'maintenance',
        severity: 'info',
        id: 'stale',
        message: `No release in ${humanizeDays(lastPublishDays)} (installed version published ${meta.installedPublishedAt.slice(0, 10)}). Noted for maintenance review only — age alone is not a security risk.`,
        evidence: [`npm registry time["${version}"] = ${meta.installedPublishedAt}`],
      });
    }
  } else {
    missingData.push('npm-metadata');
  }

  // ---- Unscored warnings: lifecycle scripts (static flag from lockfile) ----
  if (hasInstallScript) {
    warnings.push({
      category: 'lifecycle-script',
      severity: 'warning',
      id: 'install-script',
      message: 'Lockfile records install/preinstall/postinstall lifecycle scripts for this package (they run on `npm install`). Reviewed as static evidence only — nothing was executed here.',
      evidence: ['package-lock.json hasInstallScript = true'],
    });
  }

  // ---- Unscored warnings: license policy ----
  const license = meta && meta.status === 'ok' ? meta.installedLicense : 'unknown';
  if (license === 'unknown') {
    missingData.push('license');
  } else {
    const hit = licensePolicy.find((frag) => String(license).toUpperCase().includes(frag.toUpperCase()));
    if (hit) {
      warnings.push({
        category: 'license-policy',
        severity: 'info',
        id: 'license-policy',
        message: `License “${license}” matches this project's copyleft watchlist (“${hit}”). A license choice is not a security risk — flagged for policy review only.`,
        evidence: [`npm registry license = ${license}`],
      });
    }
  }

  // ---- Aggregate ----
  const scored = factors.filter((f) => typeof f.points === 'number');
  const riskScore = scored.length
    ? Math.min(100, scored.reduce((sum, f) => sum + f.points, 0))
    : null;

  const riskLevel = riskScore === null
    ? 'UNKNOWN'
    : riskScore >= 80
      ? 'CRITICAL'
      : riskScore >= 50
        ? 'HIGH'
        : riskScore >= 25
          ? 'MODERATE'
          : riskScore > 0
            ? 'LOW'
            : 'NONE';

  const confidence = vulnStatus === 'ok'
    ? meta && meta.status === 'ok' ? 'high' : 'medium'
    : vulnStatus === 'partial' ? 'medium' : 'low';

  return {
    riskScore,
    riskLevel,
    factors,
    warnings,
    confidence,
    missingData: [...new Set(missingData)],
    explanation: {
      method:
        'Score = confirmed OSV advisory severity for the exact installed version only (CRITICAL 90, HIGH 65, MODERATE 40, LOW 15, unknown 30, +5 per additional advisory, capped at 100). Maintenance, lifecycle-script and license observations are listed separately and do not affect the score.',
    },
  };
}

/**
 * Project-level aggregation. Documented method (also shown in the UI):
 *   projectScore = round(0.5 * worstPackageScore
 *                      + 0.3 * mean(top 5 package scores)
 *                      + 0.2 * mean(all package scores))
 * Computed only over packages whose score is known (real OSV data).
 */
export function aggregateProjectScore(packageScores) {
  const known = packageScores.filter((s) => typeof s === 'number');
  if (!known.length) {
    return {
      score: null,
      method: 'weighted worst + top-5 + mean',
      packagesScored: 0,
      packagesUnscored: packageScores.length,
      note: 'No package could be scored (no confirmed vulnerability data available).',
    };
  }
  const mean = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;
  const sortedDesc = [...known].sort((a, b) => b - a);
  const worst = sortedDesc[0];
  const top5 = mean(sortedDesc.slice(0, 5));
  const overall = mean(known);
  const score = Math.round(0.5 * worst + 0.3 * top5 + 0.2 * overall);
  return {
    score,
    method: 'projectScore = round(0.5 × worst package score + 0.3 × mean(top 5) + 0.2 × mean(all scored packages))',
    packagesScored: known.length,
    packagesUnscored: packageScores.length - known.length,
    note: `${known.length} of ${packageScores.length} packages had confirmed vulnerability data and were scored.`,
  };
}

export function projectRiskLevel(score) {
  if (score === null || score === undefined) return 'UNKNOWN';
  return score >= 80 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MODERATE' : score > 0 ? 'LOW' : 'NONE';
}
