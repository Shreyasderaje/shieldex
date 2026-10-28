// Remediation recommendations.
//
// Rule: an upgrade target is derived from OSV fixed-version evidence
// (affected[].ranges[].events[].fixed) for advisories that actually match
// the installed version. If no fixed version is listed by OSV, the advice
// is explicitly labelled uncertain. We never claim "installing the latest
// version fixes it".

import { compareVersions } from './semver.js';

function smallestFixedAtOrAbove(fixedVersions, installedVersion) {
  const candidates = (fixedVersions || [])
    .filter((v) => typeof v === 'string' && compareVersions(v, installedVersion) >= 0)
    .sort(compareVersions);
  return candidates.length ? candidates[0] : null;
}

/**
 * @param {object} input
 *   name, version (installed)
 *   vulnerabilities: normalized advisories (with fixedFor: {packageName: [fixed versions]})
 *   meta: npm metadata summary or null
 * @returns {Array} recommendations sorted by confidence/type
 */
export function buildRecommendations({ name, version, vulnerabilities = [], meta = null }) {
  const recs = [];
  if (!version) {
    return [{
      package: name,
      type: 'rescan',
      confidence: 'none',
      uncertain: true,
      message: 'No exact installed version available (no lockfile) — upload package-lock.json to get vulnerability-specific remediation.',
    }];
  }

  const advisories = (vulnerabilities || []).filter((v) => v && v.id);
  if (advisories.length) {
    const withFix = [];
    const withoutFix = [];
    let upgradeTarget = null;
    for (const advisory of advisories) {
      const fixedList = (advisory.fixedFor && advisory.fixedFor[name]) || [];
      const perAdvisoryFix = smallestFixedAtOrAbove(fixedList, version);
      if (perAdvisoryFix) {
        withFix.push({ advisory, fix: perAdvisoryFix });
        // To resolve ALL advisories, target the highest minimal fix.
        if (!upgradeTarget || compareVersions(perAdvisoryFix, upgradeTarget) > 0) {
          upgradeTarget = perAdvisoryFix;
        }
      } else {
        withoutFix.push(advisory);
      }
    }

    if (upgradeTarget) {
      const majorBump = upgradeTarget.split('.')[0] !== version.split('.')[0];
      recs.push({
        package: name,
        type: 'upgrade',
        currentVersion: version,
        targetVersion: upgradeTarget,
        majorBump,
        confidence: 'high',
        uncertain: false,
        resolvedAdvisories: withFix.map((w) => w.advisory.id),
        message: `OSV lists fixed version ${upgradeTarget} for ${withFix.length} advisory(ies) affecting ${name}@${version} (${withFix.map((w) => w.advisory.id).join(', ')}). Upgrade to at least ${upgradeTarget} to resolve them${majorBump ? ' — note this is a major-version jump, review breaking changes before upgrading' : ''}. Verify with a rescan after upgrading.`,
      });
    }

    for (const advisory of withoutFix) {
      recs.push({
        package: name,
        type: 'review-advisory',
        confidence: 'low',
        uncertain: true,
        resolvedAdvisories: [advisory.id],
        message: `UNCERTAIN: OSV reports ${advisory.id} affecting ${name}@${version} but lists no fixed version for it. Check the advisory (${advisory.url}) for remediation guidance — we cannot confirm any upgrade resolves it.`,
      });
    }
  }

  // Maintenance-only advice (independent of vulnerability claims).
  if (meta && meta.status === 'ok') {
    if (meta.installedDeprecated) {
      recs.push({
        package: name,
        type: 'replace-deprecated',
        confidence: 'low',
        uncertain: true,
        message: `Package is deprecated${typeof meta.installedDeprecated === 'string' && meta.installedDeprecated !== 'deprecated' ? `: “${meta.installedDeprecated}”` : ''}. Consider migrating to a maintained alternative — UNCERTAIN: no automated replacement analysis was performed.`,
      });
    } else if (!advisories.length && meta.latestVersion !== 'unknown' && compareVersions(meta.latestVersion, version) > 0) {
      recs.push({
        package: name,
        type: 'update-optional',
        confidence: 'medium',
        uncertain: false,
        message: `Newer version ${meta.latestVersion} is available (installed ${version}). This is maintenance hygiene, not a security claim: no confirmed advisories affect the installed version.`,
      });
    }
  }

  return recs;
}

export function sortRecommendations(recs) {
  const order = { upgrade: 0, 'review-advisory': 1, 'replace-deprecated': 2, 'update-optional': 3, rescan: 4 };
  return [...recs].sort((a, b) => (order[a.type] ?? 9) - (order[b.type] ?? 9));
}
