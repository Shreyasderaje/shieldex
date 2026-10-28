// Minimal CVSS v3.x base-score computation from an OSV severity vector, used
// only when an advisory carries a CVSS vector but no reviewed severity label.

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { H: 0.56, L: 0.22, N: 0 };

const roundUp = (x) => Math.ceil(x * 10) / 10;

export function cvss3BaseScore(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const parts = vector.split('/');
  const metrics = {};
  for (const part of parts.slice(1)) {
    const [k, v] = part.split(':');
    metrics[k] = v;
  }
  if (!metrics.AV || !metrics.AC || !metrics.PR || !metrics.UI || !metrics.S || !metrics.C || !metrics.I || !metrics.A) {
    return null;
  }
  const scopeChanged = metrics.S === 'C';
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[metrics.PR];
  if (pr === undefined) return null;

  const iss = 1 - (1 - (CIA[metrics.C] ?? 0)) * (1 - (CIA[metrics.I] ?? 0)) * (1 - (CIA[metrics.A] ?? 0));
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    : 6.42 * iss;
  const exploitability = 8.22 * (AV[metrics.AV] ?? 0) * (AC[metrics.AC] ?? 0) * pr * (UI[metrics.UI] ?? 0);
  if (impact <= 0) return 0;
  return roundUp(Math.min(impact + exploitability, 10));
}

export function severityLabelFromScore(score) {
  if (score === null || score === undefined) return 'UNKNOWN';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MODERATE';
  if (score > 0) return 'LOW';
  return 'NONE';
}
