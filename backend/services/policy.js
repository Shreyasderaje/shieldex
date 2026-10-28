const SEVERITY = { CRITICAL: 5, HIGH: 4, MODERATE: 3, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 };
const THRESHOLDS = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'NONE'];

export function evaluatePolicy(report, { failOn = 'HIGH', unknown = 'warn' } = {}) {
  if (!report || !Array.isArray(report.dependencies)) throw new Error('A valid scan report with dependencies is required.');
  const threshold = String(failOn).toUpperCase();
  if (!THRESHOLDS.includes(threshold)) throw new Error(`Unsupported fail-on threshold: ${failOn}`);
  if (!['warn', 'fail', 'ignore'].includes(unknown)) throw new Error(`Unsupported unknown policy: ${unknown}`);
  const findings = [];
  for (const dependency of report.dependencies) {
    for (const advisory of dependency.vulnerabilities || []) {
      const severity = String(advisory.severity?.label || 'UNKNOWN').toUpperCase();
      if ((SEVERITY[severity] ?? 0) >= SEVERITY[threshold]) findings.push({ package: `${dependency.name}@${dependency.version || 'unknown'}`, id: advisory.id, severity });
    }
  }
  const unknownPackages = report.dependencies.filter((dependency) => dependency.riskLevel === 'UNKNOWN' || (dependency.vulnerabilities || []).some((advisory) => !advisory.severity?.label || advisory.severity.label === 'UNKNOWN')).map((dependency) => `${dependency.name}@${dependency.version || 'unknown'}`);
  const failedUnknown = unknown === 'fail' && unknownPackages.length > 0;
  return { passed: findings.length === 0 && !failedUnknown, failOn: threshold, unknownPolicy: unknown, findings, unknownPackages };
}
