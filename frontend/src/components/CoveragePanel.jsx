import React from 'react';

// Scan-coverage panel: tells the user exactly which data was available,
// which wasn't, and what that means for the findings.
function CoveragePanel({ report }) {
  const c = report.coverage;
  const statusText = {
    ok: 'All OSV vulnerability queries succeeded.',
    partial: 'Some OSV queries failed — affected packages may be undercounted.',
    unavailable: 'OSV.dev could not be reached — nothing is claimed to be vulnerability-free.',
    'skipped-no-exact-version': 'No lockfile was provided, so no exact versions could be scanned.',
  }[c.vulnerabilityStatus] || c.vulnerabilityStatus;

  return (
    <section className="coverage-panel card">
      <h3>Scan coverage &amp; data sources</h3>
      <p className={`coverage-status ${c.vulnerabilityStatus}`}>
        <strong>{report.dataSource === 'demo-fixture' ? 'DEMO FIXTURES' : 'LIVE OSV.dev + npm registry'}</strong>
        {' — '}{statusText}
      </p>
      <ul className="coverage-grid">
        <li><span>Lockfile version</span><b>v{c.lockfileVersion ?? '?'}</b></li>
        <li><span>Installed instances</span><b>{c.totalInstances}</b></li>
        <li><span>Unique name@version scanned</span><b>{c.osvQueriesSent}</b></li>
        <li><span>OSV queries failed</span><b>{c.osvQueriesFailed}</b></li>
        <li><span>Advisories matched</span><b>{c.advisoriesMatched}</b></li>
        <li><span>Advisory details failed</span><b>{c.advisoryDetailFailures}</b></li>
        <li><span>Registry lookups</span><b>{c.registryLookups}</b></li>
        <li><span>Registry failures</span><b>{c.registryFailures}</b></li>
      </ul>
      {c.notes?.length > 0 && (
        <details className="coverage-notes">
          <summary>{c.notes.length} parser/coverage note(s)</summary>
          <ul>{c.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
        </details>
      )}
    </section>
  );
}

export default CoveragePanel;
