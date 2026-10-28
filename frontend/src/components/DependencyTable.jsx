import React, { useMemo, useState } from 'react';
import { sortRows } from '../utils/sort.js';
import { riskColor } from './LoadingSpinner.jsx';

// Findings table. One row PER INSTALLED INSTANCE (name + version + install
// path) — duplicate versions of the same package are never merged. Unknown
// values sort last in both directions. Row expansion shows the full
// explanation: factors, evidence, confidence, missing data, warnings,
// remediation.

const COLUMNS = [
  { key: 'name', label: 'Package', accessor: (r) => r.name, type: 'text' },
  { key: 'version', label: 'Installed', accessor: (r) => r.version, type: 'version' },
  { key: 'latestVersion', label: 'Latest', accessor: (r) => r.latestVersion, type: 'version' },
  { key: 'vulnCount', label: 'Advisories', accessor: (r) => r.vulnerabilities.length, type: 'number' },
  { key: 'riskScore', label: 'Risk', accessor: (r) => r.riskScore, type: 'number' },
  { key: 'riskLevel', label: 'Level', accessor: (r) => r.riskLevel, type: 'text' },
  { key: 'confidence', label: 'Confidence', accessor: (r) => r.confidence, type: 'text' },
  { key: 'scope', label: 'Scope', accessor: (r) => (r.devOnly ? 'dev' : r.isDirect ? 'direct' : 'transitive'), type: 'text' },
  { key: 'installedPublishedAt', label: 'Published (installed)', accessor: (r) => (r.installedPublishedAt && r.installedPublishedAt !== 'unknown' ? r.installedPublishedAt.slice(0, 10) : 'unknown'), type: 'version' },
  { key: 'license', label: 'License', accessor: (r) => r.license, type: 'text' },
];

function WarningChip({ w }) {
  return (
    <li className={`warn warn-${w.severity}`}>
      <span className="warn-cat">{w.category}</span> {w.message}
      {w.evidence?.length > 0 && <small>Evidence: {w.evidence.join(' · ')}</small>}
    </li>
  );
}

function DetailPanel({ dep }) {
  return (
    <div className="detail-panel">
      <div className="detail-grid">
        <section>
          <h4>Why this score</h4>
          <p className="method-note">{dep.explanation?.method}</p>
          <h4>Confirmed advisories ({dep.vulnerabilities.length})</h4>
          {dep.vulnerabilities.length === 0 ? <p className="muted">No advisory matched this exact installed version.</p> : (
            <ul className="advisory-list">
              {dep.vulnerabilities.map((v) => (
                <li key={v.id}>
                  <strong>{v.id}</strong> · {v.severity?.label || 'UNKNOWN'}
                  {v.severity?.score !== null && v.severity?.score !== undefined ? ` (CVSS ${v.severity.score})` : ''}
                  {v.severity?.source ? ` · source: ${v.severity.source}` : ''}
                  <p>{v.summary || 'No advisory summary provided.'}</p>
                  <small>Matched installed version {dep.name}@{dep.version}. {v.fixedVersions?.length ? `OSV fixed-version evidence: ${v.fixedVersions.join(', ')}.` : 'No fixed version listed by OSV.'}</small>
                  {v.url && <a href={v.url} target="_blank" rel="noreferrer">View advisory</a>}
                </li>
              ))}
            </ul>
          )}
          {dep.factors.map((f) => (
            <div key={f.id} className="factor">
              <div className="factor-head">
                <strong>{f.label}</strong>
                <span className="factor-points">
                  {f.points === null ? 'no score (data missing)' : `+${f.points} pts`}
                </span>
                <span className={`confidence confidence-${f.confidence}`}>confidence: {f.confidence}</span>
              </div>
              <ul>
                {f.evidence.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          ))}
        </section>

        <section>
          <h4>Separate warnings (not part of the score)</h4>
          {dep.warnings.length === 0 && <p className="muted">None.</p>}
          <ul className="warn-list">
            {dep.warnings.map((w, i) => <WarningChip key={i} w={w} />)}
          </ul>

          <h4>Remediation</h4>
          {dep.remediation.length === 0 && <p className="muted">No action suggested.</p>}
          <ul className="rec-list">
            {dep.remediation.map((r, i) => (
              <li key={i} className={r.uncertain ? 'uncertain' : 'confident'}>
                <span className={`rec-type rec-${r.type}`}>{r.type}</span>
                {r.message}
              </li>
            ))}
          </ul>

          {dep.missingData.length > 0 && (
            <p className="missing-data">
              Missing data: {dep.missingData.join(', ')} — treated as unknown, never as bad.
            </p>
          )}
          <p className="muted path-note">Install path: <code>{dep.id}</code></p>
          <p className="muted path-note">
            Direct?: {String(dep.isDirect)} ({dep.evidence?.isDirect}) · dev-only: {String(dep.devOnly)} ({dep.evidence?.devOnly})
          </p>
        </section>
      </div>
    </div>
  );
}

function DependencyTable({ dependencies }) {
  const [sortBy, setSortBy] = useState('riskScore');
  const [dir, setDir] = useState('desc');
  const [expanded, setExpanded] = useState(null);

  const sorted = useMemo(
    () => sortRows(dependencies, COLUMNS.find((c) => c.key === sortBy).accessor, dir),
    [dependencies, sortBy, dir],
  );

  const handleSort = (key) => {
    if (key === sortBy) setDir(dir === 'desc' ? 'asc' : 'desc');
    else {
      setSortBy(key);
      setDir(COLUMNS.find((c) => c.key === key).type === 'text' ? 'asc' : 'desc');
    }
  };

  return (
    <div className="table-container">
      <table className="dependencies-table">
        <thead>
          <tr>
            {COLUMNS.map((col) => (
              <th key={col.key} className={sortBy === col.key ? 'sorted' : ''} aria-sort={sortBy === col.key ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
                <button className="sort-control" onClick={() => handleSort(col.key)}>
                  {col.label}
                  {sortBy === col.key && <span className="sort-arrow" aria-hidden="true">{dir === 'desc' ? ' ▾' : ' ▴'}</span>}
                </button>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && <tr><td colSpan={COLUMNS.length} className="empty-findings">No packages match these filters.</td></tr>}
          {sorted.map((dep) => (
            <React.Fragment key={dep.id}>
              <tr
                className={`${expanded === dep.id ? 'expanded-row' : ''} ${dep.vulnerabilities.length ? 'has-advisory' : ''}`}
                style={{ '--finding-accent': riskColor(dep.riskLevel) }}
                onClick={() => setExpanded(expanded === dep.id ? null : dep.id)}
                tabIndex={0}
                aria-expanded={expanded === dep.id}
                onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setExpanded(expanded === dep.id ? null : dep.id); } }}
              >
                <td className="package-name">
                  {dep.devOnly && <span className="badge dev">dev</span>}
                  {dep.isDirect && <span className="badge">direct</span>}
                  {!dep.isDirect && !dep.devOnly && <span className="badge trans">transitive</span>}
                  {dep.hasInstallScript && <span className="badge script" title="Lockfile records install lifecycle scripts (static evidence only)">scripts</span>}
                  {dep.name}
                </td>
                <td className="mono">{dep.version ?? 'unknown'}</td>
                <td className="mono">{dep.latestVersion ?? 'unknown'}</td>
                <td>{dep.vulnerabilities.length}</td>
                <td>
                  <span className="score-badge" style={{ backgroundColor: riskColor(dep.riskLevel) }}>
                    {dep.riskScore === null ? '?' : dep.riskScore}
                  </span>
                </td>
                <td><strong style={{ color: riskColor(dep.riskLevel) }}>{dep.riskLevel}</strong></td>
                <td className={`confidence-text confidence-${dep.confidence}`}>{dep.confidence}</td>
                <td>{dep.devOnly ? 'dev-only' : dep.isDirect ? 'direct' : 'transitive'}</td>
                <td className="mono">{dep.installedPublishedAt === 'unknown' ? 'unknown' : dep.installedPublishedAt?.slice(0, 10)}</td>
                <td>{dep.license ?? 'unknown'}</td>
              </tr>
              <tr className="detail-row">
                <td colSpan={COLUMNS.length}>
                  <div className={`detail-clip ${expanded === dep.id ? 'is-open' : ''}`} aria-hidden={expanded !== dep.id} inert={expanded !== dep.id}>
                    <DetailPanel dep={dep} />
                  </div>
                </td>
              </tr>
            </React.Fragment>
          ))}
        </tbody>
      </table>
      <p className="table-hint">
        {sorted.length} installed instance(s) — click a row for evidence, factors, warnings and remediation.
        {' '}Unknown values always sort last.
      </p>
    </div>
  );
}

export default DependencyTable;
