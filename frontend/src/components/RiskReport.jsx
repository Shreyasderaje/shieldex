import React, { useEffect, useState } from 'react';
import DependencyTable from './DependencyTable.jsx';
import DependencyGraph from './DependencyGraph.jsx';
import CoveragePanel from './CoveragePanel.jsx';
import { riskColor } from './LoadingSpinner.jsx';
import SecurityWorkspace, { PackageDetail } from './SecurityWorkspace.jsx';
import NetworkGraph from './NetworkGraph.jsx';

const LEVELS = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'NONE', 'UNKNOWN'];

function AnimatedRiskScore({ score }) {
  const target = typeof score === 'number' ? Math.round(score) : null;
  const [shown, setShown] = useState(target === null ? null : 0);

  useEffect(() => {
    if (target === null) { setShown(null); return undefined; }
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setShown(target);
      return undefined;
    }
    let frame;
    const start = performance.now();
    const duration = 760;
    const tick = (now) => {
      const progress = Math.min(1, (now - start) / duration);
      setShown(Math.round(target * (1 - (1 - progress) ** 3)));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target]);

  return <>{shown === null ? 'UNKNOWN' : `${shown}/100`}</>;
}

function RiskReport({ data, activeSection = 'overview', selectedPackageId, onSelectPackage }) {
  const [filter, setFilter] = useState('ALL');
  const [scope, setScope] = useState('ALL');
  const [search, setSearch] = useState('');
  const [tab, setTab] = useState('table'); // 'table' | 'tree'

  const filtered = data.dependencies.filter((d) =>
    (filter === 'ALL' || d.riskLevel === filter) &&
    (scope === 'ALL' || (scope === 'DIRECT' ? d.isDirect : !d.isDirect)) &&
    d.name.toLowerCase().includes(search.trim().toLowerCase()),
  );

  const total = data.dependencies.length || 1;

  const topRecommendations = data.dependencies
    .flatMap((d) => d.remediation.map((r) => ({ ...r, package: d.package || d.name, name: d.name, version: d.version })))
    .sort((a, b) => (a.uncertain ? 1 : 0) - (b.uncertain ? 1 : 0))
    .slice(0, 10);

  return (
    <div className="report-container">
      {data.demo && (
        <div className="demo-banner" role="note">
          <strong>DEMO MODE — SIMULATED DATA.</strong> {data.notice}{' '}
          Press “Analyze another project” and upload real files for a live OSV.dev scan.
        </div>
      )}

      {activeSection === 'overview' ? <>
      <section className="overview-intro"><div><span className="eyebrow">PROJECT OVERVIEW</span><h2>See the risk. Secure your dependencies.</h2><p>Node.js dependency analysis powered by exact-version OSV.dev advisory matching.</p></div><span className="project-chip">{data.projectName}{data.projectVersion ? ` · ${data.projectVersion}` : ''}</span></section>
      <div className="summary-cards">
        <div className="card">
          <h3>Project risk</h3>
          <div className="score-display" style={{ color: riskColor(data.projectRiskLevel) }} aria-label={`Project risk score ${data.projectRiskScore === null ? 'unknown' : `${data.projectRiskScore} out of 100`}`}>
            <AnimatedRiskScore score={data.projectRiskScore} />
          </div>
          <p>{data.projectRiskLevel}</p>
          <p className="muted small score-caveat">Prioritization aid based on available evidence; it is not a guarantee that dependencies are safe.</p>
          <p className="muted small">{data.aggregation.method}</p>
          <p className="muted small">{data.aggregation.note}</p>
        </div>
        <div className="card">
          <h3>Installed instances</h3>
          <div className="big-number">{data.dependencies.length}</div>
          <p className="muted small">
            {data.coverage.uniquePackages} unique name@version pairs ·{' '}
            {data.duplicates.length} package(s) with multiple versions
          </p>
        </div>
        <div className="card">
          <h3>Confirmed advisories</h3>
          <div className="big-number">
            {data.dependencies.reduce((sum, d) => sum + d.vulnerabilities.length, 0)}
          </div>
          <p className="muted small">matched by OSV.dev against exact installed versions</p>
        </div>
        <div className="card">
          <h3>Unscannable</h3>
          <div className="big-number grey">{data.byRiskLevel.UNKNOWN}</div>
          <p className="muted small">instances with UNKNOWN risk (missing data, not “safe”)</p>
        </div>
      </div>

      <section className="overview-graph-layout"><div className="card overview-network"><div className="tool-heading"><div><span className="eyebrow">LIVE LOCKFILE STRUCTURE</span><h3>Dependency threat map</h3><p className="tool-muted">{data.graph.edges.length} resolved relationships across {data.graph.nodes.length} installed instances.</p></div></div>
        <NetworkGraph report={data} mode="network" selectedId={selectedPackageId} onSelect={onSelectPackage} showFilters showViewToggle />
      </div><aside className="overview-detail"><PackageDetail dep={data.dependencies.find((dep) => dep.id === selectedPackageId)} /></aside></section>

      <CoveragePanel report={data} />

      <section className="card">
        <h3>Risk distribution</h3>
        <div className="risk-bar" role="img" aria-label={`Risk distribution: ${LEVELS.map((level) => `${level} ${data.byRiskLevel[level] || 0}`).join(', ')}`}>
          {LEVELS.map((level) => {
            const count = data.byRiskLevel[level] || 0;
            const width = (count / total) * 100;
            if (width === 0) return null;
            return (
              <div
                key={level}
                className={`risk-segment ${level.toLowerCase()}`}
                style={{ width: `${width}%` }}
                title={`${level}: ${count}`}
              />
            );
          })}
        </div>
        <div className="legend">
          {LEVELS.map((level) => (
            <span key={level}>
              <span className="dot" style={{ backgroundColor: riskColor(level) }} /> {level} ({data.byRiskLevel[level] || 0})
            </span>
          ))}
        </div>
      </section>

      <section className="card risk-ranking"><h3>Package risk ranking</h3><p className="muted small">Highest scored installed instances. Unknown results stay separate from scored packages.</p>
        <ol>{[...data.dependencies].sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1)).slice(0, 8).map((dep) => <li key={dep.id}><button className={selectedPackageId === dep.id ? 'risk-rank-selected' : ''} onClick={() => onSelectPackage(dep.id)}><span>{dep.name}<small>@{dep.version || 'unknown'} · {dep.isDirect ? 'direct' : 'transitive'}</small></span><strong style={{ color: riskColor(dep.riskLevel) }}>{dep.riskScore ?? 'UNKNOWN'} · {dep.riskLevel}</strong></button></li>)}</ol>
      </section>

      <section className="card">
        <div className="tabs">
          <button className={tab === 'table' ? 'active' : ''} onClick={() => setTab('table')}>Findings table</button>
          <button className={tab === 'tree' ? 'active' : ''} onClick={() => setTab('tree')}>Dependency tree</button>
        </div>
        {tab === 'table' ? (
          <>
            <div className="filter-buttons">
              <button className={`filter-btn ${filter === 'ALL' ? 'active' : ''}`} onClick={() => setFilter('ALL')}>
                ALL ({data.dependencies.length})
              </button>
              {LEVELS.map((level) => (
                <button
                  key={level}
                  className={`filter-btn ${filter === level ? 'active' : ''}`}
                  style={filter === level ? { backgroundColor: riskColor(level), color: 'white' } : undefined}
                  onClick={() => setFilter(level)}
                >
                  {level} ({data.byRiskLevel[level] || 0})
                </button>
              ))}
              <label className="scope-filter">Scope<select value={scope} onChange={(event) => setScope(event.target.value)}><option value="ALL">All packages</option><option value="DIRECT">Direct</option><option value="TRANSITIVE">Transitive</option></select></label>
            </div>
            <label className="finding-search">
              <span>Search package</span>
              <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Type a package name" />
            </label>
            <DependencyTable dependencies={filtered} />
          </>
        ) : (
          <DependencyGraph report={data} />
        )}
      </section>

      <section className="card recommendations-section">
        <h3>Top remediation actions</h3>
        <p className="muted small">
          Derived from OSV affected/fixed-version evidence. Entries marked <strong>UNCERTAIN</strong> lack
          fixed-version evidence — verify before acting. “Latest version available” is never treated as a fix.
        </p>
        <ul className="recommendations-list">
          {topRecommendations.map((r, i) => (
            <li key={i} className={r.uncertain ? 'uncertain' : 'confident'}>
              <strong>{r.name}{r.version ? `@${r.version}` : ''}</strong> — <span className={`rec-type rec-${r.type}`}>{r.type}</span>{' '}
              {r.message}
            </li>
          ))}
          {topRecommendations.length === 0 && <li className="muted">No remediation actions to suggest.</li>}
        </ul>
      </section>
      </> : <SecurityWorkspace section={activeSection} report={data} selectedId={selectedPackageId} onSelect={onSelectPackage} />}
    </div>
  );
}

export default RiskReport;
