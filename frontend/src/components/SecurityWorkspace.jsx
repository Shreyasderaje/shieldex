import React, { useMemo, useState } from 'react';
import {
  buildThreatSignals, createCycloneDx, createSpdx, evaluateGate,
  findDependents, findNameConfusions, simulateRisk,
} from '../utils/securityTools.js';
import { riskColor } from './LoadingSpinner.jsx';
import NetworkGraph from './NetworkGraph.jsx';

export const WORKSPACE_SECTIONS = [
  ['overview', 'Overview', '01'], ['threat-map', 'Threat map', '02'], ['impact', 'Attack impact', '03'],
  ['fix-advisor', 'Fix advisor', '04'], ['signals', 'Threat signals', '05'], ['risk-simulator', 'What-if risk', '06'],
  ['blast-radius', 'Blast radius', '07'], ['name-review', 'Name review', '08'], ['sbom', 'SBOM export', '09'],
  ['security-gate', 'Security gate', '10'], ['executive-report', 'Executive report', '11'],
];

export function WorkspaceSidebar({ active, onNavigate, ready, onNewScan }) {
  return (
    <aside className="workspace-sidebar card" aria-label="Security workspace navigation">
      <div className="sidebar-brand"><span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><path d="M24 3.5 41 10v12.2c0 10.3-7 18-17 22.3C14 40.2 7 32.5 7 22.2V10L24 3.5Z" stroke="currentColor" strokeWidth="2.4"/><path d="m15.5 24 5.3 5.2L33 17" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/></svg></span><div><strong>SHIELDEX</strong><small>Dependency Security</small></div></div>
      <div className="sidebar-heading"><span className="sidebar-orb" /> WORKSPACE</div>
      <nav>
        {WORKSPACE_SECTIONS.map(([id, label, number]) => (
          <button key={id} className={`sidebar-link ${active === id ? 'active' : ''}`} onClick={() => onNavigate(id)} disabled={!ready} aria-current={active === id ? 'page' : undefined}>
            <span className="nav-number">{number}</span><span>{label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-bottom"><p className="sidebar-status"><i className={ready ? 'ready' : ''} /><span><strong>{ready ? 'Scan ready' : 'Awaiting scan'}</strong><small>{ready ? 'Evidence-led analysis' : 'Upload a lockfile to begin'}</small></span></p>{ready && <button className="sidebar-new-scan" onClick={onNewScan}>＋ New scan</button>}</div>
    </aside>
  );
}

const reportDependency = (report, id) => report.dependencies.find((dep) => dep.id === id);

export function PackageDetail({ dep }) {
  if (!dep) return <div className="card tool-empty">Select a package to inspect its scan evidence.</div>;
  return (
    <div className="card package-detail-card">
      <div className="tool-heading"><div><span className="eyebrow">SELECTED INSTANCE</span><h3>{dep.name}<small>@{dep.version || 'unknown'}</small></h3></div><span className="risk-pill" style={{ '--severity': riskColor(dep.riskLevel) }}>{dep.riskLevel}</span></div>
      <p className="tool-muted">{dep.isDirect ? 'Direct dependency' : 'Transitive dependency'} Â· Install path <code>{dep.id}</code></p>
      <h4>Confirmed advisory evidence</h4>
      {!dep.vulnerabilities.length && <p className="tool-muted">No confirmed advisory is attached to this instance. Unknown scan status is not a safe result.</p>}
      {dep.vulnerabilities.map((advisory) => <article key={advisory.id} className="tool-advisory">
        <strong>{advisory.id}</strong><span className="severity-chip" style={{ '--severity': riskColor(advisory.severity?.label) }}>{advisory.severity?.label || 'UNKNOWN'}</span>
        <p>{advisory.summary || 'No summary provided by advisory source.'}</p>
        <p className="tool-muted">Severity source: {advisory.severity?.source || 'not stated'} Â· exact installed version matched: {dep.version || 'unknown'}</p>
        <p className="tool-muted">Fixed versions listed by OSV: {advisory.fixedVersions?.length ? advisory.fixedVersions.join(', ') : 'none reported'}</p>
        {advisory.url && <a href={advisory.url} target="_blank" rel="noreferrer">Open source advisory â†—</a>}
      </article>)}
      <h4>Recommended action</h4>
      {dep.remediation.length ? dep.remediation.map((item, index) => <p className="tool-action" key={`${item.type}-${index}`}>{item.message}</p>) : <p className="tool-muted">No remediation recommendation is available from current evidence.</p>}
    </div>
  );
}

function ThreatMap({ report, selectedId, onSelect }) {
  const selected = reportDependency(report, selectedId);
  return <div className="security-view">
    <div className="tool-title"><div><span className="eyebrow">LOCKFILE-DEFINED RELATIONSHIPS</span><h2>Neural Dependency Threat Map</h2><p>Stable network layout of installed instances. Arrows point from a dependent to its resolved dependency.</p></div></div>
    <NetworkGraph report={report} mode="network" selectedId={selectedId} onSelect={onSelect} showFilters showViewToggle />
    <PackageDetail dep={selected} />
  </div>;
}

function PackageSelect({ report, value, onChange, vulnerableOnly = false }) {
  const deps = vulnerableOnly ? report.dependencies.filter((dep) => dep.vulnerabilities.length) : report.dependencies;
  return <label className="tool-select">Package instance<select value={value || ''} onChange={(event) => onChange(event.target.value)}><option value="">Choose packageâ€¦</option>{deps.map((dep) => <option key={dep.id} value={dep.id}>{dep.name}@{dep.version || 'unknown'} Â· {dep.riskLevel}</option>)}</select></label>;
}

function RelationshipPanel({ report, initialId, impactMode }) {
  const [id, setId] = useState(initialId || '');
  const [scenarioRun, setScenarioRun] = useState(false);
  const result = id ? findDependents(report, id) : null;
  const selected = id && reportDependency(report, id);
  const pathNodes = new Map(report.dependencies.map((dep) => [dep.id, dep]));
  const pathIds = selected && result?.known ? [id, ...result.all] : [];
  const showScenario = !impactMode || scenarioRun;
  const reselect = (nextId) => { setId(nextId); setScenarioRun(false); };
  const selectGraphNode = (nextId) => {
    const candidate = reportDependency(report, nextId);
    if (!impactMode || candidate?.vulnerabilities?.length) reselect(nextId);
  };
  return <div className="security-view">
    <div className="tool-title"><div><span className="eyebrow">{impactMode ? 'HYPOTHETICAL SCENARIO' : 'REVERSE DEPENDENCY ANALYSIS'}</span><h2>{impactMode ? 'Attack Impact Simulator' : 'Dependency Blast-radius Analyzer'}</h2><p>{impactMode ? 'Explore confirmed lockfile paths from a vulnerable instance. A graph path does not establish exploitability, runtime reachability, or compromise.' : 'Radial view of resolved relationships touching the selected instance. A lockfile cannot represent every runtime relationship.'}</p></div></div>
    <div className="card relationship-control"><PackageSelect report={report} value={id} onChange={reselect} vulnerableOnly={impactMode} />{impactMode && <div className="button-row"><button className="tool-button" disabled={!selected} onClick={() => setScenarioRun(true)}>Run hypothetical scenario</button><button className="tool-button secondary" onClick={() => { setScenarioRun(false); setId(''); }}>Reset</button></div>}</div>
    {!selected ? <div className="card tool-empty">{impactMode ? 'Select a package with a confirmed OSV advisory to inspect this hypothetical scenario.' : 'Select a package instance to explore reverse dependencies.'}</div> : <>
      <div className="card selected-summary"><strong>{selected.name}@{selected.version}</strong><span className="severity-chip" style={{ '--severity': riskColor(selected.riskLevel) }}>{selected.riskLevel}</span><p>{selected.vulnerabilities.length} confirmed advisory match(es). {impactMode ? 'Scenario paths are hypothetical and evidence-limited.' : 'Relationships shown come from resolved lockfile edges.'}</p>{selected.vulnerabilities.map((advisory) => <article className="tool-advisory" key={advisory.id}><strong>{advisory.id}</strong><span className="severity-chip" style={{ '--severity': riskColor(advisory.severity?.label) }}>{advisory.severity?.label || 'UNKNOWN'}</span><p>{advisory.summary || 'No summary provided by advisory source.'}</p><small>Fixed versions reported: {advisory.fixedVersions?.join(', ') || 'none'}</small></article>)}</div>
      {showScenario && <>
        <div className="relationship-metrics"><span><strong>{result?.direct.length || 0}</strong> immediate dependents</span><span><strong>{result?.all.length || 0}</strong> connected instances</span><span><strong>{Math.max(0, result?.all.length || 0)}</strong> instances along recorded paths</span></div>
        {!result?.all.length && <div className="card tool-empty">No reverse dependency path to another installed instance appears in the parsed lockfile graph. The lockfile may not capture runtime relationships.</div>}
        <div className={impactMode ? 'attack-impact-graph' : 'blast-radius-graph'}><NetworkGraph report={report} mode={impactMode ? 'layered' : 'radial'} selectedId={id} onSelect={selectGraphNode} highlightedIds={impactMode ? pathIds : [id]} scenarioStartId={impactMode ? id : ''} mutedIds={impactMode ? report.dependencies.filter((dep) => !pathIds.includes(dep.id)).map((dep) => dep.id) : []} emptyMessage="No resolved relationships are present in this lockfile." /></div>
        {!!result?.all.length && <section className="card relationship-list"><h3>Evidence-backed dependent paths</h3>{result.paths.map((entry) => { const dep = pathNodes.get(entry.id); return <article key={entry.id} className="relationship-item"><strong>{dep?.name}@{dep?.version}</strong><span>{entry.path.length - 1} edge(s) away</span><p className="tool-muted">Known path: {entry.path.map((pathId) => { const item = pathNodes.get(pathId); return item ? `${item.name}@${item.version}` : pathId; }).join(' ? ')}</p></article>; })}</section>}
      </>}
    </>}
  </div>;
}

function FixAdvisor({ report }) {
  const fixes = report.dependencies.flatMap((dep) => dep.remediation.filter((item) => item.type === 'upgrade' && item.targetVersion).map((item) => ({ dep, item })));
  const [copied, setCopied] = useState('');
  const copy = async (id, text) => { try { await navigator.clipboard.writeText(text); setCopied(id); } catch { setCopied(''); } };
  return <div className="security-view"><div className="tool-title"><div><span className="eyebrow">DETERMINISTIC Â· OSV FIXED-VERSION EVIDENCE</span><h2>Evidence-based Fix Advisor</h2><p>No AI provider is configured or called. Recommendations below use only the existing advisory fixed-version data.</p></div></div>
    {!fixes.length ? <div className="card tool-empty">No advisory-backed fixed version is available in this scan. Review each advisory; no upgrade is presented as a confirmed fix without OSV evidence.</div> : fixes.map(({ dep, item }, index) => {
      const manifestField = dep.isDirect ? (dep.devOnly ? 'devDependencies' : 'dependencies') : 'overrides';
      const snippet = dep.isDirect ? { [manifestField]: { [dep.name]: item.targetVersion } } : { overrides: { [dep.name]: item.targetVersion } };
      const bashName = `${dep.name}@${item.targetVersion}`.replaceAll("'", "'\\''");
      const command = `npm install --save-exact '${bashName}'`;
      const id = `${dep.id}-${index}`;
      return <article className="card fix-card" key={id}><div className="tool-heading"><div><span className="eyebrow">{dep.isDirect ? `DIRECT Â· ${manifestField}` : 'TRANSITIVE Â· npm overrides'}</span><h3>{dep.name}</h3></div><span className={`severity-chip ${item.majorBump ? 'warning' : ''}`}>{item.majorBump ? 'MAJOR REVIEW' : 'FIX EVIDENCE'}</span></div>
        <div className="fix-version-row"><span>Current <strong>{dep.version}</strong></span><span>Minimum fixed <strong>{item.targetVersion}</strong></span></div>
        <p>{item.message}</p><p className="tool-muted">Advisories: {(item.resolvedAdvisories || []).join(', ') || 'not specified'}. {item.majorBump && 'Major-version changes can break compatibility; review release notes and tests.'}</p>
        <pre>{JSON.stringify(snippet, null, 2)}</pre><div className="button-row"><button className="tool-button" onClick={() => copy(`${id}-json`, JSON.stringify(snippet, null, 2))}>Copy manifest change</button><button className="tool-button secondary" onClick={() => copy(`${id}-cmd`, command)}>Copy Bash command</button><span aria-live="polite">{copied === `${id}-json` || copied === `${id}-cmd` ? 'Copied' : ''}</span></div>
      </article>;
    })}
  </div>;
}

function SignalCenter({ report }) {
  const signals = useMemo(() => buildThreatSignals(report), [report]);
  const names = useMemo(() => findNameConfusions(report.dependencies), [report]);
  return <div className="security-view"><div className="tool-title"><div><span className="eyebrow">SOURCE Â· TIMESTAMP Â· CONFIDENCE</span><h2>Early-warning Threat Signals</h2><p>Confirmed OSV matches are separated from local heuristics and insufficient data. No external threat-intelligence feed is configured.</p></div></div>
    <div className="signal-summary"><span>{signals.filter((item) => item.kind === 'confirmed').length} confirmed</span><span>{signals.filter((item) => item.kind === 'heuristic').length + names.length} heuristic</span><span>{signals.filter((item) => item.kind === 'insufficient').length} coverage gaps</span></div>
    {!signals.length && !names.length ? <div className="card tool-empty">No advisory or review signals were produced by the available scan sources. This is not a guarantee of safety.</div> : <div className="signal-list">{signals.map((signal, index) => <article className={`card signal-card signal-${signal.kind}`} key={`${signal.kind}-${signal.package}-${index}`}><div className="tool-heading"><strong>{signal.label}</strong><span className="signal-kind">{signal.kind === 'confirmed' ? 'CONFIRMED' : signal.kind === 'heuristic' ? 'HEURISTIC' : 'INSUFFICIENT DATA'}</span></div><p>{signal.package}</p><p>{signal.evidence}</p><small>Source: {signal.source} Â· {signal.timestamp ? new Date(signal.timestamp).toLocaleString() : 'timestamp unavailable'} Â· Confidence: {signal.confidence}</small></article>)}
      {names.map((signal) => <article className="card signal-card signal-heuristic" key={`${signal.package}-${signal.similarTo}`}><div className="tool-heading"><strong>Package-name similarity heuristic</strong><span className="signal-kind">HEURISTIC Â· LOW</span></div><p>{signal.package}</p><p>{signal.evidence}</p><small>Source: dependency names in this scan Â· scan timestamp {report.generatedAt || 'unavailable'}</small></article>)}</div>}
    <p className="tool-muted">No signal here is called a zero-day. Local heuristics require human review and do not establish malicious intent.</p>
  </div>;
}

function RiskSimulator({ report }) {
  const [selected, setSelected] = useState([]);
  const result = simulateRisk(report, selected);
  const projectedIds = new Set(result.assumedRemediated);
  const afterLevels = report.dependencies.reduce((counts, dep) => {
    const level = projectedIds.has(dep.id) ? 'NONE' : dep.riskLevel;
    counts[level] = (counts[level] || 0) + 1;
    return counts;
  }, {});
  const deltaPercent = result.baselineScore ? Math.round((result.delta || 0) / result.baselineScore * 100) : 0;
  const eligible = report.dependencies.filter((dep) => { const upgrade = dep.remediation.find((rec) => rec.type === 'upgrade'); return dep.vulnerabilities.length && dep.riskScore !== null && dep.vulnerabilities.every((advisory) => upgrade?.resolvedAdvisories?.includes(advisory.id)); });
  const toggle = (id) => setSelected((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  return <div className="security-view"><div className="tool-title"><div><span className="eyebrow">PROJECTION ONLY ? ORIGINAL SCAN UNCHANGED</span><h2>What-if Risk Reduction Simulator</h2><p>Project the existing score model only when OSV fixed-version evidence covers every matched advisory on the selected instance.</p></div></div>
    <div className="simulator-score card"><div><span>BASELINE RISK</span><strong>{result.baselineScore ?? 'UNKNOWN'}</strong></div><span className="sim-arrow">?</span><div><span>PROJECTED RISK</span><strong>{result.projectedScore ?? 'UNKNOWN'}</strong></div><div><span>PROJECTED CHANGE</span><strong className="risk-change">{result.delta === null ? 'UNKNOWN' : `?${result.delta} (${deltaPercent}%)`}</strong></div><button className="tool-button secondary" onClick={() => setSelected([])}>Reset to baseline</button></div>
    <section className="card distribution-comparison"><h3>Severity distribution ? current and projected</h3><div className="distribution-columns">{[['Current scan', report.byRiskLevel], ['Projection', afterLevels]].map(([label, levels]) => <div key={label}><h4>{label}</h4>{['CRITICAL','HIGH','MODERATE','LOW','NONE','UNKNOWN'].map((level) => <div className="distribution-row" key={level}><span>{level}</span><div><i style={{ width: `${Math.max(0, Math.min(100, ((levels[level] || 0) / Math.max(report.dependencies.length, 1)) * 100))}%`, background: riskColor(level) }} /></div><strong>{levels[level] || 0}</strong></div>)}</div>)}</div><p className="tool-muted">Projected categories treat selected, fully supported remediation instances as resolved for this model only.</p></section>
    <div className="card simulation-list"><h3>Hypothetically remediate evidence-backed instances</h3><p className="tool-muted">Each option has a recommended target supported for every matched advisory on that instance.</p>{!eligible.length && <p className="tool-empty">No package has complete fixed-version evidence for all its matched advisories.</p>}{eligible.map((dep) => { const upgrade = dep.remediation.find((rec) => rec.type === 'upgrade'); return <label className="simulation-choice" key={dep.id}><input type="checkbox" checked={selected.includes(dep.id)} onChange={() => toggle(dep.id)} /><span><strong>{dep.name}@{dep.version}</strong><small>Target {upgrade.targetVersion} ? {dep.vulnerabilities.map((item) => item.id).join(', ')} ? fixed: {dep.vulnerabilities.flatMap((item) => item.fixedVersions || []).join(', ')}</small></span></label>; })}</div>
    <p className="simulation-disclaimer">PROJECTION ONLY: selected actions do not modify the original scan, manifests, or package state, and do not guarantee that a fix has been applied or that the project is secure.</p>
  </div>;
}

function NameReview({ report }) {
  const similar = findNameConfusions(report.dependencies);
  const metadata = report.dependencies.flatMap((dep) => dep.warnings.filter((warning) => warning.category === 'lifecycle-script' || warning.category === 'maintenance').map((warning) => ({ dep, warning })));
  return <div className="security-view"><div className="tool-title"><div><span className="eyebrow">HEURISTIC REVIEW Â· NOT A MALICIOUS-PACKAGE VERDICT</span><h2>Package Name &amp; Metadata Review</h2><p>Checks only package names in this lockfile and metadata already returned by the npm registry.</p></div></div>
    <div className="card"><h3>Typosquatting-like name similarity</h3><p className="tool-muted">Comparison baseline: direct dependency names from this same manifest. Low-confidence spelling similarity only.</p>{!similar.length ? <p className="tool-empty">No one-character similarity to another direct dependency was detected.</p> : similar.map((item) => <article className="tool-advisory heuristic" key={`${item.package}-${item.similarTo}`}><strong>{item.package}</strong><p>{item.evidence}</p></article>)}</div>
    <div className="card"><h3>Inspectable metadata indicators</h3>{!metadata.length ? <p className="tool-empty">No deprecated-package or install-script warnings are present in the scan data. This is not a malicious-package verdict.</p> : metadata.map(({ dep, warning }, index) => <article className="tool-advisory heuristic" key={`${dep.id}-${index}`}><strong>{dep.name}@{dep.version} Â· {warning.category}</strong><p>{warning.message}</p><small>Evidence source: {warning.category === 'lifecycle-script' ? 'package-lock.json static metadata' : 'npm registry'}</small></article>)}</div>
    <p className="tool-muted">No external malware feed is configured. Scanned packages are never downloaded, installed, or executed.</p>
  </div>;
}

function downloadFile(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function SbomPanel({ report }) {
  const [format, setFormat] = useState('CycloneDX 1.5'); const [error, setError] = useState('');
  const generate = () => { try { const doc = format.startsWith('Cyclone') ? createCycloneDx(report) : createSpdx(report); setError(''); downloadFile(`${report.projectName || 'project'}-${format.startsWith('Cyclone') ? 'cyclonedx' : 'spdx'}.json`, JSON.stringify(doc, null, 2), 'application/json'); } catch (exception) { setError(exception.message); } };
  return <div className="security-view"><div className="tool-title"><div><span className="eyebrow">STANDARDS-BASED INVENTORY</span><h2>SBOM Generator</h2><p>Exports installed package instances and only lockfile relationships present in this scan.</p></div></div>
    <div className="card export-card"><label>Format<select value={format} onChange={(event) => setFormat(event.target.value)}><option>CycloneDX 1.5</option><option>SPDX 2.3</option></select></label><p className="tool-muted">Missing exact versions prevent an SBOM export. Unknown licenses and identifiers remain unasserted; document creation time and SHIELDEX tool metadata are included.</p><button className="tool-button" onClick={generate}>Download {format} JSON</button>{error && <p className="error-box" role="alert">{error}</p>}</div>
  </div>;
}

function GatePanel({ report }) {
  const [failOn, setFailOn] = useState('HIGH'); const [unknown, setUnknown] = useState('fail');
  const result = evaluateGate(report, { failOn, unknown });
  return <div className="security-view"><div className="tool-title"><div><span className="eyebrow">LOCAL POLICY EVALUATION Â· NO REPOSITORY CONNECTION</span><h2>GitHub Security Gate</h2><p>Evaluate this scan locally or use the documented CLI in a GitHub Actions workflow. This dashboard has not connected or started a workflow.</p></div></div>
    <div className="card gate-settings"><label>Fail on<select value={failOn} onChange={(event) => setFailOn(event.target.value)}>{['CRITICAL','HIGH','MODERATE','LOW','NONE'].map((value) => <option key={value}>{value}</option>)}</select></label><label>Unknown results<select value={unknown} onChange={(event) => setUnknown(event.target.value)}><option value="warn">Warn</option><option value="fail">Fail</option><option value="ignore">Ignore (explicit)</option></select></label><strong className={result.passed ? 'gate-pass' : 'gate-fail'}>{result.passed ? 'POLICY PASSED' : 'POLICY FAILED'}</strong></div>
    <div className="card"><h3>{result.findings.length} threshold finding(s) Â· {result.unknownPackages.length} unknown package(s)</h3>{result.findings.map((item) => <p className="gate-finding" key={`${item.package}-${item.id}`}>{item.severity} Â· {item.package} Â· {item.id}</p>)}{result.unknownPackages.map((name) => <p className="gate-finding unknown" key={name}>UNKNOWN Â· {name}</p>)}{!result.findings.length && !result.unknownPackages.length && <p className="tool-muted">No policy violations for the selected settings.</p>}</div>
    <div className="card"><h3>Run in GitHub Actions</h3><pre>node backend/cli/security-gate.js --package-json package.json --lockfile package-lock.json --fail-on {failOn} --unknown {unknown}</pre><p className="tool-muted">See docs/security-gate.md and the example workflow. The CLI exits 1 on policy failure and 2 on invalid input or scan failure.</p></div>
  </div>;
}

function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]); }
function executiveHtml(report) {
  const levels = ['CRITICAL','HIGH','MODERATE','LOW','NONE','UNKNOWN'];
  const findings = report.dependencies.filter((dep) => dep.vulnerabilities.length).sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
  const bars = levels.map((level) => `<div><span>${level}</span><meter min="0" max="${Math.max(report.dependencies.length, 1)}" value="${report.byRiskLevel[level] || 0}"></meter><b>${report.byRiskLevel[level] || 0}</b></div>`).join('');
  const rows = findings.map((dep) => `<tr><td>${escapeHtml(dep.name)}@${escapeHtml(dep.version)}</td><td>${dep.riskLevel}</td><td>${dep.vulnerabilities.map((item) => escapeHtml(item.id)).join(', ')}</td><td>${escapeHtml(dep.remediation.map((item) => item.targetVersion || item.type).join('; ') || 'Review advisory')}</td></tr>`).join('');
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SHIELDEX Executive Report â€” ${escapeHtml(report.projectName)}</title><style>body{font:15px/1.55 system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 22px;color:#E7F0EA;background:#111916}h1,h2{color:#42D6A0}.metrics,.bars{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.metrics div,.bars div{padding:14px;background:#17261F;border:1px solid rgba(202,235,215,.15);border-radius:10px}meter{width:70%;accent-color:#42D6A0}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:10px;border-bottom:1px solid rgba(202,235,215,.15)}th{color:#8BDCC0}.note{padding:12px;background:#49391F;border:1px solid rgba(230,212,119,.3)}button{padding:9px 14px;color:#10251B;background:#42D6A0;border:0;border-radius:7px;font:inherit;font-weight:650}@media print{body{max-width:none;margin:0;padding:20px;color:#17231B;background:#fff}.metrics div,.bars div,.note{color:#17231B;background:#f3f7f4;border-color:#c9d9ce}.no-print{display:none}}</style><h1>SHIELDEX Â· Executive Security Report</h1><p>${escapeHtml(report.projectName)} ${escapeHtml(report.projectVersion)} Â· Scan ${escapeHtml(report.generatedAt)} Â· Source ${escapeHtml(report.dataSource)}</p>${report.demo ? `<p class="note"><strong>SIMULATED DEMO DATA.</strong> ${escapeHtml(report.notice)}</p>` : ''}<div class="metrics"><div>Project risk <strong>${report.projectRiskScore ?? 'UNKNOWN'} / 100</strong> Â· ${escapeHtml(report.projectRiskLevel)}</div><div>Installed instances <strong>${report.dependencies.length}</strong></div><div>Confirmed advisories <strong>${report.coverage.advisoriesMatched}</strong></div><div>OSV status <strong>${escapeHtml(report.coverage.vulnerabilityStatus)}</strong></div></div><h2>Severity distribution</h2><div class="bars">${bars}</div><h2>Priority findings</h2><table><thead><tr><th>Package</th><th>Risk</th><th>Advisories</th><th>Remediation</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No confirmed advisory rows in this scan.</td></tr>'}</tbody></table><h2>Coverage and limitations</h2><p>OSV queries: ${report.coverage.osvQueriesSent}; failed: ${report.coverage.osvQueriesFailed}; registry lookups failed: ${report.coverage.registryFailures}; advisory details failed: ${report.coverage.advisoryDetailFailures}.</p><p class="note">Unknown or unavailable results are not safe results. Risk score is an evidence-based prioritization aid, not a guarantee of safety. Recommendations depend on advisory fixed-version data. ${escapeHtml((report.coverage.notes || []).join(' '))}</p><button class="no-print" onclick="window.print()">Print / Save as PDF</button></html>`;
}
function findingsCsv(report) {
  const cell = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;
  return [['package','version','direct','risk_level','risk_score','advisories','remediation'], ...report.dependencies.map((dep) => [dep.name,dep.version,dep.isDirect ? 'direct' : 'transitive',dep.riskLevel,dep.riskScore,dep.vulnerabilities.map((item) => item.id).join(';'),dep.remediation.map((item) => item.targetVersion || item.type).join(';')])].map((row) => row.map(cell).join(',')).join('\r\n');
}

function ExecutiveReport({ report }) {
  const [error, setError] = useState('');
  return <div className="security-view"><div className="tool-title"><div><span className="eyebrow">SHAREABLE Â· SCAN-DERIVED</span><h2>Executive Security Report</h2><p>HTML can be printed or saved to PDF from the browser. CSV contains per-instance findings.</p></div></div><div className="card executive-actions"><button className="tool-button" onClick={() => { try { downloadFile(`${report.projectName || 'project'}-shieldex-report.html`, executiveHtml(report), 'text/html'); setError(''); } catch (exception) { setError(exception.message); } }}>Download report (HTML / print to PDF)</button><button className="tool-button secondary" onClick={() => downloadFile(`${report.projectName || 'project'}-findings.csv`, findingsCsv(report), 'text/csv')}>Download findings CSV</button>{error && <p role="alert">{error}</p>}</div><div className="card executive-preview"><h3>{report.projectName} Â· {report.projectRiskScore ?? 'UNKNOWN'} / 100</h3><p>Scan time: {report.generatedAt} Â· Source: {report.dataSource}{report.demo ? ' Â· SIMULATED DEMO DATA' : ''}</p><p>{report.coverage.vulnerabilityStatus} OSV coverage Â· {report.coverage.osvQueriesFailed} query failure(s) Â· {report.coverage.registryFailures} registry failure(s)</p><p className="tool-muted">The downloadable report includes severity distribution, confirmed advisory IDs, remediation summary, coverage, uncertainty and limitations.</p></div></div>;
}

export default function SecurityWorkspace({ section, report, selectedId, onSelect }) {
  switch (section) {
    case 'threat-map': return <ThreatMap report={report} selectedId={selectedId} onSelect={onSelect} />;
    case 'impact': return <RelationshipPanel report={report} initialId={selectedId} impactMode />;
    case 'fix-advisor': return <FixAdvisor report={report} />;
    case 'signals': return <SignalCenter report={report} />;
    case 'risk-simulator': return <RiskSimulator report={report} />;
    case 'blast-radius': return <RelationshipPanel report={report} initialId={selectedId} impactMode={false} />;
    case 'name-review': return <NameReview report={report} />;
    case 'sbom': return <SbomPanel report={report} />;
    case 'security-gate': return <GatePanel report={report} />;
    case 'executive-report': return <ExecutiveReport report={report} />;
    default: return <p className="tool-empty">Choose an analysis tool from the workspace navigation.</p>;
  }
}
