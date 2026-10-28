import React, { useCallback, useState } from 'react';
import FileUpload from './components/FileUpload.jsx';
import RiskReport from './components/RiskReport.jsx';
import LoadingSpinner from './components/LoadingSpinner.jsx';
import { WorkspaceSidebar, WORKSPACE_SECTIONS } from './components/SecurityWorkspace.jsx';
import { apiUrl } from './api.js';

function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(null); // 'live' | 'demo'
  const [error, setError] = useState(null);
  const [activeSection, setActiveSection] = useState('overview');
  const [selectedPackageId, setSelectedPackageId] = useState('');

  const handleAnalyze = useCallback(async (packageJson, lockJson) => {
    setLoading('live');
    setError(null);
    try {
      const response = await fetch(apiUrl('/api/analyze'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packageJson, lockJson }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Server error ${response.status}`);
      setReport(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(null);
    }
  }, []);

  const handleDemo = useCallback(async () => {
    setLoading('demo');
    setError(null);
    try {
      const response = await fetch(apiUrl('/api/demo'));
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Server error ${response.status}`);
      setReport(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(null);
    }
  }, []);

  const resetScan = () => { setReport(null); setActiveSection('overview'); setSelectedPackageId(''); setError(null); };
  const activeLabel = WORKSPACE_SECTIONS.find(([id]) => id === activeSection)?.[1] || 'Overview';
  return (
    <div className="app">
      {loading && <LoadingSpinner mode={loading} />}
      <div className="workspace-shell">
        <WorkspaceSidebar active={activeSection} onNavigate={setActiveSection} ready={Boolean(report)} onNewScan={resetScan} />
        <div className="workspace-content">
        <header className="app-header"><div className="topbar-identity"><span>SHIELDEX</span><i />{report ? <strong>{report.projectName}</strong> : <strong>Dependency Security Intelligence</strong>}<small>{activeLabel}</small></div><div className="topbar-actions">{report && <span className="scan-source">{report.demo ? 'Simulated demo' : `${report.coverage.vulnerabilityStatus} OSV coverage`}</span>}</div></header>
        <main className="workspace-main">
          {error && <div className="error-box" role="alert">{error}</div>}
          {!report ? (
            <FileUpload onAnalyze={handleAnalyze} onDemo={handleDemo} disabled={Boolean(loading)} />
          ) : (
            <>
              <RiskReport data={report} activeSection={activeSection} selectedPackageId={selectedPackageId} onSelectPackage={setSelectedPackageId} />
            </>
          )}
        </main>
        </div>
      </div>
    </div>
  );
}

export default App;
