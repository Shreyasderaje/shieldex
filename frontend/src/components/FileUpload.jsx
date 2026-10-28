import React, { useMemo, useState } from 'react';

const MAX_BYTES = 4 * 1024 * 1024; // mirrors the backend limit

// Client-side pre-validation of both files BEFORE analysis starts; the
// backend re-validates. Only reading + JSON.parse — nothing is ever executed.

async function readAndValidate(file, kind) {
  if (!file) return { ok: true, text: null };
  if (file.size > MAX_BYTES) {
    return { ok: false, error: `${file.name} is too large (${(file.size / 1024 / 1024).toFixed(1)} MB, limit 4 MB).` };
  }
  const text = await file.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    return { ok: false, error: `${file.name} is not valid JSON: ${err.message}.` };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: `${file.name} must contain a JSON object.` };
  }
  if (kind === 'lock') {
    if (!parsed.packages && !parsed.dependencies) {
      return { ok: false, error: `${file.name} does not look like an npm lockfile (missing "packages" or "dependencies"). Lockfile versions 1, 2 and 3 are supported.` };
    }
    if (typeof parsed.lockfileVersion === 'number' && parsed.lockfileVersion > 3) {
      return { ok: false, error: `${file.name}: lockfileVersion ${parsed.lockfileVersion} is not supported (supported: 1, 2, 3).` };
    }
  }
  if (kind === 'pkg' && !parsed.name && !parsed.dependencies && !parsed.devDependencies) {
    return { ok: false, error: `${file.name} does not look like a package.json (no name/dependencies/devDependencies).` };
  }
  return { ok: true, text };
}

function FileUpload({ onAnalyze, onDemo, disabled }) {
  const [pkgFile, setPkgFile] = useState(null);
  const [lockFile, setLockFile] = useState(null);
  const [localError, setLocalError] = useState(null);
  const [busy, setBusy] = useState(false);

  const ready = Boolean(pkgFile) && !busy && !disabled;

  const handlePkg = (e) => {
    setLocalError(null);
    setPkgFile(e.target.files?.[0] || null);
  };
  const handleLock = (e) => {
    setLocalError(null);
    setLockFile(e.target.files?.[0] || null);
  };

  const handleStart = async () => {
    setBusy(true);
    setLocalError(null);
    try {
      const [pkg, lock] = await Promise.all([
        readAndValidate(pkgFile, 'pkg'),
        readAndValidate(lockFile, 'lock'),
      ]);
      if (!pkg.ok) { setLocalError(pkg.error); return; }
      if (!lock.ok) { setLocalError(lock.error); return; }
      await onAnalyze(pkg.text, lock.text);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="upload-container">
      <div className="upload-box">
        <h2>Analyze a Node.js project</h2>
        <p className="upload-intro">
          Select package.json and, when available, package-lock.json, then press Analyze. The lockfile provides exact
          installed versions, which is what OSV.dev vulnerability matching requires — without it no
          vulnerability claims are made.
        </p>
        <div className="file-inputs">
          <label className={pkgFile ? 'chosen' : ''}>
            <input type="file" accept=".json,application/json" onChange={handlePkg} disabled={busy || disabled} />
            <span>package.json *</span>
            <small>{pkgFile ? pkgFile.name : 'required'}</small>
          </label>
          <label className={lockFile ? 'chosen' : ''}>
            <input type="file" accept=".json,application/json" onChange={handleLock} disabled={busy || disabled} />
            <span>package-lock.json *</span>
            <small>{lockFile ? lockFile.name : 'required for vulnerability scan'}</small>
          </label>
        </div>

        {localError && <div className="error-box small" role="alert">{localError}</div>}

        <button className="btn-primary" onClick={handleStart} disabled={!ready}>
          {busy ? 'Validating…' : 'Analyze dependencies'}
        </button>
        {!lockFile && pkgFile && (
          <p className="upload-hint warning-hint">
            No lockfile selected: analysis will list declared packages only and the vulnerability
            scan will be skipped (scores shown as UNKNOWN).
          </p>
        )}

        <div className="demo-divider"><span>or</span></div>
        <button className="btn-secondary" onClick={onDemo} disabled={busy || disabled}>
          Run demo with built-in fixtures (clearly labelled, not live data)
        </button>

        <p className="privacy-note">
          Files are parsed as JSON only. Nothing you upload is executed, installed, or run —
          lifecycle scripts are reported as static evidence, never triggered.
        </p>
      </div>
    </div>
  );
}

export default FileUpload;
