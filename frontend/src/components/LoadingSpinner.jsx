import React from 'react';

const RISK_COLORS = {
  CRITICAL: '#F07878',
  HIGH: '#F2B86F',
  MODERATE: '#E6D477',
  LOW: '#65CBA0',
  NONE: '#42D6A0',
  UNKNOWN: '#8FA8B8',
};

export const riskColor = (level) => RISK_COLORS[level] || RISK_COLORS.UNKNOWN;

function LoadingSpinner({ mode }) {
  return (
    <div className="loading-overlay" role="status" aria-live="polite" aria-label={mode === 'demo' ? 'Loading simulated demo report' : 'Scanning dependencies'}>
      <div className="spinner">
        <div className="spinner-circle" />
        <p>
          {mode === 'demo'
            ? 'Running demo scan on built-in fixtures…'
            : 'Querying OSV.dev and the npm registry…'}
        </p>
        <small>
          {mode === 'demo'
            ? 'Simulated data — no live APIs are called.'
            : 'Matching exact installed versions against advisories.'}
        </small>
      </div>
    </div>
  );
}

export default LoadingSpinner;
