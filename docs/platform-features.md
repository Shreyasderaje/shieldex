# SHIELDEX platform feature notes

SHIELDEX reuses the existing lockfile parser, exact-version OSV.dev checks, npm metadata lookup and risk scoring. The feature workspace presents that report without changing scanner semantics. Demo fixtures remain labelled as simulated.

## Evidence boundaries

- The threat map and reverse-dependency views use only dependency instances and edges present in the scanner's parsed lockfile graph. They do not infer runtime reachability.
- Impact paths and risk-reduction controls are hypothetical. A package is eligible for risk reduction only when the report contains fixed-version remediation evidence covering its confirmed advisories; changing a control does not modify the scan report or mark anything fixed.
- Fix suggestions use the scanner's existing remediation evidence. No AI provider is configured or called. Transitive proposals use npm `overrides` and should be reviewed for compatibility.
- Threat signals separate confirmed OSV advisories from local heuristic warnings and insufficient metadata. The project has no live malicious-package feed or early-warning feed configured. Name similarity is a heuristic, not a malware verdict.
- CycloneDX 1.5 and SPDX 2.3 downloads are built from exact installed instances and known lockfile relationships. Missing identifiers, versions or relationships are not invented; incomplete input is rejected where a valid document cannot be formed.
- Executive HTML and findings CSV exports are generated from the current report. Use the browser's print dialog to save the HTML report as PDF.
- The policy CLI evaluates a live scan and exits 0 when allowed, 1 when policy fails, or 2 on invalid input/scan failure. The workflow in `docs/examples` is a copyable example and is not connected to another repository.

## Run locally

In PowerShell, start the backend and frontend in separate terminals:

```powershell
cd backend
npm.cmd start
```

```powershell
cd frontend
npm.cmd run dev
```

Open `http://localhost:3000`. The Vite proxy targets backend port 5000 by default; set `BACKEND_PORT` for Vite and `PORT` for the backend when using another port. Do not install dependencies from projects being scanned.
