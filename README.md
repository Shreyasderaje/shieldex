# SHIELDEX
### Dependency Security Intelligence

**See the risk. Secure your dependencies.**

SHIELDEX is a Node.js dependency security analysis platform that helps developers identify vulnerable packages, understand dependency relationships, and explore potential security risks.

## Features

- **Dependency Threat Map** — Visualize packages and resolved dependency relationships.
- **Attack Impact Simulator** — Explore hypothetical dependency attack scenarios.
- **Fix Advisor** — Review remediation guidance for identified vulnerabilities.
- **Threat Signals** — Examine available vulnerability advisories and suspicious-package indicators.
- **What-if Risk Simulator** — Compare potential risk changes under hypothetical scenarios.
- **Blast Radius Analyzer** — Investigate the potential impact of vulnerable dependencies.
- **Package Name Review** — Review package names for potential concerns.
- **SBOM Export** — Export supported Software Bill of Materials data.
- **Security Gate** — Evaluate projects against configured security checks.
- **Executive Report** — Present security findings in a report-friendly format.

## How It Works

1. Upload a Node.js `package.json`.
2. Provide the corresponding `package-lock.json`.
3. Run the dependency analysis.
4. Review vulnerability advisories, package relationships, and risk indicators.
5. Explore the analysis tools and available remediation guidance.

SHIELDEX uses exact-version vulnerability advisory matching with OSV.dev. Results depend on the supplied package data and available advisory information.

## Technology Stack

- React
- Vite
- Node.js
- Express
- OSV.dev vulnerability data

## Getting Started

Clone the repository:

```bash
git clone https://github.com/Shreyasderaje/shieldex.git
cd shieldex
```

Install dependencies in the frontend and backend directories using their respective `package.json` files. Run the development scripts defined in those files to start the application.

## Security Notes

- Use matching package manifests and lockfiles.
- Vulnerability results depend on advisory coverage and package-version accuracy.
- Hypothetical scenarios do not prove real-world exploitability.
- Review remediation suggestions before applying changes.
- Never commit API keys, passwords, tokens, or private `.env` files.

## Project Status

SHIELDEX is under active development.

## Team

**Team Sudarshan**
