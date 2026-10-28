# SHIELDEX GitHub Security Gate

The CLI scans the supplied manifest and lockfile with the same parser, OSV.dev client, npm registry client, and package scoring pipeline used by `/api/analyze`. It reads JSON as data; it does not install or execute packages from the scanned project. It sends package names and exact versions to OSV.dev and package names to the npm registry.

## Run locally

From the repository root:

```powershell
cd backend
npm.cmd ci
node cli/security-gate.js --package-json ..\backend\smoke\smoke-pkg.json --lockfile ..\backend\smoke\smoke-lock.json --fail-on HIGH --unknown fail
```

Options:

- `--fail-on CRITICAL|HIGH|MODERATE|LOW|NONE` fails when a confirmed advisory meets or exceeds the selected severity.
- `--unknown warn|fail|ignore` controls packages whose vulnerability result is unknown. The default is `warn`.
- Exit code `0` means policy passed; `1` means findings/unknown coverage violated policy; `2` means invalid input, configuration, or scan failure.

The gate prints scan coverage alongside policy results. Failed OSV queries are not reported as safe. Since the default CLI policy uses live OSV/npm endpoints, network or registry outages can prevent an authoritative scan.

## GitHub Actions example

Copy `docs/examples/shieldex-security-gate.yml` to `.github/workflows/shieldex-security-gate.yml` and copy the `backend` scanner folder into the Node.js application repository you want to scan. The workflow sample requires that target repository to have `package.json` and `package-lock.json` at its root. It installs only SHIELDEX's scanner dependencies, not the target application's dependencies. The sample is not active in or connected to any external repository from this workspace.
