#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { analyzeProject } from '../routes/analyze.js';
import { queryVulnIds } from '../services/osv.js';
import { fetchAdvisories } from '../services/osv.js';
import { fetchRegistryMeta } from '../services/npmMeta.js';
import { evaluatePolicy } from '../services/policy.js';

function args(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!['--package-json', '--lockfile', '--fail-on', '--unknown'].includes(key)) throw new Error(`Unknown argument: ${key}`);
    if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`Missing value for ${key}`);
    result[key.slice(2)] = argv[++i];
  }
  if (!result['package-json'] || !result.lockfile) throw new Error('Usage: node backend/cli/security-gate.js --package-json package.json --lockfile package-lock.json [--fail-on HIGH] [--unknown warn|fail|ignore]');
  return { packageJsonPath: result['package-json'], lockPath: result.lockfile, failOn: (result['fail-on'] || 'HIGH').toUpperCase(), unknown: result.unknown || 'warn' };
}

try {
  const options = args(process.argv.slice(2));
  const [packageJsonText, lockJsonText] = await Promise.all([
    readFile(options.packageJsonPath, 'utf8'),
    readFile(options.lockPath, 'utf8'),
  ]);
  const report = await analyzeProject({ packageJsonText, lockJsonText }, { queryVulnIds, fetchAdvisories, fetchRegistryMeta });
  if (!report.ok) throw new Error(report.error);
  const result = evaluatePolicy(report, options);
  console.log(JSON.stringify({ project: report.projectName, dataSource: report.dataSource, coverage: report.coverage, policy: result }, null, 2));
  if (!result.passed) process.exitCode = 1;
} catch (error) {
  console.error(`SHIELDEX security gate: ${error.message}`);
  process.exitCode = 2;
}
