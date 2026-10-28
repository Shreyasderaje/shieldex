// npm registry metadata client.
//
// Fetches the full packument (one request per unique package NAME) and
// derives metadata for BOTH the exact installed version and the latest
// published version. All fields are kept distinct:
//   - installedPublishedAt  (when the installed version was published)
//   - latestPublishedAt     (when the latest version was published)
//   - installedLicense / latestLicense
//   - installedDeprecated   (deprecation message of the installed version)
// Missing data is reported as explicit "unknown" values, never guessed.

import { fetchJson, mapPool } from './http.js';

const REGISTRY_BASE = process.env.NPM_REGISTRY_BASE || 'https://registry.npmjs.org';
const CONCURRENCY = 6;
const TIMEOUT_MS = Number(process.env.NPM_TIMEOUT_MS || 15000);

export function summarizePackument(packument, installedVersion) {
  const latest = packument && packument['dist-tags'] && typeof packument['dist-tags'].latest === 'string'
    ? packument['dist-tags'].latest
    : null;
  const time = packument && typeof packument.time === 'object' && packument.time ? packument.time : {};
  const versions = packument && typeof packument.versions === 'object' && packument.versions ? packument.versions : {};
  const installedEntry = installedVersion ? versions[installedVersion] : null;

  const unknown = (v) => (typeof v === 'string' && v ? v : 'unknown');

  return {
    status: 'ok',
    latestVersion: latest || 'unknown',
    latestPublishedAt: unknown(latest ? time[latest] : null),
    installedPublishedAt: unknown(installedVersion ? time[installedVersion] : null),
    installedDeprecated:
      installedEntry && typeof installedEntry.deprecated === 'string' && installedEntry.deprecated
        ? installedEntry.deprecated
        : installedEntry && installedEntry.deprecated === true
          ? 'deprecated'
          : null,
    installedLicense: unknown(installedEntry ? installedEntry.license : packument && packument.license),
    latestLicense: unknown(latest ? (versions[latest] ? versions[latest].license : undefined) : null),
    maintainers: Array.isArray(packument && packument.maintainers) ? packument.maintainers.length : null,
  };
}

/**
 * @param {string[]} names unique package names
 * @returns {Promise<{byName: Map<string, object>, failures: Map<string, string>}>}
 *          byName maps name -> summarizePackument() result or {status:'not_found'}
 */
export async function fetchRegistryMeta(names, { fetchImpl = globalThis.fetch, log = () => {} } = {}) {
  const uniqueNames = [...new Set(names)].filter((n) => typeof n === 'string' && n && n.length <= 214 && !n.startsWith('@types/'));
  const byName = new Map();
  const failures = new Map();

  const results = await mapPool(uniqueNames, CONCURRENCY, async (name) => {
    const encoded = name.startsWith('@') ? name.replace('/', '%2f') : name;
    const { json } = await fetchJson(`${REGISTRY_BASE}/${encoded}`, {
      headers: { Accept: 'application/json' },
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
    if (!json || typeof json !== 'object' || !json.name) {
      throw new Error('packument response shape invalid');
    }
    return json;
  });

  for (let i = 0; i < results.length; i++) {
    const name = uniqueNames[i];
    const result = results[i];
    if (result.ok) {
      // result.value is the validated packument JSON
      byName.set(name, result.value);
    } else if (result.error && result.error.status === 404) {
      byName.set(name, { status: 'not_found' });
    } else {
      failures.set(name, result.error ? result.error.message : 'unknown error');
      log(`registry fetch failed for ${name}: ${result.error && result.error.message}`);
    }
  }
  return { byName, failures };
}
