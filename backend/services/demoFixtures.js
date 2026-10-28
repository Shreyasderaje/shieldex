// Built-in demo mode: FIXTURE data, clearly labelled as simulated.
//
// Nothing here is a live OSV result. The fixtures are run through the exact
// same parsing/scoring/recommendation pipeline as live scans, with the OSV
// and npm-registry service calls replaced by in-memory fixture responses.
// The lockfile versions and advisory ranges below are internally consistent:
// every advisory actually covers the fixture version that reports it, and
// fixed versions match the advisory history.

import { normalizeAdvisory, queryVulnIds as liveQueryVulnIds } from './osv.js';
import { summarizePackument, fetchRegistryMeta as liveFetchRegistryMeta } from './npmMeta.js';

export const DEMO_NOTICE =
  'SIMULATED DEMO DATA — these findings come from built-in fixtures, NOT from a live OSV.dev or npm registry scan.';

export const DEMO_PACKAGE_JSON = JSON.stringify(
  {
    name: 'demo-shop',
    version: '1.0.0',
    dependencies: {
      lodash: '^4.17.15',
      moment: '^2.24.0',
      request: '^2.88.2',
      'node-forge': '^0.7.6',
      'left-pad': '^1.3.0',
    },
    devDependencies: {
      webpack: '^4.43.0',
      'node-sass': '^4.14.1',
    },
  },
  null,
  2,
);

export const DEMO_LOCK_JSON = JSON.stringify(
  {
    name: 'demo-shop',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: 'demo-shop',
        version: '1.0.0',
        dependencies: {
          lodash: '^4.17.15',
          moment: '^2.24.0',
          request: '^2.88.2',
          'node-forge': '^0.7.6',
          'left-pad': '^1.3.0',
        },
        devDependencies: {
          webpack: '^4.43.0',
          'node-sass': '^4.14.1',
        },
      },
      'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
      'node_modules/moment': { version: '2.24.0', resolved: 'https://registry.npmjs.org/moment/-/moment-2.24.0.tgz' },
      'node_modules/request': {
        version: '2.88.2',
        resolved: 'https://registry.npmjs.org/request/-/request-2.88.2.tgz',
        dependencies: { 'tough-cookie': '~2.4.3' },
      },
      'node_modules/request/node_modules/tough-cookie': {
        version: '2.4.3',
        resolved: 'https://registry.npmjs.org/tough-cookie/-/tough-cookie-2.4.3.tgz',
      },
      'node_modules/node-forge': { version: '0.7.6', resolved: 'https://registry.npmjs.org/node-forge/-/node-forge-0.7.6.tgz' },
      'node_modules/left-pad': { version: '1.3.0', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz' },
      'node_modules/webpack': {
        version: '4.43.0',
        dev: true,
        resolved: 'https://registry.npmjs.org/webpack/-/webpack-4.43.0.tgz',
        dependencies: { lodash: '^4.17.19' },
      },
      'node_modules/webpack/node_modules/lodash': {
        version: '4.17.21',
        dev: true,
        resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
      },
      'node_modules/node-sass': {
        version: '4.14.1',
        dev: true,
        hasInstallScript: true,
        resolved: 'https://registry.npmjs.org/node-sass/-/node-sass-4.14.1.tgz',
      },
    },
  },
  null,
  2,
);

// Fixture advisories in raw OSV document shape (normalized through the same
// normalizeAdvisory() used for live data).
const FIXTURE_ADVISORY_DOCS = {
  'GHSA-p6mc-m468-83gw': {
    id: 'GHSA-p6mc-m468-83gw',
    summary: 'Prototype Pollution in lodash',
    aliases: ['CVE-2020-8203'],
    published: '2020-07-15T17:15:00Z',
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '4.0.0' }, { fixed: '4.17.19' }] }],
      },
    ],
  },
  'GHSA-35jh-r3h4-6jhm': {
    id: 'GHSA-35jh-r3h4-6jhm',
    summary: 'Command Injection in lodash',
    aliases: ['CVE-2021-23337'],
    published: '2021-02-15T18:15:00Z',
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0.0.0' }, { fixed: '4.17.21' }] }],
      },
    ],
  },
  'GHSA-8hfj-j24r-96c4': {
    id: 'GHSA-8hfj-j24r-96c4',
    summary: 'Path Traversal in moment',
    aliases: ['CVE-2022-24785'],
    published: '2022-04-04T20:15:00Z',
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'moment', ecosystem: 'npm' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0.0.0' }, { fixed: '2.29.2' }] }],
      },
    ],
  },
  'GHSA-wc69-2hcp-5jr3': {
    id: 'GHSA-wc69-2hcp-5jr3',
    summary: 'Inefficient Regular Expression Complexity in moment',
    aliases: ['CVE-2022-31129'],
    published: '2022-07-06T18:15:00Z',
    database_specific: { severity: 'MODERATE' },
    affected: [
      {
        package: { name: 'moment', ecosystem: 'npm' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0.0.0' }, { fixed: '2.29.4' }] }],
      },
    ],
  },
  'GHSA-p8p7-x288-28g6': {
    id: 'GHSA-p8p7-x288-28g6',
    summary: 'Server-Side Request Forgery in request',
    aliases: ['CVE-2023-28155'],
    published: '2023-03-21T19:15:00Z',
    database_specific: { severity: 'MODERATE' },
    affected: [
      {
        package: { name: 'request', ecosystem: 'npm' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0.0.0' }] }],
      },
    ],
  },
  'GHSA-92xj-mqp7-vmcj': {
    id: 'GHSA-92xj-mqp7-vmcj',
    summary: 'Prototype Pollution in node-forge',
    aliases: ['CVE-2020-7720'],
    published: '2020-09-28T20:15:00Z',
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'node-forge', ecosystem: 'npm' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0.0.0' }, { fixed: '0.10.0' }] }],
      },
    ],
  },
  'GHSA-72xf-g2v4-qvf3': {
    id: 'GHSA-72xf-g2v4-qvf3',
    summary: 'Tough Cookie module vulnerable to prototype pollution',
    aliases: ['CVE-2023-38547'],
    published: '2023-10-25T20:15:00Z',
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'tough-cookie', ecosystem: 'npm' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0.0.0' }, { fixed: '4.1.3' }] }],
      },
    ],
  },
};

// Which fixture advisories the fixture OSV "server" returns per exact version.
const FIXTURE_MATCHES = {
  'lodash@4.17.15': ['GHSA-p6mc-m468-83gw', 'GHSA-35jh-r3h4-6jhm'],
  'lodash@4.17.21': [],
  'moment@2.24.0': ['GHSA-8hfj-j24r-96c4', 'GHSA-wc69-2hcp-5jr3'],
  'request@2.88.2': ['GHSA-p8p7-x288-28g6'],
  'tough-cookie@2.4.3': ['GHSA-72xf-g2v4-qvf3'],
  'node-forge@0.7.6': ['GHSA-92xj-mqp7-vmcj'],
  'left-pad@1.3.0': [],
  'webpack@4.43.0': [],
  'node-sass@4.14.1': [],
};

const FIXTURE_PACKUMENTS = {
  lodash: {
    'dist-tags': { latest: '4.17.21' },
    time: { '4.17.15': '2019-07-13T18:00:00Z', '4.17.21': '2021-02-20T14:00:00Z' },
    versions: {
      '4.17.15': { license: 'MIT' },
      '4.17.21': { license: 'MIT' },
    },
    maintainers: [{}, {}],
  },
  moment: {
    'dist-tags': { latest: '2.29.4' },
    time: { '2.24.0': '2019-01-24T14:00:00Z', '2.29.4': '2022-07-06T15:00:00Z' },
    versions: { '2.24.0': { license: 'MIT' }, '2.29.4': { license: 'MIT' } },
    maintainers: [{}, {}, {}],
  },
  request: {
    'dist-tags': { latest: '2.88.2' },
    time: { '2.88.2': '2019-02-19T14:00:00Z' },
    versions: {
      '2.88.2': {
        license: 'Apache-2.0',
        deprecated: 'request has been deprecated, see https://github.com/request/request/issues/3142',
      },
    },
    maintainers: [{}, {}],
  },
  'tough-cookie': {
    'dist-tags': { latest: '4.1.3' },
    time: { '2.4.3': '2018-05-09T14:00:00Z', '4.1.3': '2023-01-06T15:00:00Z' },
    versions: { '2.4.3': { license: 'BSD-3-Clause' }, '4.1.3': { license: 'BSD-3-Clause' } },
    maintainers: [{}, {}],
  },
  'node-forge': {
    'dist-tags': { latest: '1.3.1' },
    time: { '0.7.6': '2018-10-29T14:00:00Z', '1.3.1': '2022-03-18T15:00:00Z' },
    versions: { '0.7.6': { license: 'BSD-3-Clause; GPL-2.0' }, '1.3.1': { license: '(BSD-3-Clause; GPL-2.0)' } },
    maintainers: [{}, {}],
  },
  'left-pad': {
    'dist-tags': { latest: '1.3.0' },
    time: { '1.3.0': '2016-07-13T14:00:00Z' },
    versions: { '1.3.0': { license: 'MIT' } },
    maintainers: [{}],
  },
  webpack: {
    'dist-tags': { latest: '5.88.2' },
    time: { '4.43.0': '2020-04-15T14:00:00Z', '5.88.2': '2023-06-15T15:00:00Z' },
    versions: { '4.43.0': { license: 'MIT' }, '5.88.2': { license: 'MIT' } },
    maintainers: [{}, {}, {}, {}, {}],
  },
  'node-sass': {
    'dist-tags': { latest: '9.0.0' },
    time: { '4.14.1': '2020-05-19T14:00:00Z', '9.0.0': '2023-09-13T15:00:00Z' },
    versions: { '4.14.1': { license: 'MIT' }, '9.0.0': { license: 'MIT' } },
    maintainers: [{}, {}],
  },
};

/** Fixture service implementations with the same signatures as the live ones. */
export function createDemoServices() {
  const advisories = new Map(
    Object.entries(FIXTURE_ADVISORY_DOCS).map(([id, doc]) => [id, normalizeAdvisory(doc)]),
  );
  return {
    queryVulnIds: async (pairs) => {
      const byKey = new Map();
      const okKeys = new Set();
      for (const { name, version } of pairs) {
        const key = `${name}@${version}`;
        if (key in FIXTURE_MATCHES) {
          byKey.set(key, [...FIXTURE_MATCHES[key]]);
          okKeys.add(key);
        }
      }
      return { byKey, okKeys, failedKeys: new Set() };
    },
    fetchAdvisories: async (ids) => ({
      advisories: new Map([...ids].filter((id) => advisories.has(id)).map((id) => [id, advisories.get(id)])),
      failures: [],
    }),
    fetchRegistryMeta: async (names) => {
      const byName = new Map();
      for (const name of names) {
        const packument = FIXTURE_PACKUMENTS[name];
        // Use the installed version actually present in the demo lockfile.
        const versionFromLock = {
          lodash: '4.17.15',
          moment: '2.24.0',
          request: '2.88.2',
          'tough-cookie': '2.4.3',
          'node-forge': '0.7.6',
          'left-pad': '1.3.0',
          webpack: '4.43.0',
          'node-sass': '4.14.1',
        }[name];
        if (packument && versionFromLock) byName.set(name, summarizePackument(packument, versionFromLock));
      }
      return { byName, failures: new Map() };
    },
  };
}
