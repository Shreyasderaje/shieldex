// Semver-ish comparison used for ordering versions and checking whether a
// fixed version is newer than the installed one. Handles prerelease tags
// loosely (numeric-first), which is enough for advisory fixed-version logic.

export function parseVersion(input) {
  if (typeof input !== 'string') return null;
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(input.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    pre: m[4] ? m[4].split('.').map((p) => (/^\d+$/.test(p) ? { num: Number(p) } : { str: p })) : [],
  };
}

export function isValidVersion(input) {
  return parseVersion(input) !== null;
}

function comparePre(a, b) {
  // No prerelease > has prerelease
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const pa = a[i];
    const pb = b[i];
    if (!pa) return -1;
    if (!pb) return 1;
    if (pa.num !== undefined && pb.num !== undefined) {
      if (pa.num !== pb.num) return pa.num < pb.num ? -1 : 1;
    } else if (pa.str !== undefined && pb.str !== undefined) {
      if (pa.str !== pb.str) return pa.str < pb.str ? -1 : 1;
    } else {
      // numeric identifiers always have lower precedence than alphanumeric
      return pa.num !== undefined ? -1 : 1;
    }
  }
  return 0;
}

/** Returns -1 | 0 | 1. Unparseable versions sort after parseable ones. */
export function compareVersions(a, b) {
  const va = parseVersion(a);
  const vb = parseVersion(b);
  if (!va && !vb) return 0;
  if (!va) return 1;
  if (!vb) return -1;
  if (va.major !== vb.major) return va.major < vb.major ? -1 : 1;
  if (va.minor !== vb.minor) return va.minor < vb.minor ? -1 : 1;
  if (va.patch !== vb.patch) return va.patch < vb.patch ? -1 : 1;
  return comparePre(va.pre, vb.pre);
}
