// Sorting utilities for the findings table.
//
// Correctly orders numeric fields (by value), text fields (case-insensitive
// locale compare) and semver-ish version strings. Unknown/null values
// ("unknown", null, undefined) always sort LAST in ascending order — never
// interleaved with real values — regardless of direction.

export function isUnknown(value) {
  if (value === null || value === undefined) return true;
  if (typeof value === 'number') return false;
  if (typeof value === 'string') {
    const t = value.trim().toLowerCase();
    return t === '' || t === 'unknown' || t === 'n/a' || t === '-';
  }
  return false;
}

function parseSemver(v) {
  if (typeof v !== 'string') return null;
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function compareValues(a, b) {
  const aUnknown = isUnknown(a);
  const bUnknown = isUnknown(b);
  if (aUnknown && bUnknown) return 0;
  if (aUnknown) return 1; // unknowns after everything
  if (bUnknown) return -1;

  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return (a ? 1 : 0) - (b ? 1 : 0);

  const sa = String(a);
  const sb = String(b);
  const va = parseSemver(sa);
  const vb = parseSemver(sb);
  if (va && vb) {
    for (let i = 0; i < 3; i++) {
      if (va[i] !== vb[i]) return va[i] < vb[i] ? -1 : 1;
    }
    return sa.localeCompare(sb);
  }
  return sa.localeCompare(sb, undefined, { sensitivity: 'base', numeric: true });
}

/**
 * Sorts rows for a given column. `accessor(row)` returns the raw value.
 * Ascending: real values ascending, then unknowns last.
 * Descending: real values descending, unknowns still last (mirrored rule).
 */
export function sortRows(rows, accessor, direction) {
  const dir = direction === 'desc' ? -1 : 1;
  return [...rows].sort((ra, rb) => {
    const a = accessor(ra);
    const b = accessor(rb);
    const aU = isUnknown(a);
    const bU = isUnknown(b);
    if (aU && bU) return compareValues(ra.name, rb.name); // stable-ish tiebreak
    if (aU) return 1;
    if (bU) return -1;
    const cmp = compareValues(a, b) * dir;
    return cmp !== 0 ? cmp : compareValues(ra.name, rb.name);
  });
}
