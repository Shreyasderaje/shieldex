// Small HTTP helpers shared by the OSV and npm registry clients:
// JSON fetching with timeout, retry-on-transient-failure, response
// validation, and a bounded-concurrency pool. We only ever parse JSON —
// nothing from scanned files or API responses is ever executed.

export async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function isTransientError(err) {
  if (err && err.permanent) return false;
  return true; // timeouts, network failures, 429/5xx are worth one retry
}

export async function fetchJson(url, {
  method = 'GET',
  body,
  headers = {},
  timeoutMs = 12000,
  fetchImpl = globalThis.fetch,
  retries = 1,
} = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await sleep(600 * attempt);
    try {
      const res = await fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 429 || res.status >= 500) {
        lastError = new Error(`HTTP ${res.status} from ${url}`);
        continue;
      }
      if (!res.ok) {
        const err = new Error(`HTTP ${res.status} from ${url}`);
        err.status = res.status;
        err.permanent = true; // 404 and friends will not get better on retry
        throw err;
      }
      const text = await res.text();
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        throw new Error(`Invalid JSON response from ${url}`);
      }
      return { status: res.status, json };
    } catch (err) {
      if (err && err.permanent) throw err;
      lastError = err;
    }
  }
  throw lastError;
}

/**
 * Maps `fn` over `items` with at most `limit` calls in flight at once.
 * Never rejects: each result is {ok:true, value} or {ok:false, error}.
 */
export async function mapPool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      while (next < items.length) {
        const idx = next++;
        try {
          results[idx] = { ok: true, value: await fn(items[idx], idx) };
        } catch (error) {
          results[idx] = { ok: false, error };
        }
      }
    },
  );
  await Promise.all(workers);
  return results;
}

export function chunk(items, size) {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}
