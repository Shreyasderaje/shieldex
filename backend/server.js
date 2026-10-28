// SHIELDEX — Dependency Security Intelligence backend entrypoint.
//
// SECURITY NOTE: this server only JSON-parses uploaded package.json /
// package-lock.json content and calls read-only HTTPS APIs (OSV.dev, npm
// registry). It never executes uploaded files, never installs dependencies,
// never runs lifecycle scripts, and never spawns processes from user input.

import express from 'express';
import cors from 'cors';
import { createAnalyzeRouter } from './routes/analyze.js';
import { pathToFileURL } from 'node:url';

const app = express();
app.use(cors({ origin: ['http://localhost:3000', 'http://127.0.0.1:3000'] }));
// 12 MB body cap ≈ two 4 MB files + envelope; per-file 4 MB checks in the route.
app.use(express.json({ limit: '12mb' }));

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.use(createAnalyzeRouter());

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Upload too large (limit 12 MB total, 4 MB per file)' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Request body must be valid JSON' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const port = Number(process.env.PORT || 5000);
  app.listen(port, () => {
    console.log(`SHIELDEX backend running on http://localhost:${port}`);
  });
}

export default app;
