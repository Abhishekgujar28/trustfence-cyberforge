'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { analyze, mergeSemanticFindings } = require('./src/analyzer');
const { semanticScan } = require('./src/ollama');
const ROOT = __dirname;
const PORT = Number(process.env.PORT || 4173);
const MAX_BODY = 200_000;
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' });
  res.end(type.startsWith('application/json') ? JSON.stringify(body) : body);
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/analyze') {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > MAX_BODY) {
        send(res, 413, { error: 'Request too large. Limit is 200 KB.' });
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        const payload = JSON.parse(raw || '{}');
        const result = analyze(payload);
        if (result.error) return send(res, 400, result);
        if (process.env.OLLAMA_ENABLED === 'true') {
          semanticScan({ userIntent: String(payload.userIntent), untrustedContent: String(payload.untrustedContent) })
            .then(scan => {
              if (scan.ok) return send(res, 200, mergeSemanticFindings(result, scan, String(payload.userIntent), String(payload.untrustedContent)));
              result.analysisMode = 'RULES_ONLY_FALLBACK';
              result.semanticScan = { enabled: true, ok: false, model: scan.model, message: scan.message };
              return send(res, 200, result);
            });
          return;
        }
        result.semanticScan = { enabled: false, ok: false, message: 'Optional local LLM is off; using deterministic rule engine.' };
        return send(res, 200, result);
      } catch {
        return send(res, 400, { error: 'Invalid JSON request.' });
      }
    });
    return;
  }
  if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed.' });
  let urlPath = (req.url || '/').split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';
  const publicRoot = path.resolve(ROOT, 'public');
  const filePath = path.resolve(publicRoot, '.' + urlPath);
  if (!filePath.startsWith(publicRoot + path.sep) && filePath !== path.join(publicRoot, 'index.html')) return send(res, 403, { error: 'Forbidden.' });
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, { error: 'Not found.' });
    send(res, 200, data, MIME[path.extname(filePath)] || 'application/octet-stream');
  });
});
server.listen(PORT, '127.0.0.1', () => console.log(`TrustFence MVP running at http://127.0.0.1:${PORT}`));
