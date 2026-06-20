#!/usr/bin/env node
// SOV dashboard server.
//
// A tiny, dependency-free (Node std `http` only) static server for the SOV
// dashboard that ALSO exposes one action endpoint, POST /api/regenerate, which
// runs the real `dashboard/gen-status.mjs` generator (which in turn runs a real
// `cargo test --workspace`) and rewrites status.js.
//
// Why this exists: the dashboard is otherwise a static file:// page, and a page
// opened from file:// cannot spawn `cargo`/`node`. The Regenerate button needs
// *something* local that can. This server is that something — and nothing more.
// It fabricates no data: /api/regenerate just shells out to the same generator
// you would run by hand and reports its real exit code + real output.
//
// Usage:
//   node dashboard/serve.mjs            # serve on http://localhost:8787
//   PORT=9000 node dashboard/serve.mjs  # choose a port
//
// ABSOLUTE RULE (project-wide): no dummy data. This server only serves real
// files and runs the real generator.

import { createServer, get as httpGet } from "node:http";
import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");
const GENERATOR = join(__dirname, "gen-status.mjs");
const PORT = Number(process.env.PORT) || 8787;
const HOST = "127.0.0.1";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".map": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function send(res, code, body, headers = {}) {
  res.writeHead(code, { "Cache-Control": "no-store", ...headers });
  res.end(body);
}

const JSON_HDR = { "Content-Type": MIME[".json"] };

// --- POST /api/regenerate : run the real generator, report real output -----
function regenerate(res) {
  const startedAt = Date.now();
  console.log(`[regenerate] spawning: node ${GENERATOR}`);
  const child = spawn(process.execPath, [GENERATOR], { cwd: REPO_ROOT, env: process.env });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => { stdout += d; process.stdout.write(d); });
  child.stderr.on("data", (d) => { stderr += d; process.stderr.write(d); });
  child.on("error", (err) => {
    send(res, 500, JSON.stringify({
      ok: false, code: null, error: `could not spawn generator: ${err.message}`,
      stdout, stderr, durationMs: Date.now() - startedAt,
    }), JSON_HDR);
  });
  child.on("close", (code) => {
    const durationMs = Date.now() - startedAt;
    console.log(`[regenerate] generator exited ${code} in ${durationMs}ms`);
    send(res, code === 0 ? 200 : 500,
      JSON.stringify({ ok: code === 0, code, stdout, stderr, durationMs }), JSON_HDR);
  });
}

// --- static file serving, confined to the dashboard/ directory -------------
async function serveStatic(res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === "/" || rel === "") rel = "/index.html";
  const full = normalize(join(__dirname, rel));
  if (full !== __dirname && !full.startsWith(__dirname + "/")) {
    return send(res, 403, "Forbidden"); // no path traversal outside dashboard/
  }
  try {
    const st = await stat(full);
    if (st.isDirectory()) return send(res, 403, "Forbidden");
    const buf = await readFile(full);
    const type = MIME[extname(full).toLowerCase()] || "application/octet-stream";
    return send(res, 200, buf, { "Content-Type": type });
  } catch {
    // chain-status.js is legitimately absent until you mine; the page is built
    // to no-op when it's missing. Serve an honest empty stub rather than a 404
    // (mirrors how file:// silently ignores the missing <script>). Not data —
    // just an empty placeholder so the console stays clean.
    if (rel === "/chain-status.js") {
      return send(res, 200, "// no live mining session (chain-status.js absent — run sov-miner)\n",
        { "Content-Type": MIME[".js"] });
    }
    return send(res, 404, "Not found");
  }
}

const server = createServer((req, res) => {
  const { pathname } = new URL(req.url, `http://${req.headers.host || HOST}`);

  if (pathname === "/api/health") {
    return send(res, 200, JSON.stringify({ server: "sov-dashboard", port: PORT }), JSON_HDR);
  }
  if (pathname === "/api/regenerate") {
    if (req.method !== "POST") return send(res, 405, "Method Not Allowed", { Allow: "POST" });
    return regenerate(res);
  }
  if (req.method !== "GET" && req.method !== "HEAD") {
    return send(res, 405, "Method Not Allowed");
  }
  return serveStatic(res, pathname);
});

// If the port is taken, find out whether it is already *this* server (reuse it)
// or something else (fail loudly — never hijack a stranger's port).
server.on("error", (e) => {
  if (e.code !== "EADDRINUSE") { console.error(`server error: ${e.message}`); process.exit(1); }
  let done = false;
  const finish = (msg, code) => {
    if (done) return; done = true;
    (code ? console.error : console.log)(msg);
    process.exit(code);
  };
  const probe = httpGet({ host: HOST, port: PORT, path: "/api/health" }, (r) => {
    let body = ""; r.on("data", (d) => (body += d));
    r.on("end", () => {
      try {
        if (JSON.parse(body).server === "sov-dashboard") {
          return finish(`SOV dashboard already running → http://localhost:${PORT}`, 0);
        }
      } catch { /* fall through */ }
      finish(`Port ${PORT} is in use by another process. Choose another: PORT=<n> node dashboard/serve.mjs`, 1);
    });
  });
  probe.on("error", () => finish(`Port ${PORT} is in use. Choose another: PORT=<n> node dashboard/serve.mjs`, 1));
  probe.setTimeout(1500, () => { probe.destroy(); finish(`Port ${PORT} is in use (no health response). Choose another: PORT=<n> node dashboard/serve.mjs`, 1); });
});

server.listen(PORT, HOST, () => {
  console.log(`SOV dashboard → http://localhost:${PORT}`);
  console.log(`  serving ${__dirname}`);
  console.log(`  POST /api/regenerate runs the real gen-status.mjs (cargo test --workspace)`);
});
