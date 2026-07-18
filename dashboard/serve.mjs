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
// The action endpoint is guarded two ways because it spawns a multi-minute
// `cargo test --workspace`: a localhost-only Origin/Host allowlist (drive-by
// CSRF + DNS-rebind can't reach it) and a single-flight lock (a second POST
// while one is running is rejected, never a second overlapping cargo run).
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

// --- request-origin guard: localhost only ----------------------------------
// The /api/regenerate action spawns a multi-minute `cargo test --workspace`, so
// a hostile page in the user's browser (a drive-by tab, or a DNS-rebind that
// makes a foreign hostname resolve to 127.0.0.1) must not be able to POST to it.
// Accept the action only when it plainly originates from this local server:
//   - Host header (if present) must name localhost/127.0.0.1/[::1] on our port;
//   - Origin/Referer (if present) must do the same. A same-origin fetch from our
//     own page sends a matching Origin; a rebind attack cannot forge one that
//     both parses as a URL and carries a loopback hostname on our port.
// A CLI caller (curl) with no Host/Origin at all is allowed — it is not a
// browser and cannot be driven cross-origin by a web page.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
function hostIsLocal(hostHeader) {
  if (!hostHeader) return true; // absent Host: not a browser attack vector
  const hostname = hostHeader.replace(/:\d+$/, ""); // strip :port
  return LOOPBACK_HOSTS.has(hostname);
}
function originIsLocal(originHeader) {
  if (!originHeader || originHeader === "null") return true; // absent: allow (CLI); "null": opaque origin, treated below
  try {
    const u = new URL(originHeader);
    return LOOPBACK_HOSTS.has(u.hostname) && Number(u.port || 0) === PORT;
  } catch {
    return false;
  }
}
function isLocalRequest(req) {
  if (!hostIsLocal(req.headers.host)) return false;
  // An Origin of "null" (opaque, e.g. from a sandboxed/file:// document) is not
  // our own same-origin page, so reject it for the action endpoint.
  if (req.headers.origin === "null") return false;
  if (!originIsLocal(req.headers.origin)) return false;
  if (!originIsLocal(req.headers.referer)) return false;
  return true;
}

// --- POST /api/regenerate : run the real generator, report real output -----
// Single-flight: at most one generator runs at a time. A concurrent POST while
// one is in flight is rejected (409) rather than spawning a second overlapping
// `cargo test --workspace` — which would burn CPU twice over and race two
// writers on status.js.
let regenInFlight = false;
function regenerate(res) {
  if (regenInFlight) {
    return send(res, 409, JSON.stringify({
      ok: false, code: null, error: "a regeneration is already in progress",
    }), JSON_HDR);
  }
  regenInFlight = true;
  const startedAt = Date.now();
  console.log(`[regenerate] spawning: node ${GENERATOR}`);
  const child = spawn(process.execPath, [GENERATOR], { cwd: REPO_ROOT, env: process.env });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => { stdout += d; process.stdout.write(d); });
  child.stderr.on("data", (d) => { stderr += d; process.stderr.write(d); });
  child.on("error", (err) => {
    regenInFlight = false;
    send(res, 500, JSON.stringify({
      ok: false, code: null, error: `could not spawn generator: ${err.message}`,
      stdout, stderr, durationMs: Date.now() - startedAt,
    }), JSON_HDR);
  });
  child.on("close", (code) => {
    regenInFlight = false;
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
    // Reject cross-origin / foreign-Host POSTs (drive-by CSRF + DNS-rebind).
    if (!isLocalRequest(req)) {
      return send(res, 403, JSON.stringify({
        ok: false, code: null, error: "forbidden: this action is localhost-only",
      }), JSON_HDR);
    }
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
