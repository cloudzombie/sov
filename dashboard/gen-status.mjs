#!/usr/bin/env node
// SOV dashboard status generator.
//
// Inspects the REAL repository state and emits dashboard/status.js as a
// `window.SOV_STATUS = { ... };` assignment so it can be loaded from a plain
// <script> tag (works under file:// — unlike fetch() of JSON).
//
// ABSOLUTE RULE: no dummy data. Every value here is read from the filesystem
// or parsed from a real command's output. When something doesn't exist or a
// command fails, that is reported honestly — never faked.
//
// Run from the repo root:  node dashboard/gen-status.mjs

import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync, existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const CHAIN_DIR = join(REPO_ROOT, "chain");
const CHAIN_CRATES = join(CHAIN_DIR, "crates");
const EXPLORER_DIR = join(REPO_ROOT, "explorer");
const PHASES_PATH = join(__dirname, "phases.json");
const OUT_PATH = join(__dirname, "status.js");

// --- helpers ---------------------------------------------------------------

function listDirs(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
}

function walkFiles(dir, predicate, acc = []) {
  if (!existsSync(dir)) return acc;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "target" || entry.name === "node_modules" || entry.name === ".git") {
      continue;
    }
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(full, predicate, acc);
    } else if (predicate(full)) {
      acc.push(full);
    }
  }
  return acc;
}

function countLines(file) {
  try {
    const text = readFileSync(file, "utf8");
    if (text.length === 0) return 0;
    // Count line separators; add 1 for a final line lacking a trailing newline.
    const newlines = (text.match(/\n/g) || []).length;
    return text.endsWith("\n") ? newlines : newlines + 1;
  } catch {
    return 0;
  }
}

// --- 1. Chain tests via real cargo run -------------------------------------

function readCrateName(crateDir) {
  const cargoToml = join(crateDir, "Cargo.toml");
  if (!existsSync(cargoToml)) return null;
  const m = readFileSync(cargoToml, "utf8").match(/^\s*name\s*=\s*"([^"]+)"/m);
  return m ? m[1] : null;
}

// Read the workspace `members = [...]` list so we can tell which crate
// directories are actually part of the build (and thus actually tested).
function readWorkspaceMembers() {
  const cargoToml = join(CHAIN_DIR, "Cargo.toml");
  if (!existsSync(cargoToml)) return [];
  const text = readFileSync(cargoToml, "utf8");
  const m = text.match(/members\s*=\s*\[([^\]]*)\]/);
  if (!m) return [];
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

function runChainTests() {
  const result = {
    ran: false,
    status: "unknown",
    passed: 0,
    failed: 0,
    message: "",
    perBinary: {},
  };

  if (!existsSync(join(CHAIN_DIR, "Cargo.toml"))) {
    result.status = "not_started";
    result.message = "chain/Cargo.toml not found";
    return result;
  }

  // Merge stderr into stdout (2>&1) so cargo's "Running …(target/…)" lines
  // (stderr) stay interleaved with the test binaries' "test result:" lines
  // (stdout) in execution order — that ordering is what lets us attribute each
  // result to the crate that produced it. Captured separately, the two streams
  // arrive as two blocks and the pairing is lost.
  const manifest = join(CHAIN_DIR, "Cargo.toml");
  const proc = spawnSync(`cargo test --workspace --manifest-path "${manifest}" 2>&1`, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: true,
  });

  if (proc.error) {
    // cargo binary missing / not spawnable.
    result.status = "error";
    result.message = `cargo could not run: ${proc.error.message}`;
    return result;
  }

  const output = `${proc.stdout || ""}${proc.stderr || ""}`;
  result.ran = true;

  // Walk the output line by line. Each test binary prints a
  //   "Running <kind> (target/.../<base>-<hash>)"  (or "Doc-tests <crate>")
  // line, then later a "test result: ok./FAILED. N passed; M failed" line. We
  // pair them so every result is attributed to the binary that produced it
  // (result.perBinary[base]) AND summed into the workspace totals. Every number
  // comes straight from real cargo output — nothing is inferred or fabricated.
  // Anchor on the ".../deps/<base>-<hash>)" tail so it matches regardless of the
  // target-dir prefix (e.g. "(target/…" when run from chain/, or "(chain/target/…"
  // when run from the repo root with --manifest-path).
  const runRe = /Running\s+.*deps[/\\]([A-Za-z0-9_]+)-[0-9a-f]+\)/;
  const docRe = /Doc-tests\s+([A-Za-z0-9_]+)/;
  const resRe = /test result:\s*(ok|FAILED)\.\s*(\d+)\s+passed;\s*(\d+)\s+failed/;
  let sawResultLine = false;
  let currentBase = null;
  for (const line of output.split("\n")) {
    const run = line.match(runRe);
    if (run) {
      currentBase = run[1];
      continue;
    }
    const doc = line.match(docRe);
    if (doc) {
      currentBase = doc[1];
      continue;
    }
    const res = line.match(resRe);
    if (res) {
      sawResultLine = true;
      const passed = Number(res[2]);
      const failed = Number(res[3]);
      result.passed += passed;
      result.failed += failed;
      if (currentBase) {
        const acc = result.perBinary[currentBase] || { passed: 0, failed: 0 };
        acc.passed += passed;
        acc.failed += failed;
        result.perBinary[currentBase] = acc;
        currentBase = null;
      }
    }
  }

  if (!sawResultLine) {
    // No test-result lines means the build itself failed (compile error etc.).
    result.status = "error";
    const errLine = (proc.stderr || output)
      .split("\n")
      .find((l) => /^error/.test(l));
    result.message = errLine
      ? errLine.trim()
      : "cargo test produced no test-result lines (build likely failed)";
    return result;
  }

  result.status = result.failed === 0 ? "passing" : "failing";
  result.message =
    result.failed === 0
      ? `All ${result.passed} tests passing`
      : `${result.failed} of ${result.passed + result.failed} tests failing`;
  return result;
}

// --- 2. Real crates --------------------------------------------------------

function inspectCrates(perBinary = {}) {
  const dirs = listDirs(CHAIN_CRATES);
  const members = readWorkspaceMembers();
  const underscore = (s) => s.replace(/-/g, "_");
  return dirs.map((d) => {
    const crateDir = join(CHAIN_CRATES, d);
    const name = readCrateName(crateDir) || d;
    const rsFiles = walkFiles(crateDir, (f) => f.endsWith(".rs"));
    const loc = rsFiles.reduce((sum, f) => sum + countLines(f), 0);
    const srcDir = join(crateDir, "src");
    const hasLib = existsSync(join(srcDir, "lib.rs"));
    const hasMain = existsSync(join(srcDir, "main.rs"));
    const binDir = join(srcDir, "bin");
    const binStems = (existsSync(binDir) ? readdirSync(binDir) : [])
      .filter((f) => f.endsWith(".rs"))
      .map((f) => f.slice(0, -3));
    const testsDir = join(crateDir, "tests");
    const testStems = (existsSync(testsDir) ? readdirSync(testsDir) : [])
      .filter((f) => f.endsWith(".rs"))
      .map((f) => f.slice(0, -3));
    const hasBuildTarget = hasLib || hasMain || binStems.length > 0;
    const inWorkspace = members.includes(`crates/${d}`);

    // Honest, finer-grained state:
    //   active           — a library crate that is part of the workspace build
    //   binary           — in the build, ships a binary/main but has no library yet
    //   scaffold         — in the build but has NO build target at all (truly incomplete)
    //   not_in_workspace — a directory that is not a workspace member
    let state;
    if (!inWorkspace) state = "not_in_workspace";
    else if (hasLib) state = "active";
    else if (hasMain || binStems.length > 0) state = "binary";
    else state = "scaffold";

    // Human-readable target kind, e.g. "library", "library + 1 bin", "1 bin".
    const kindParts = [];
    if (hasLib) kindParts.push("library");
    if (hasMain) kindParts.push("binary (main)");
    if (binStems.length) {
      kindParts.push(`${binStems.length} bin${binStems.length === 1 ? "" : "s"}`);
    }
    const kind = kindParts.join(" + ") || "no targets";

    // Attribute real test counts to this crate by the cargo artifact base names
    // it owns: its lib/main use the package name; each src/bin/<x>.rs and
    // tests/<x>.rs use the file stem (cargo turns '-' into '_' in artifacts).
    const ownedBases = new Set([underscore(name)]);
    for (const b of binStems) ownedBases.add(underscore(b));
    for (const t of testStems) ownedBases.add(underscore(t));
    let attributed = false;
    let testsPassed = 0;
    let testsFailed = 0;
    for (const [base, r] of Object.entries(perBinary)) {
      if (ownedBases.has(base)) {
        attributed = true;
        testsPassed += r.passed;
        testsFailed += r.failed;
      }
    }

    return {
      dir: d,
      name,
      rustFiles: rsFiles.length,
      loc,
      inWorkspace,
      hasLib,
      hasMain,
      bins: binStems,
      hasBuildTarget,
      state,
      kind,
      tests: { attributed, passed: testsPassed, failed: testsFailed },
    };
  });
}

// --- 3. Total Rust LOC across chain/crates ---------------------------------

function totalRustLoc() {
  const files = walkFiles(CHAIN_CRATES, (f) => f.endsWith(".rs"));
  const loc = files.reduce((sum, f) => sum + countLines(f), 0);
  return { files: files.length, loc };
}

// --- 4. Explorer status ----------------------------------------------------

function inspectExplorer() {
  const result = {
    exists: existsSync(EXPLORER_DIR),
    hasPackageJson: false,
    sourceFiles: 0,
    status: "not_started",
    message: "",
  };

  if (!result.exists) {
    result.message = "explorer/ directory not found";
    return result;
  }

  result.hasPackageJson = existsSync(join(EXPLORER_DIR, "package.json"));

  const srcExts = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".rs"];
  const srcFiles = walkFiles(EXPLORER_DIR, (f) =>
    srcExts.some((ext) => f.endsWith(ext))
  );
  result.sourceFiles = srcFiles.length;

  if (!result.hasPackageJson && result.sourceFiles === 0) {
    result.status = "not_started";
    result.message = "scaffolding pending — no package.json or source files yet";
  } else if (result.hasPackageJson && result.sourceFiles === 0) {
    result.status = "scaffolding";
    result.message = "package.json present, no source files yet";
  } else {
    result.status = "in_progress";
    result.message = `${result.sourceFiles} source file(s) present`;
  }
  return result;
}

// --- 5. Phases (single source of truth for roadmap progress) ---------------

function loadPhases() {
  if (!existsSync(PHASES_PATH)) {
    return { error: "dashboard/phases.json not found", phases: [] };
  }
  try {
    const data = JSON.parse(readFileSync(PHASES_PATH, "utf8"));
    return data;
  } catch (e) {
    return { error: `could not parse phases.json: ${e.message}`, phases: [] };
  }
}

// Normalize an item's kanban status. Source of truth for "done" is the
// boolean `done` flag (which must reflect real repo state). `status` adds the
// in-progress lane for project tracking; it can never silently upgrade an
// item to "done" — only the real `done` flag can do that.
function normStatus(item) {
  if (item.done === true) return "done";
  const s = (item.status || "todo").toLowerCase();
  if (s === "done") return "done"; // honored only because done flag also true above; otherwise demote
  if (s === "in_progress" || s === "in-progress" || s === "doing") return "in_progress";
  return "todo";
}

function summarizePhases(phasesDoc) {
  const phases = phasesDoc.phases || [];
  let totalItems = 0;
  let doneItems = 0;
  let inProgressItems = 0;
  let todoItems = 0;
  const perPhase = phases.map((p) => {
    const items = p.items || [];
    const done = items.filter((i) => i.done === true).length;
    totalItems += items.length;
    doneItems += done;
    return {
      id: p.id,
      title: p.title,
      tag: p.tag,
      description: p.description || null,
      items: items.map((i, idx) => {
        // Guard: an item flagged status:"done" but done:false stays out of the
        // done lane — we never fabricate completion.
        let status = i.done === true ? "done" : normStatus(i);
        if (status === "done" && i.done !== true) status = "in_progress";
        if (status === "in_progress") inProgressItems++;
        else if (status === "todo") todoItems++;
        return {
          id: i.id || `p${p.id}-i${idx}`,
          text: i.text,
          done: i.done === true,
          status,
          note: i.note || null,
        };
      }),
      doneCount: done,
      totalCount: items.length,
      percent: items.length === 0 ? 0 : Math.round((done / items.length) * 100),
    };
  });
  return {
    perPhase,
    totalItems,
    doneItems,
    inProgressItems,
    todoItems,
    percent: totalItems === 0 ? 0 : Math.round((doneItems / totalItems) * 100),
  };
}

// --- assemble & emit -------------------------------------------------------

function main() {
  const chainTests = runChainTests();
  const crates = inspectCrates(chainTests.perBinary || {});
  const rust = totalRustLoc();
  const explorer = inspectExplorer();
  const phasesDoc = loadPhases();
  const phases = summarizePhases(phasesDoc);

  const status = {
    generatedAt: new Date().toISOString(),
    generator: "dashboard/gen-status.mjs",
    repoRoot: REPO_ROOT,
    chain: {
      crateCount: crates.length,
      crates,
      rustFiles: rust.files,
      rustLoc: rust.loc,
      tests: chainTests,
    },
    explorer,
    progress: {
      percent: phases.percent,
      doneItems: phases.doneItems,
      totalItems: phases.totalItems,
      inProgressItems: phases.inProgressItems,
      todoItems: phases.todoItems,
    },
    roadmapIntro: phasesDoc.intro || null,
    phases: phases.perPhase,
    phasesError: phasesDoc.error || null,
  };

  const banner =
    "// AUTO-GENERATED by dashboard/gen-status.mjs — DO NOT EDIT BY HAND.\n" +
    "// Every value below is derived from real repo state. Refresh with:\n" +
    "//   node dashboard/gen-status.mjs\n";

  const body = `window.SOV_STATUS = ${JSON.stringify(status, null, 2)};\n`;
  writeFileSync(OUT_PATH, banner + body, "utf8");

  // Console summary so a human running it sees the real numbers.
  console.log("SOV status generated ->", OUT_PATH);
  console.log(`  generated at : ${status.generatedAt}`);
  console.log(`  crates       : ${status.chain.crateCount} (${crates.map((c) => `${c.name}[${c.state}]`).join(", ") || "none"})`);
  console.log(`  rust LOC     : ${status.chain.rustLoc} across ${status.chain.rustFiles} file(s)`);
  console.log(`  chain tests  : ${chainTests.status} — ${chainTests.passed} passed / ${chainTests.failed} failed`);
  console.log(`  explorer     : ${explorer.status} — ${explorer.message}`);
  console.log(`  progress     : ${phases.percent}% (${phases.doneItems}/${phases.totalItems} items)`);
  if (phasesDoc.error) console.log(`  WARNING      : ${phasesDoc.error}`);
}

main();
