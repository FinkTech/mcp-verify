/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 *
 * compile-sea.js
 * ──────────────
 * Generates Node.js Single Executable Applications (SEA) for mcp-verify.
 * Replaces `pkg` (CVE-2024-24828) with the native Node 20+ SEA API.
 *
 * Prerequisites (one-time):
 *   npm install --save-dev postject
 *
 * Usage:
 *   node tools/scripts/compile-sea.js              # current platform only
 *   node tools/scripts/compile-sea.js --all        # all platforms (needs node bins)
 *   node tools/scripts/compile-sea.js --target linux
 *   node tools/scripts/compile-sea.js --server     # also compile mcp-server
 *   node tools/scripts/compile-sea.js --no-sign    # skip macOS codesign (CI)
 *
 * Cross-platform compilation requires placing the target Node binaries at:
 *   tools/node-bins/node-v20-linux-x64   (no extension)
 *   tools/node-bins/node-v20-macos-x64   (no extension)
 *   tools/node-bins/node-v20-win-x64.exe
 *
 * Download them from: https://nodejs.org/dist/latest-v20.x/
 */

"use strict";

const { execSync, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

// ─────────────────────────────────────────────────────────────────────────────
// CLI argument parsing (no extra deps)
// ─────────────────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const hasFlag = (f) => argv.includes(f);
const flagValue = (f) => {
  const i = argv.indexOf(f);
  return i !== -1 ? argv[i + 1] : null;
};

const OPT = {
  all: hasFlag("--all"),
  server: hasFlag("--server"),
  noSign: hasFlag("--no-sign"),
  verbose: hasFlag("--verbose") || hasFlag("-v"),
  skipBuild: hasFlag("--skip-build"), // assume esbuild already ran
  target: flagValue("--target"), // linux | macos | windows
  nodeVersion: flagValue("--node-version") || "20",
};

// ─────────────────────────────────────────────────────────────────────────────
// Paths
// ─────────────────────────────────────────────────────────────────────────────

const ROOT = path.resolve(__dirname, "../..");
const DIST = path.join(ROOT, "dist");
const BIN_OUT = path.join(DIST, "bin"); // final executables land here
const SEA_DIR = path.join(DIST, ".sea"); // temp blobs
const NODE_BINS = path.join(ROOT, "tools", "node-bins"); // optional cross-compile bins

// ─────────────────────────────────────────────────────────────────────────────
// Build targets
// ─────────────────────────────────────────────────────────────────────────────

const ALL_TARGETS = [
  { id: "linux", platform: "linux", ext: "", nodeBinSuffix: "linux-x64" },
  { id: "macos", platform: "darwin", ext: "", nodeBinSuffix: "darwin-x64" },
  {
    id: "windows",
    platform: "win32",
    ext: ".exe",
    nodeBinSuffix: "win-x64.exe",
  },
];

function resolveTargets() {
  if (OPT.target) {
    const t = ALL_TARGETS.find((t) => t.id === OPT.target);
    if (!t) {
      die(`Unknown target "${OPT.target}". Valid: linux | macos | windows`);
    }
    return [t];
  }
  if (OPT.all) return ALL_TARGETS;

  // Default: current platform only
  const current =
    ALL_TARGETS.find((t) => t.platform === process.platform) ||
    ALL_TARGETS.find((t) => t.id === "linux"); // CI fallback
  return [current];
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging helpers
// ─────────────────────────────────────────────────────────────────────────────

const colors = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
  white: "\x1b[37m",
};

const c = (color, text) => `${colors[color]}${text}${colors.reset}`;

function log(msg) {
  console.log(`  ${c("cyan", "›")} ${msg}`);
}
function success(msg) {
  console.log(`  ${c("green", "✔")} ${c("bold", msg)}`);
}
function warn(msg) {
  console.log(`  ${c("yellow", "⚠")} ${msg}`);
}
function section(title) {
  console.log(`\n${c("bold", "  ── " + title + " ──")}`);
}
function die(msg) {
  console.error(`\n  ${c("red", "✗")} ${c("bold", msg)}\n`);
  process.exit(1);
}
function verbose(msg) {
  if (OPT.verbose) console.log(`  ${c("dim", "[verbose] " + msg)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Shell helpers
// ─────────────────────────────────────────────────────────────────────────────

function run(cmd, opts = {}) {
  verbose(`$ ${cmd}`);
  return execSync(cmd, { encoding: "utf8", stdio: "pipe", ...opts }).trim();
}

function runOrDie(cmd, errorMsg, opts = {}) {
  try {
    return run(cmd, opts);
  } catch (err) {
    die(`${errorMsg}\n    ${err.message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: resolve a local node_modules/.bin executable (no npx, no network)
// ─────────────────────────────────────────────────────────────────────────────

function resolveLocalBin(name) {
  // Check both root and hoisted workspace locations
  const candidates = [
    path.join(ROOT, "node_modules", ".bin", name),
    path.join(ROOT, "node_modules", ".bin", name + ".cmd"), // Windows
  ];
  return candidates.find((p) => fs.existsSync(p)) || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: compute SHA-256 of a file
// ─────────────────────────────────────────────────────────────────────────────

function sha256File(filePath) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(filePath))
    .digest("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1 – Validate prerequisites
// ─────────────────────────────────────────────────────────────────────────────

function validatePrerequisites() {
  section("Validating prerequisites");

  // Node version check (need ≥ 20 for SEA)
  const nodeVer = process.versions.node.split(".").map(Number);
  if (nodeVer[0] < 20) {
    die(`Node.js 20+ required for SEA. Found: ${process.version}`);
  }
  log(`Node.js ${process.version} ✓`);

  // postject must be installed as a local devDependency.
  // We resolve it directly from node_modules — no npx, no network, pinned version.
  const postjectBin = resolveLocalBin("postject");
  if (!postjectBin) {
    die(
      "postject not found in node_modules/.bin/.\n" +
        "    Run: npm install --save-dev postject\n" +
        "    Then retry: node tools/scripts/compile-sea.js",
    );
  }
  // Stash for use in injectBlob()
  process.env._MCP_POSTJECT_BIN = postjectBin;
  log(`postject ${c("dim", postjectBin)} ✓`);

  // macOS signing tools (soft check)
  if (process.platform === "darwin" && !OPT.noSign) {
    const hasCodesign = spawnSync("which", ["codesign"]).status === 0;
    if (!hasCodesign) {
      warn(
        "codesign not found. macOS binary will be unsigned. Use --no-sign to silence this.",
      );
    } else {
      log("codesign ✓");
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2 – Ensure esbuild bundle exists (or run it)
// ─────────────────────────────────────────────────────────────────────────────

function ensureBundle(bundleFile, label) {
  if (!fs.existsSync(bundleFile)) {
    if (OPT.skipBuild) {
      die(
        `Bundle not found at ${bundleFile}. Remove --skip-build to build first.`,
      );
    }
    log(`Bundle not found. Running esbuild for ${label}…`);
    runOrDie(
      `node ${path.join(ROOT, "tools/scripts/bundle.js")}`,
      "esbuild failed",
    );
  }

  if (!fs.existsSync(bundleFile)) {
    die(`Bundle still missing after build: ${bundleFile}`);
  }

  const sizeKB = (fs.statSync(bundleFile).size / 1024).toFixed(1);
  log(`Bundle: ${path.relative(ROOT, bundleFile)} (${sizeKB} KB) ✓`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 3 – Write SEA configuration JSON
//
// sea-config.json reference:
//   https://nodejs.org/api/single-executable-applications.html#generating-single-executable-preparation-blobs
//
// Notes on options:
//   useSnapshot       → V8 startup snapshot; avoid for CLI tools that read env/args
//   useCodeCache      → pre-compiled bytecode; safe, improves cold-start ~15%
//   assets            → embed static files (Node 21.2+; skip for Node 20 LTS)
// ─────────────────────────────────────────────────────────────────────────────

function writeSeaConfig(bundleFile, blobFile, label) {
  const configPath = path.join(SEA_DIR, `sea-config-${label}.json`);

  const config = {
    main: bundleFile,
    output: blobFile,
    // Disable snapshot: our CLI reads process.env, process.argv and calls
    // initLanguage() at startup — all incompatible with V8 snapshots.
    useSnapshot: false,
    // Enable code cache for faster startup (safe, no side effects).
    useCodeCache: true,
    // NOTE: "assets" key (for embedding non-JS files) requires Node ≥ 21.2.
    // Since mcp-verify uses esbuild to inline all TS/i18n/rules, we don't
    // need this. If you add file-based assets later, gate on node version:
    //   ...(nodeVer[0] >= 21 && nodeVer[1] >= 2 ? { assets: { ... } } : {}),
  };

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  verbose(`SEA config written to ${configPath}`);
  return configPath;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 4 – Generate the SEA preparation blob
// ─────────────────────────────────────────────────────────────────────────────

function generateBlob(seaConfigPath, blobFile) {
  log("Generating SEA preparation blob…");
  runOrDie(
    `node --experimental-sea-config "${seaConfigPath}"`,
    "Failed to generate SEA blob",
    { cwd: ROOT },
  );

  if (!fs.existsSync(blobFile)) {
    die(`Blob was not created at expected path: ${blobFile}`);
  }

  const blobSizeKB = (fs.statSync(blobFile).size / 1024).toFixed(1);
  log(`Blob generated: ${path.relative(ROOT, blobFile)} (${blobSizeKB} KB) ✓`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 5 – Locate the Node.js binary for a given target
//
// For the CURRENT platform: use process.execPath.
// For CROSS-COMPILATION: look in tools/node-bins/.
//
// Download official Node binaries from:
//   https://nodejs.org/dist/latest-v20.x/
// Rename them to the convention below and place in tools/node-bins/.
// ─────────────────────────────────────────────────────────────────────────────

function resolveNodeBinary(target) {
  // Same platform as host → use current Node executable directly
  if (target.platform === process.platform) {
    verbose(`Using host Node binary: ${process.execPath}`);
    return process.execPath;
  }

  // Cross-compile: look for pre-downloaded binary
  const suffix = target.nodeBinSuffix;
  const expected = path.join(NODE_BINS, `node-v${OPT.nodeVersion}-${suffix}`);

  if (!fs.existsSync(expected)) {
    die(
      `Cross-compile binary not found for target "${target.id}".\n` +
        `    Expected: ${expected}\n` +
        `    Download: https://nodejs.org/dist/latest-v${OPT.nodeVersion}.x/\n` +
        `    Rename the binary to: node-v${OPT.nodeVersion}-${suffix}`,
    );
  }

  verbose(`Using cross-compile Node binary: ${expected}`);
  return expected;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 6 – Copy + prepare the Node binary
// ─────────────────────────────────────────────────────────────────────────────

function prepareNodeCopy(target, label, nodeBinary) {
  const outputName =
    label === "cli"
      ? `mcp-verify${target.ext}`
      : `mcp-verify-server${target.ext}`;
  const outputPath = path.join(BIN_OUT, target.id, outputName);

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.copyFileSync(nodeBinary, outputPath);

  // Make executable on Unix
  if (target.platform !== "win32") {
    fs.chmodSync(outputPath, 0o755);
  }

  log(`Copied Node binary → ${path.relative(ROOT, outputPath)}`);
  return outputPath;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 7 – Remove macOS signature before injection
//
// Apple requires the binary signature to be stripped before postject can
// modify the binary, then re-signed afterward.
// ─────────────────────────────────────────────────────────────────────────────

function removeMacOSSignature(binaryPath) {
  if (process.platform !== "darwin") return;
  if (OPT.noSign) return;

  verbose("Removing existing macOS code signature…");
  try {
    run(`codesign --remove-signature "${binaryPath}"`);
    log("Existing macOS signature removed ✓");
  } catch {
    // Binary may not be signed; that's fine
    verbose("No existing signature to remove (or codesign unavailable)");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 8 – Inject the blob with postject
//
// postject injects arbitrary binary data into the NODE_SEA_BLOB section of
// the Mach-O / PE / ELF binary. Node detects this section at startup and
// runs the embedded script instead of loading an entry-point file.
//
// Flags:
//   --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
//     Required by Node.js to identify injected SEA executables.
//   --macho-segment-name NODE_SEA
//     Required on macOS (Mach-O format uses segments, not just sections).
// ─────────────────────────────────────────────────────────────────────────────

const SEA_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

function injectBlob(binaryPath, blobPath, target) {
  log("Injecting SEA blob with postject…");

  const machoFlag =
    target.platform === "darwin" ? "--macho-segment-name NODE_SEA" : "";

  // Use the local devDependency binary resolved in validatePrerequisites().
  // Never use npx here — it adds network latency and may resolve a different version.
  const postjectBin =
    process.env._MCP_POSTJECT_BIN ||
    resolveLocalBin("postject") ||
    die("postject binary not found. Run npm install --save-dev postject");

  const cmd = [
    `"${postjectBin}"`,
    `"${binaryPath}"`,
    "NODE_SEA_BLOB",
    `"${blobPath}"`,
    `--sentinel-fuse ${SEA_FUSE}`,
    machoFlag,
  ]
    .filter(Boolean)
    .join(" ");

  runOrDie(cmd, `postject injection failed for ${path.basename(binaryPath)}`);
  log("Blob injected ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 9 – Re-sign binary (macOS only)
//
// After postject modifies the Mach-O binary, it must be re-signed for
// macOS Gatekeeper to accept it. Ad-hoc signing (-) works for local use
// and distribution via direct download. For Mac App Store, use a proper
// Developer ID certificate.
// ─────────────────────────────────────────────────────────────────────────────

function signBinary(binaryPath, target) {
  if (target.platform !== "darwin") return;
  if (OPT.noSign) {
    warn(
      "Skipping macOS code signing (--no-sign). Binary may be blocked by Gatekeeper.",
    );
    return;
  }

  const codesignId = process.env.MCP_VERIFY_SIGN_IDENTITY || "-"; // '-' = ad-hoc
  const entitlements = process.env.MCP_VERIFY_ENTITLEMENTS_PATH
    ? `--entitlements "${process.env.MCP_VERIFY_ENTITLEMENTS_PATH}"`
    : "";

  log(`Signing binary (identity: ${codesignId})…`);
  runOrDie(
    `codesign --sign "${codesignId}" ${entitlements} "${binaryPath}"`,
    "codesign failed",
  );
  log("Binary signed ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 10 – Verify the binary runs (smoke test)
// ─────────────────────────────────────────────────────────────────────────────

function smokeTest(binaryPath, target) {
  // Only smoke-test if we're on the same platform as the binary
  if (target.platform !== process.platform) {
    warn(`Skipping smoke test for ${target.id} (cross-compiled binary)`);
    return;
  }

  log("Running smoke test…");
  try {
    const output = run(`"${binaryPath}" --version 2>&1`);
    if (output) {
      log(`Smoke test passed. Output: ${output.split("\n")[0]}`);
    } else {
      warn("Smoke test: no output from --version (binary ran without error)");
    }
  } catch (err) {
    warn(
      `Smoke test failed: ${err.message}\n    Binary may still work; check manually.`,
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 11 – Update integrity manifest
// (mirrors the logic from bundle.js → writeIntegrityManifestV2)
// ─────────────────────────────────────────────────────────────────────────────

function updateIntegrityManifest(artifacts) {
  const manifestDir = path.join(ROOT, ".mcp-verify");
  const manifestPath = path.join(manifestDir, "sea-integrity.json");

  fs.mkdirSync(manifestDir, { recursive: true });

  let gitCommit = "unknown";
  try {
    gitCommit = run("git rev-parse --short HEAD", { cwd: ROOT });
  } catch {}

  let pkgVersion = "0.0.0";
  try {
    pkgVersion = JSON.parse(
      fs.readFileSync(path.join(ROOT, "package.json"), "utf8"),
    ).version;
  } catch {}

  const entry = {
    buildId: `sea-${Date.now()}`,
    buildType: "node-sea",
    version: pkgVersion,
    timestamp: new Date().toISOString(),
    gitCommit,
    artifacts: artifacts.map((a) => ({
      target: a.target,
      label: a.label,
      path: path.relative(ROOT, a.path),
      size: fs.statSync(a.path).size,
      sha256: `sha256-${sha256File(a.path)}`,
    })),
  };

  let existing = { current: null, history: [] };
  try {
    existing = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {}
  existing.history = [existing.current, ...(existing.history || [])]
    .filter(Boolean)
    .slice(0, 20);
  existing.current = entry;

  const tmp = manifestPath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(existing, null, 2) + "\n");
  fs.renameSync(tmp, manifestPath);

  log(`Integrity manifest: ${path.relative(ROOT, manifestPath)}`);
  for (const a of entry.artifacts) {
    log(`  ${a.target}/${a.label}: ${a.sha256.slice(0, 26)}…`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile a single (target × label) combination
// ─────────────────────────────────────────────────────────────────────────────

function compileSingle(target, label, bundleFile) {
  const blobFile = path.join(SEA_DIR, `${label}-${target.id}.blob`);

  section(`${label.toUpperCase()} → ${target.id}`);

  // 3. SEA config
  const seaConfigPath = writeSeaConfig(
    bundleFile,
    blobFile,
    `${label}-${target.id}`,
  );

  // 4. Generate blob
  generateBlob(seaConfigPath, blobFile);

  // 5. Resolve Node binary
  const nodeBinary = resolveNodeBinary(target);

  // 6. Copy Node binary
  const outputBinary = prepareNodeCopy(target, label, nodeBinary);

  // 7. Remove macOS signature (before injection)
  removeMacOSSignature(outputBinary);

  // 8. Inject blob
  injectBlob(outputBinary, blobFile, target);

  // 9. Re-sign (macOS)
  signBinary(outputBinary, target);

  // 10. Smoke test
  smokeTest(outputBinary, target);

  success(`${label} / ${target.id} → ${path.relative(ROOT, outputBinary)}`);
  return outputBinary;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n${c("bold", "  🔒 mcp-verify — Node.js SEA Compiler")}`);
  console.log(
    c(
      "dim",
      `  Replaces pkg (CVE-2024-24828) with native Node ${OPT.nodeVersion}+ SEA\n`,
    ),
  );

  // 1. Prerequisites
  validatePrerequisites();

  // Ensure working directories exist
  fs.mkdirSync(BIN_OUT, { recursive: true });
  fs.mkdirSync(SEA_DIR, { recursive: true });

  const targets = resolveTargets();
  log(`Targets: ${targets.map((t) => t.id).join(", ")}`);

  // 2. Ensure bundles exist
  section("Checking bundles");
  const CLI_BUNDLE = path.join(DIST, "mcp-verify.js");
  const SERVER_BUNDLE = path.join(DIST, "mcp-server.js");

  ensureBundle(CLI_BUNDLE, "CLI");
  if (OPT.server) ensureBundle(SERVER_BUNDLE, "MCP Server");

  // Compile each target
  const allArtifacts = [];

  for (const target of targets) {
    const cliOut = compileSingle(target, "cli", CLI_BUNDLE);
    allArtifacts.push({ target: target.id, label: "cli", path: cliOut });

    if (OPT.server) {
      const serverOut = compileSingle(target, "server", SERVER_BUNDLE);
      allArtifacts.push({
        target: target.id,
        label: "server",
        path: serverOut,
      });
    }
  }

  // 11. Integrity manifest
  section("Integrity manifest");
  updateIntegrityManifest(allArtifacts);

  // Summary
  section("Build summary");
  for (const a of allArtifacts) {
    const sizeKB = (fs.statSync(a.path).size / 1024 / 1024).toFixed(1);
    success(
      `${a.target}/${a.label}: ${path.relative(ROOT, a.path)} (${sizeKB} MB)`,
    );
  }

  console.log(
    `\n  ${c("green", "✔")} ${c("bold", "SEA compilation complete.")}\n`,
  );
}

main().catch((err) => die(err.stack || err.message));
