/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
const esbuild = require("esbuild");
const path = require("path");
const fs = require("fs");
const crypto = require("node:crypto");
const { execSync } = require("child_process");

const distDir = path.join(__dirname, "../../dist");
const rootDir = path.join(__dirname, "../..");

// Ensure dist directory exists
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// ---------------------------------------------------------------------------
// Workspace alias plugin
// Maps @mcp-verify/* monorepo packages to their source paths on disk.
// ---------------------------------------------------------------------------
const workspaceAliasPlugin = {
  name: "workspace-alias",
  setup(build) {
    const aliases = {
      "@mcp-verify/core": path.join(rootDir, "libs/core"),
      "@mcp-verify/shared": path.join(rootDir, "libs/shared"),
      "@mcp-verify/transport": path.join(rootDir, "libs/transport"),
      "@mcp-verify/protocol": path.join(rootDir, "libs/protocol"),
      "@mcp-verify/fuzzer": path.join(rootDir, "libs/fuzzer"),
    };

    build.onResolve({ filter: /^@mcp-verify\// }, (args) => {
      const parts = args.path.split("/");
      const pkgName = `${parts[0]}/${parts[1]}`;
      const subPath = parts.slice(2).join("/");

      if (!aliases[pkgName]) return undefined;

      if (!subPath) {
        return { path: path.join(aliases[pkgName], "index.ts") };
      }

      const basePath = path.join(aliases[pkgName], subPath);
      const candidates = [
        basePath + ".ts",
        basePath + ".js",
        path.join(basePath, "index.ts"),
        path.join(basePath, "index.js"),
        basePath,
      ];

      for (const candidate of candidates) {
        try {
          if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
            return { path: candidate };
          }
        } catch {
          // Continue to next candidate
        }
      }

      // Default: assume .ts extension
      return { path: basePath + ".ts" };
    });
  },
};

// ---------------------------------------------------------------------------
// Integrity helpers
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 hash of a file and return it as a hex string.
 * @param {string} filePath - Absolute path to the file.
 * @returns {string} Hex-encoded SHA-256 digest.
 */
function computeFileSha256(filePath) {
  const contents = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(contents).digest("hex");
}

/**
 * Read the "version" field from the root package.json.
 * Falls back to "0.0.0" if the file is absent or unparseable.
 * @returns {string}
 */
function readRootVersion() {
  try {
    const pkgPath = path.join(rootDir, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * Get the current git commit hash (short format).
 * Falls back to "unknown" if git is not available or not a git repository.
 * @returns {string}
 */
function getGitCommitHash() {
  try {
    return execSync("git rev-parse --short HEAD", {
      encoding: "utf8",
      cwd: rootDir,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "unknown";
  }
}

/**
 * Load existing integrity history from .mcp-verify/integrity-history.json.
 * Returns null if the file doesn't exist or is unparseable.
 * @param {string} manifestPath - Absolute path to the manifest file.
 * @returns {object | null}
 */
function loadExistingHistory(manifestPath) {
  try {
    if (!fs.existsSync(manifestPath)) {
      return null;
    }
    const content = fs.readFileSync(manifestPath, "utf8");
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Write .mcp-verify/integrity-history.json with hashes for BOTH CLI and Server binaries.
 * Maintains a history of the last N builds (default: 20).
 *
 * @param {string} cliPath - Absolute path to the CLI bundle (mcp-verify.js)
 * @param {string} serverPath - Absolute path to the MCP Server bundle (mcp-server.js)
 */
function writeIntegrityManifestV2(cliPath, serverPath) {
  // Ensure .mcp-verify directory exists (survives `npm run clean`)
  const workspaceDir = path.join(rootDir, ".mcp-verify");
  if (!fs.existsSync(workspaceDir)) {
    fs.mkdirSync(workspaceDir, { recursive: true });
  }

  const manifestPath = path.join(workspaceDir, "integrity-history.json");
  const version = readRootVersion();
  const timestamp = new Date().toISOString();
  const buildId = `build-${Date.now()}`;
  const gitCommit = getGitCommitHash();

  // Hash both binaries
  const cliHash = computeFileSha256(cliPath);
  const serverHash = computeFileSha256(serverPath);

  const cliStats = fs.statSync(cliPath);
  const serverStats = fs.statSync(serverPath);

  // Create current build entry
  const currentBuild = {
    buildId,
    version,
    timestamp,
    gitCommit,
    binaries: {
      cli: {
        hash: `sha256-${cliHash}`,
        path: path.relative(rootDir, cliPath),
        size: cliStats.size,
      },
      server: {
        hash: `sha256-${serverHash}`,
        path: path.relative(rootDir, serverPath),
        size: serverStats.size,
      },
    },
  };

  // Load existing manifest and history
  const existingManifest = loadExistingHistory(manifestPath);
  let history = [];
  if (existingManifest && Array.isArray(existingManifest.history)) {
    history = existingManifest.history;
  }

  // Add current build to history
  history.unshift(currentBuild);

  // Trim history to 20 entries (from DEFAULT_CONFIG.integrity.historyLimit)
  const historyLimit = 20;
  if (history.length > historyLimit) {
    history = history.slice(0, historyLimit);
  }

  // Create new manifest
  const manifest = {
    current: currentBuild,
    history,
  };

  // Write atomically (write to .tmp then rename)
  const tmpPath = manifestPath + ".tmp";
  fs.writeFileSync(tmpPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  fs.renameSync(tmpPath, manifestPath);

  console.log(
    `🔒 Integrity manifest written to ${path.relative(rootDir, manifestPath)}`,
  );
  console.log(`   CLI hash:    sha256-${cliHash.slice(0, 16)}...`);
  console.log(`   Server hash: sha256-${serverHash.slice(0, 16)}...`);
  console.log(`   Version:     ${version}`);
  console.log(`   Git commit:  ${gitCommit}`);
  console.log(`   Build ID:    ${buildId}`);
  console.log(`   History:     ${history.length} builds tracked`);
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

console.log("🚀 Starting build with esbuild...");

const bundleOutfile = path.join(distDir, "mcp-verify.js");

const buildCLI = esbuild.build({
  plugins: [workspaceAliasPlugin],
  entryPoints: [
    path.join(__dirname, "../../apps/cli-verifier/src/bin/index.ts"),
  ],
  outfile: bundleOutfile,
  bundle: true,
  platform: "node",
  target: "node20",
  minify: false,
  define: { "import.meta.url": "__import_meta_url__" },
  banner: {
    // __filename behaviour by context:
    //   node dist/mcp-verify.js  → path to the .js file on disk
    //   SEA binary               → process.execPath (the compiled binary)
    // native-loader.ts uses path.dirname(process.execPath), not __dirname,
    // so it is unaffected by this difference.
    js: `#!/usr/bin/env node\nconst __import_meta_url__ = require("url").pathToFileURL(__filename).href;\n// Build ID: ${new Date().getTime()}`,
  },
  sourcemap: true,
  external: [
    // Native addons: excluded from bundle, resolved at runtime by
    // libs/core/src/native-loader.ts (works in dev, npm install, and SEA).
    "fsevents",
    "@napi-rs/keyring",
    // Peer dependencies: optional LLM SDKs — only loaded when the user
    // configures --llm. Must stay external: they are not in dependencies,
    // only in peerDependencies, so they may not be installed at build time.
    "@anthropic-ai/sdk",
    "@modelcontextprotocol/sdk",
  ],
  logLevel: "info",
});

// ---------------------------------------------------------------------------
// Build MCP Server
// ---------------------------------------------------------------------------
const serverOutfile = path.join(distDir, "mcp-server.js");

const buildServer = esbuild.build({
  plugins: [workspaceAliasPlugin],
  entryPoints: [path.join(__dirname, "../../apps/mcp-server/src/index.ts")],
  outfile: serverOutfile,
  bundle: true,
  platform: "node",
  target: "node20",
  minify: true,
  define: { "import.meta.url": "__import_meta_url__" },
  banner: {
    js: `#!/usr/bin/env node\nconst __import_meta_url__ = require("url").pathToFileURL(__filename).href;\n// Build ID: ${new Date().getTime()}`,
  },
  sourcemap: true,
  external: [
    "fsevents",
    "@napi-rs/keyring",
    "@anthropic-ai/sdk",
    "@modelcontextprotocol/sdk",
  ],
  logLevel: "info",
});

Promise.all([buildCLI, buildServer])
  .then(() => {
    // ---------------------------------------------------------------------------
    // Post-build UI: Professional build summary
    // ---------------------------------------------------------------------------
    const chalkModule = require("chalk");
    const chalk = chalkModule.default || chalkModule;
    const separator = chalk.white.dim("  " + "─".repeat(50));

    console.log(`\n  ${chalk.green("✔")} ${chalk.bold("Build complete:")}`);
    console.log(`     • ${chalk.cyan("dist/mcp-verify.js")} (CLI)`);
    console.log(`     • ${chalk.cyan("dist/mcp-server.js")} (MCP Server)`);
    console.log(separator);
    console.log(`  ${chalk.bold.yellow("🔒 Integrity Manifest v1.0")}`);
    console.log(separator);

    // Write integrity manifest for BOTH binaries with history tracking
    writeIntegrityManifestV2(bundleOutfile, serverOutfile);

    console.log(separator + "\n");
  })
  .catch((err) => {
    console.error("❌ Build failed:", err);
    process.exit(1);
  });
