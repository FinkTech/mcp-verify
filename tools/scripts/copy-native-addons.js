/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 *
 * copy-native-addons.js
 * ─────────────────────
 * Post-compile step: copies native Node addons (.node files) next to each
 * SEA executable so they can be found at runtime via require().
 *
 * Why this is needed:
 *   pkg virtualised native addons inside its snapshot filesystem.
 *   Node SEA has no virtual FS — require() resolves against the real
 *   filesystem. Native addons must therefore live alongside the executable.
 *
 * Expected output layout:
 *   dist/bin/
 *   ├── linux/
 *   │   ├── mcp-verify                        ← SEA executable
 *   │   └── keyring.linux-x64-gnu.node        ← native addon (copied here)
 *   ├── macos/
 *   │   ├── mcp-verify
 *   │   ├── keyring.darwin-x64.node
 *   │   └── fsevents.node                     ← macOS only
 *   └── windows/
 *       ├── mcp-verify.exe
 *       └── keyring.win32-x64-msvc.node
 *
 * Usage (run after compile-sea.js):
 *   node tools/scripts/copy-native-addons.js
 *   node tools/scripts/copy-native-addons.js --verbose
 *   node tools/scripts/copy-native-addons.js --target linux
 *   node tools/scripts/copy-native-addons.js --dry-run
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// CLI flags
// ─────────────────────────────────────────────────────────────────────────────

const argv    = process.argv.slice(2);
const VERBOSE = argv.includes('--verbose') || argv.includes('-v');
const DRY_RUN = argv.includes('--dry-run');
const TARGET  = (() => { const i = argv.indexOf('--target'); return i !== -1 ? argv[i + 1] : null; })();

// ─────────────────────────────────────────────────────────────────────────────
// Paths
// ─────────────────────────────────────────────────────────────────────────────

const ROOT    = path.resolve(__dirname, '../..');
const BIN_OUT = path.join(ROOT, 'dist', 'bin');

// ─────────────────────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────────────────────

const c = {
  green:  s => `\x1b[32m${s}\x1b[0m`,
  yellow: s => `\x1b[33m${s}\x1b[0m`,
  cyan:   s => `\x1b[36m${s}\x1b[0m`,
  dim:    s => `\x1b[2m${s}\x1b[0m`,
  bold:   s => `\x1b[1m${s}\x1b[0m`,
  red:    s => `\x1b[31m${s}\x1b[0m`,
};

const log     = msg => console.log(`  ${c.cyan('›')} ${msg}`);
const success = msg => console.log(`  ${c.green('✔')} ${msg}`);
const warn    = msg => console.log(`  ${c.yellow('⚠')} ${msg}`);
const verbose = msg => { if (VERBOSE) console.log(`  ${c.dim('[verbose] ' + msg)}`); };
const die     = msg => { console.error(`\n  ${c.red('✗')} ${c.bold(msg)}\n`); process.exit(1); };

// ─────────────────────────────────────────────────────────────────────────────
// Native addon catalogue
//
// Each entry defines:
//   pkg         — npm package name (used for require.resolve)
//   optional    — if true, skip gracefully when not installed
//   platforms   — which SEA target directories receive this addon
//   files       — list of { resolveFrom, destName } pairs:
//     resolveFrom — subpath passed to require.resolve() from the package root
//     destName    — filename to use in the output directory
//
// How to add a new native module:
//   1. Add an entry below.
//   2. Run `node tools/scripts/copy-native-addons.js --dry-run` to verify paths.
//   3. Test with `./dist/bin/<platform>/mcp-verify --version`.
// ─────────────────────────────────────────────────────────────────────────────

const NATIVE_ADDONS = [
  {
    pkg:      '@napi-rs/keyring',
    optional: true, // Graceful degradation: credentials won't be persisted
    platforms: ['linux', 'macos', 'windows'],
    files: [
      // linux-x64 (glibc) — standard Ubuntu/Debian/CentOS
      { resolveFrom: '@napi-rs/keyring/keyring.linux-x64-gnu.node',   destName: 'keyring.linux-x64-gnu.node',   targetPlatform: 'linux'   },
      // linux-x64 (musl) — Alpine Linux / Docker slim images
      { resolveFrom: '@napi-rs/keyring/keyring.linux-x64-musl.node',  destName: 'keyring.linux-x64-musl.node',  targetPlatform: 'linux'   },
      // macOS x64 (Intel)
      { resolveFrom: '@napi-rs/keyring/keyring.darwin-x64.node',      destName: 'keyring.darwin-x64.node',      targetPlatform: 'macos'   },
      // macOS arm64 (Apple Silicon) — cross-compiled or native M1/M2 CI
      { resolveFrom: '@napi-rs/keyring/keyring.darwin-arm64.node',    destName: 'keyring.darwin-arm64.node',    targetPlatform: 'macos'   },
      // Windows x64 (MSVC)
      { resolveFrom: '@napi-rs/keyring/keyring.win32-x64-msvc.node',  destName: 'keyring.win32-x64-msvc.node',  targetPlatform: 'windows' },
    ],
  },
  {
    pkg:      'fsevents',
    optional: true, // macOS only — not available on Linux/Windows
    platforms: ['macos'],
    files: [
      { resolveFrom: 'fsevents/fsevents.node', destName: 'fsevents.node', targetPlatform: 'macos' },
    ],
  },
  // ── Add future native modules here ────────────────────────────────────────
  // Example:
  // {
  //   pkg:      'better-sqlite3',
  //   optional: false,
  //   platforms: ['linux', 'macos', 'windows'],
  //   files: [
  //     { resolveFrom: 'better-sqlite3/build/Release/better_sqlite3.node',
  //       destName: 'better_sqlite3.node', targetPlatform: 'linux' },
  //     ...
  //   ],
  // },
];

// ─────────────────────────────────────────────────────────────────────────────
// Resolve a native addon file path via require.resolve()
// Returns null if the file cannot be found (package not installed).
// ─────────────────────────────────────────────────────────────────────────────

function resolveAddon(resolveFrom) {
  try {
    return require.resolve(resolveFrom, { paths: [ROOT] });
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Copy one addon file into a target platform directory
// ─────────────────────────────────────────────────────────────────────────────

function copyAddon({ srcPath, destDir, destName, pkg, optional }) {
  const destPath = path.join(destDir, destName);
  const relSrc   = path.relative(ROOT, srcPath);
  const relDest  = path.relative(ROOT, destPath);

  if (DRY_RUN) {
    log(`${c.dim('[dry-run]')} ${relSrc} → ${relDest}`);
    return true;
  }

  try {
    fs.copyFileSync(srcPath, destPath);
    success(`${c.bold(pkg)} → ${relDest}  ${c.dim('(' + (fs.statSync(destPath).size / 1024).toFixed(0) + ' KB)')}`);
    return true;
  } catch (err) {
    if (optional) {
      warn(`Skipped ${destName}: ${err.message}`);
      return false;
    }
    die(`Failed to copy ${destName}: ${err.message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Write a loader shim alongside the executable.
//
// At runtime, require('@napi-rs/keyring') inside the SEA bundle will fail
// because the package isn't on NODE_PATH. The native-loader.ts helper
// (libs/core/src/native-loader.ts) searches for the .node file next to
// process.execPath — this shim ensures the path is correct even when
// multiple .node variants exist (e.g. gnu vs musl on Linux).
//
// The shim is a tiny JSON manifest read by native-loader.ts so it knows
// which specific .node filename to load for the current architecture.
// ─────────────────────────────────────────────────────────────────────────────

function writeAddonManifest(targetDir, copiedFiles) {
  const manifest = {
    generatedAt:  new Date().toISOString(),
    generatedBy:  'tools/scripts/copy-native-addons.js',
    // Map package name → array of .node filenames available in this dir
    addons: copiedFiles.reduce((acc, { pkg, destName }) => {
      acc[pkg] = acc[pkg] || [];
      acc[pkg].push(destName);
      return acc;
    }, {}),
  };

  const manifestPath = path.join(targetDir, 'native-addons.json');
  if (!DRY_RUN) {
    // Atomic write
    const tmp = manifestPath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(manifest, null, 2) + '\n');
    fs.renameSync(tmp, manifestPath);
    verbose(`Manifest written: ${path.relative(ROOT, manifestPath)}`);
  } else {
    log(`${c.dim('[dry-run]')} would write manifest: ${path.relative(ROOT, manifestPath)}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

function main() {
  console.log(`\n${c.bold('  📦 mcp-verify — Copy Native Addons')}`);
  if (DRY_RUN) console.log(c.yellow('  Running in dry-run mode — no files will be written.\n'));

  // Determine which platform dirs exist in dist/bin/
  if (!fs.existsSync(BIN_OUT)) {
    die(`dist/bin/ not found. Run 'npm run compile' first.`);
  }

  const availablePlatforms = fs.readdirSync(BIN_OUT)
    .filter(d => fs.statSync(path.join(BIN_OUT, d)).isDirectory())
    .filter(d => TARGET ? d === TARGET : true);

  if (availablePlatforms.length === 0) {
    die(TARGET
      ? `No '${TARGET}' directory found in dist/bin/. Was it compiled?`
      : `No platform directories found in dist/bin/. Run 'npm run compile' first.`
    );
  }

  log(`Platform directories found: ${availablePlatforms.join(', ')}`);

  let totalCopied = 0;
  let totalSkipped = 0;

  for (const platform of availablePlatforms) {
    const targetDir = path.join(BIN_OUT, platform);
    console.log(`\n  ${c.bold('── ' + platform + ' ──')}`);

    const copiedForPlatform = [];

    for (const addon of NATIVE_ADDONS) {
      // Skip addons not targeting this platform
      if (!addon.platforms.includes(platform)) {
        verbose(`Skipping ${addon.pkg} for ${platform} (not in platforms list)`);
        continue;
      }

      // Find files for this specific platform
      const platformFiles = addon.files.filter(f => f.targetPlatform === platform);

      for (const addonFile of platformFiles) {
        const srcPath = resolveAddon(addonFile.resolveFrom);

        if (!srcPath) {
          if (addon.optional) {
            warn(`${addon.pkg}/${addonFile.destName} not installed — skipping (optional)`);
            totalSkipped++;
          } else {
            die(
              `Required native addon not found: ${addonFile.resolveFrom}\n` +
              `    Run: npm install`
            );
          }
          continue;
        }

        verbose(`Resolved ${addonFile.resolveFrom} → ${srcPath}`);

        const copied = copyAddon({
          srcPath,
          destDir:  targetDir,
          destName: addonFile.destName,
          pkg:      addon.pkg,
          optional: addon.optional,
        });

        if (copied) {
          copiedForPlatform.push({ pkg: addon.pkg, destName: addonFile.destName });
          totalCopied++;
        }
      }
    }

    // Write per-platform manifest for native-loader.ts
    if (copiedForPlatform.length > 0) {
      writeAddonManifest(targetDir, copiedForPlatform);
    } else {
      verbose(`No addons copied for ${platform}, skipping manifest`);
    }
  }

  // Summary
  console.log(`\n  ${c.bold('── Summary ──')}`);
  success(`${totalCopied} addon file(s) copied`);
  if (totalSkipped > 0) warn(`${totalSkipped} optional addon(s) skipped (not installed)`);
  if (DRY_RUN) warn('Dry-run complete — no files were written.');
  console.log();
}

main();
