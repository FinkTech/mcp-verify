/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Doctor Command — "Doctor Ultra-Visible v1.0.0"
 *
 * Professional diagnostic assistant for mcp-verify.
 * Covers four inspection domains:
 *   1. Binary Integrity   – SHA-256 verification of CLI & Server binaries
 *   2. Environment        – Runtime, toolchain and filesystem checks
 *   3. MCP Server         – Protocol handshake + capability inventory
 *   4. Environment Audit  – Sensitive variable name detection (no value exposure)
 *
 * Integrity Management:
 *   --show-history      Display integrity history (last 20 builds)
 *   --fix-integrity     Regenerate integrity manifest without full rebuild
 *   --clean-history N   Keep only last N builds in history (default: 20)
 *
 * Report Flags:
 *   --watch             Auto-refresh diagnostics every 5 seconds
 *   --verbose           Print internal sub-steps integrated within each section
 *   --html              Generate HTML report
 *   --md                Generate Markdown report
 *   --json              Generate JSON report
 */

import chalk from 'chalk';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import net from 'node:net';

import { MCPValidator } from '@mcp-verify/core';
import { DiagnosticRunner } from '@mcp-verify/core/infrastructure/diagnostics/diagnostic-runner';
import {
  NodeRuntimeCheck,
  PythonRuntimeCheck,
  GitInstallationCheck,
  DenoRuntimeCheck,
} from '@mcp-verify/core/infrastructure/diagnostics/checks/environment-checks';
import { t, getCurrentLanguage, ReportingService, ReportFormat } from '@mcp-verify/shared';
import { createTransport, detectTransportType } from '../utils/transport-factory';
import { registerCleanup } from '../utils/cleanup-handlers';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type CheckStatus = 'pass' | 'fail' | 'warn' | 'skip';

interface CheckResult {
  name: string;
  status: CheckStatus;
  value?: string;
  message?: string;
}

interface SectionResult {
  title: string;
  icon: string;
  checks: CheckResult[];
  verboseLogs: string[];
}

interface IntegrityManifest {
  hash: string;
  version: string;
  timestamp: string;
}

interface DoctorOptions {
  watch?: boolean;
  verbose?: boolean;
  html?: boolean;
  md?: boolean;
  json?: boolean;
  jsonStdout?: boolean;
  output?: string;
  transport?: string;
  showHistory?: boolean;
  fixIntegrity?: boolean;
  cleanHistory?: number;
  opts?: () => { verbose?: boolean };
}

// ---------------------------------------------------------------------------
// Visual helpers
// ---------------------------------------------------------------------------

const SEP = chalk.white.dim('─'.repeat(64));

function sectionHeader(icon: string, title: string): string {
  return (
    `\n${SEP}\n` +
    ` ${icon}  ${chalk.bgWhite(chalk.black(` ${title} `))}` +
    `\n${SEP}`
  );
}

function renderCheck(check: CheckResult): string {
  const { icon, color } = statusMeta(check.status);
  const name  = chalk.white(check.name.padEnd(28));
  const value = check.value ? chalk.cyan(check.value.padEnd(24)) : ''.padEnd(24);
  const msg   = check.message ? color(check.message) : '';
  return `  ${icon}  ${name}  ${value}  ${msg}`;
}

function statusMeta(status: CheckStatus): { icon: string; color: (s: string) => string } {
  switch (status) {
    case 'pass': return { icon: chalk.green('✔'),    color: chalk.green    };
    case 'fail': return { icon: chalk.red('✖'),      color: chalk.red      };
    case 'warn': return { icon: chalk.yellow('⚠'),   color: chalk.yellow   };
    case 'skip': return { icon: chalk.cyan.dim('○'), color: chalk.cyan.dim };
  }
}

function scorecard(checks: CheckResult[]): string {
  const pass = checks.filter(c => c.status === 'pass').length;
  const warn = checks.filter(c => c.status === 'warn').length;
  const fail = checks.filter(c => c.status === 'fail').length;
  return chalk.green(`✔ ${pass}`) + '  ' + chalk.yellow(`⚠ ${warn}`) + '  ' + chalk.red(`✖ ${fail}`);
}

function printSection(section: SectionResult, verbose: boolean): void {
  console.log(sectionHeader(section.icon, section.title));
  console.log();
  section.checks.forEach(c => console.log(renderCheck(c)));
  if (verbose && section.verboseLogs.length > 0) {
    console.log();
    section.verboseLogs.forEach(log => console.log(log));
  }
  console.log(`\n  ${scorecard(section.checks)}`);
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

async function checkBinaryIntegrity(verbose: boolean): Promise<SectionResult> {
  const checks: CheckResult[] = [];
  const logs: string[] = [];
  const vlog = (msg: string) => logs.push(`    ${chalk.cyan.dim('•')} ${chalk.white.dim(msg)}`);

  // Find project root (where .mcp-verify/ directory would be)
  const projectRoot = findProjectRoot();
  const manifestPath = path.join(projectRoot, '.mcp-verify', 'integrity-history.json');

  vlog(`Project root: ${chalk.cyan(projectRoot)}`);
  vlog(`Manifest path: ${chalk.cyan(manifestPath)}`);

  if (!fs.existsSync(manifestPath)) {
    checks.push({
      name: t('integrity_manifest'),
      status: 'warn',
      message: 'Integrity manifest not found. Run build to generate it.'
    });
    return { title: t('section_binary_integrity'), icon: '🔒', checks, verboseLogs: logs };
  }

  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const currentBuild = manifest.current;

    if (!currentBuild || !currentBuild.binaries) {
      checks.push({
        name: t('integrity_manifest'),
        status: 'fail',
        message: 'Invalid manifest format (missing binaries)'
      });
      return { title: t('section_binary_integrity'), icon: '🔒', checks, verboseLogs: logs };
    }

    checks.push({
      name: t('integrity_manifest'),
      status: 'pass',
      value: `v${currentBuild.version} (${currentBuild.gitCommit})`,
      message: t('integrity_manifest_found')
    });

    // Verify CLI binary
    if (currentBuild.binaries.cli) {
      const cliPath = path.join(projectRoot, currentBuild.binaries.cli.path);
      if (fs.existsSync(cliPath)) {
        const actualHash = `sha256-${crypto.createHash('sha256').update(fs.readFileSync(cliPath)).digest('hex')}`;
        const expectedHash = currentBuild.binaries.cli.hash;
        const match = actualHash === expectedHash;

        vlog(`CLI binary: ${chalk.cyan(currentBuild.binaries.cli.path)}`);
        vlog(`Expected: ${chalk.yellow(expectedHash.slice(0, 20))}...`);
        vlog(`Actual:   ${chalk.yellow(actualHash.slice(0, 20))}...`);

        checks.push({
          name: 'CLI Binary',
          status: match ? 'pass' : 'fail',
          value: actualHash.slice(0, 20) + '...',
          message: match ? t('integrity_hash_ok') : t('integrity_hash_mismatch')
        });
      } else {
        checks.push({
          name: 'CLI Binary',
          status: 'fail',
          message: `Not found at ${currentBuild.binaries.cli.path}`
        });
      }
    }

    // Verify Server binary
    if (currentBuild.binaries.server) {
      const serverPath = path.join(projectRoot, currentBuild.binaries.server.path);
      if (fs.existsSync(serverPath)) {
        const actualHash = `sha256-${crypto.createHash('sha256').update(fs.readFileSync(serverPath)).digest('hex')}`;
        const expectedHash = currentBuild.binaries.server.hash;
        const match = actualHash === expectedHash;

        vlog(`Server binary: ${chalk.cyan(currentBuild.binaries.server.path)}`);
        vlog(`Expected: ${chalk.yellow(expectedHash.slice(0, 20))}...`);
        vlog(`Actual:   ${chalk.yellow(actualHash.slice(0, 20))}...`);

        checks.push({
          name: 'Server Binary',
          status: match ? 'pass' : 'fail',
          value: actualHash.slice(0, 20) + '...',
          message: match ? t('integrity_hash_ok') : t('integrity_hash_mismatch')
        });
      } else {
        checks.push({
          name: 'Server Binary',
          status: 'fail',
          message: `Not found at ${currentBuild.binaries.server.path}`
        });
      }
    }

    // Show history summary
    if (manifest.history && Array.isArray(manifest.history)) {
      vlog(`History: ${chalk.green(manifest.history.length)} builds tracked`);
    }

  } catch (e) {
    checks.push({ name: t('integrity_manifest'), status: 'fail', message: String(e) });
  }
  return { title: t('section_binary_integrity'), icon: '🔒', checks, verboseLogs: logs };
}

/**
 * Find project root by looking for package.json
 */
function findProjectRoot(): string {
  let currentDir = __dirname;
  while (currentDir !== path.dirname(currentDir)) {
    if (fs.existsSync(path.join(currentDir, 'package.json'))) {
      return currentDir;
    }
    currentDir = path.dirname(currentDir);
  }
  // Fallback to current working directory
  return process.cwd();
}

/**
 * Show integrity history from manifest
 */
function showIntegrityHistory(): void {
  const projectRoot = findProjectRoot();
  const manifestPath = path.join(projectRoot, '.mcp-verify', 'integrity-history.json');

  if (!fs.existsSync(manifestPath)) {
    console.log(chalk.yellow('\n⚠ No integrity manifest found.'));
    console.log(chalk.dim('   Run build to generate integrity manifest.\n'));
    return;
  }

  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    if (!manifest.history || !Array.isArray(manifest.history) || manifest.history.length === 0) {
      console.log(chalk.yellow('\n⚠ No build history found.\n'));
      return;
    }

    console.log(chalk.bold.cyan('\n🔒 Integrity History'));
    console.log(SEP);
    console.log(chalk.dim(`Found ${chalk.white(manifest.history.length)} builds\n`));

    for (const build of manifest.history) {
      const date = new Date(build.timestamp).toLocaleString();
      const isCurrent = build.buildId === manifest.current?.buildId;

      console.log(
        `${isCurrent ? chalk.green('●') : chalk.dim('○')} ${chalk.white(build.version)} ${chalk.dim(`(${build.gitCommit})`)} - ${chalk.cyan(date)}`
      );
      console.log(chalk.dim(`   Build ID: ${build.buildId}`));

      if (build.binaries?.cli) {
        console.log(chalk.dim(`   CLI:    ${build.binaries.cli.hash.slice(0, 20)}... (${formatBytes(build.binaries.cli.size)})`));
      }
      if (build.binaries?.server) {
        console.log(chalk.dim(`   Server: ${build.binaries.server.hash.slice(0, 20)}... (${formatBytes(build.binaries.server.size)})`));
      }
      console.log('');
    }

    console.log(SEP + '\n');
  } catch (e) {
    console.log(chalk.red(`\n✖ Failed to read history: ${e}\n`));
  }
}

/**
 * Fix integrity by regenerating hashes without full rebuild
 */
function fixIntegrity(): void {
  const projectRoot = findProjectRoot();
  const manifestPath = path.join(projectRoot, '.mcp-verify', 'integrity-history.json');

  console.log(chalk.bold.cyan('\n🔧 Fixing Integrity'));
  console.log(SEP);

  const cliPath = path.join(projectRoot, 'dist', 'mcp-verify.js');
  const serverPath = path.join(projectRoot, 'dist', 'mcp-server.js');

  if (!fs.existsSync(cliPath) && !fs.existsSync(serverPath)) {
    console.log(chalk.red('✖ No binaries found in dist/'));
    console.log(chalk.dim('   Run build first.\n'));
    return;
  }

  try {
    let currentManifest: unknown = null;
    if (fs.existsSync(manifestPath)) {
      currentManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }

    const timestamp = new Date().toISOString();
    const buildId = `build-${Date.now()}`;

    // Read version from package.json
    const pkgPath = path.join(projectRoot, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const version = pkg.version;

    // Get git commit
    const { execSync } = require('child_process');
    let gitCommit = 'unknown';
    try {
      gitCommit = execSync('git rev-parse --short HEAD', {
        encoding: 'utf8',
        cwd: projectRoot,
        stdio: ['ignore', 'pipe', 'ignore']
      }).trim();
    } catch {
      // Git not available
    }

    const binaries: { cli?: unknown; server?: unknown } = {};

    if (fs.existsSync(cliPath)) {
      const hash = `sha256-${crypto.createHash('sha256').update(fs.readFileSync(cliPath)).digest('hex')}`;
      const stats = fs.statSync(cliPath);
      binaries.cli = {
        hash,
        path: 'dist/mcp-verify.js',
        size: stats.size
      };
      console.log(chalk.green('✓ CLI binary hashed'));
    }

    if (fs.existsSync(serverPath)) {
      const hash = `sha256-${crypto.createHash('sha256').update(fs.readFileSync(serverPath)).digest('hex')}`;
      const stats = fs.statSync(serverPath);
      binaries.server = {
        hash,
        path: 'dist/mcp-server.js',
        size: stats.size
      };
      console.log(chalk.green('✓ Server binary hashed'));
    }

    const newBuild = {
      buildId,
      version,
      timestamp,
      gitCommit,
      binaries
    };

    // Preserve existing history
    let history: unknown[] = [];
    if (currentManifest && typeof currentManifest === 'object' && 'history' in currentManifest && Array.isArray(currentManifest.history)) {
      history = currentManifest.history;
    }
    history.unshift(newBuild);

    // Trim to 20 entries
    if (history.length > 20) {
      history = history.slice(0, 20);
    }

    const newManifest = {
      current: newBuild,
      history
    };

    // Ensure directory exists
    const workspaceDir = path.dirname(manifestPath);
    if (!fs.existsSync(workspaceDir)) {
      fs.mkdirSync(workspaceDir, { recursive: true });
    }

    // Write atomically
    const tmpPath = manifestPath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(newManifest, null, 2) + '\n', 'utf8');
    fs.renameSync(tmpPath, manifestPath);

    console.log(chalk.green('✓ Integrity manifest updated'));
    console.log(chalk.dim(`   Path: ${manifestPath}`));
    console.log(chalk.dim(`   Build ID: ${buildId}\n`));
  } catch (e) {
    console.log(chalk.red(`\n✖ Failed to fix integrity: ${e}\n`));
  }
}

/**
 * Clean old history entries, keeping only last N
 */
function cleanHistory(keepLast: number): void {
  const projectRoot = findProjectRoot();
  const manifestPath = path.join(projectRoot, '.mcp-verify', 'integrity-history.json');

  console.log(chalk.bold.cyan('\n🧹 Cleaning History'));
  console.log(SEP);

  if (!fs.existsSync(manifestPath)) {
    console.log(chalk.yellow('⚠ No integrity manifest found.\n'));
    return;
  }

  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    if (!manifest.history || !Array.isArray(manifest.history)) {
      console.log(chalk.yellow('⚠ No history to clean.\n'));
      return;
    }

    const originalCount = manifest.history.length;
    manifest.history = manifest.history.slice(0, keepLast);
    const removedCount = originalCount - manifest.history.length;

    // Write atomically
    const tmpPath = manifestPath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    fs.renameSync(tmpPath, manifestPath);

    console.log(chalk.green(`✓ Removed ${removedCount} old entries`));
    console.log(chalk.dim(`   Kept last ${manifest.history.length} builds\n`));
  } catch (e) {
    console.log(chalk.red(`\n✖ Failed to clean history: ${e}\n`));
  }
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function checkEnvironment(verbose: boolean): Promise<SectionResult> {
  const logs: string[] = [];
  const vlog = (msg: string) => logs.push(`    ${chalk.cyan.dim('•')} ${chalk.white.dim(msg)}`);
  const runner = new DiagnosticRunner();
  runner.register(new NodeRuntimeCheck());
  runner.register(new PythonRuntimeCheck());
  runner.register(new GitInstallationCheck());
  runner.register(new DenoRuntimeCheck());
  const results = await runner.runAll();
  const checks: CheckResult[] = results.map(res => {
    vlog(`${res.name}: ${res.status}`);
    return { name: res.name, status: res.status === 'pass' ? 'pass' : res.status === 'fail' ? 'fail' : 'warn', value: res.details ?? undefined, message: res.message };
  });
  return { title: t('section_environment'), icon: '⚙', checks, verboseLogs: logs };
}

async function checkMcpServer(target: string, transportOverride: string | undefined, verbose: boolean): Promise<SectionResult> {
  const checks: CheckResult[] = [];
  const logs: string[] = [];
  const vlog = (msg: string) => logs.push(`    ${chalk.cyan.dim('•')} ${chalk.white.dim(msg)}`);

  try {
    const transportType = transportOverride ?? detectTransportType(target);
    const transport = createTransport(target, { transportType: transportType as 'stdio' | 'http' | 'sse', lang: getCurrentLanguage() });
    const validator = new MCPValidator(transport, undefined, {});
    const result = await validator.testHandshake();

    checks.push({ name: t('mcp_protocol'), status: result.success ? 'pass' : 'fail', value: result.protocolVersion || 'MCP', message: result.success ? t('handshake_successful') : t('handshake_failed') });

    // Discover capabilities separately
    const cap = await validator.discoverCapabilities();
    const tC = cap.tools?.length ?? 0;
    const rC = cap.resources?.length ?? 0;
    const pC = cap.prompts?.length ?? 0;
    
    checks.push({ name: t('mcp_tools'), status: tC > 0 ? 'pass' : 'warn', value: `${tC} ${t('found')}`, message: t('mcp_tools_detected', { count: String(tC) }) });
    checks.push({ name: t('mcp_resources'), status: rC > 0 ? 'pass' : 'warn', value: `${rC} ${t('found')}`, message: t('mcp_resources_detected', { count: String(rC) }) });
    checks.push({ name: t('mcp_prompts'), status: pC > 0 ? 'pass' : 'skip', value: `${pC} ${t('found')}`, message: pC > 0 ? t('mcp_prompts_detected', { count: String(pC) }) : t('na_label') });
    
    await validator.cleanup();
  } catch (e) {
    checks.push({ name: t('mcp_protocol'), status: 'fail', message: String(e) });
  }
  return { title: t('section_mcp_server'), icon: '🔌', checks, verboseLogs: logs };
}

function checkEnvironmentAudit(verbose: boolean): SectionResult {
  const checks: CheckResult[] = [];
  const logs: string[] = [];
  const vlog = (msg: string) => logs.push(`    ${chalk.cyan.dim('•')} ${chalk.white.dim(msg)}`);
  const envKeys = Object.keys(process.env);
  const patterns = ['PASSWORD', 'SECRET', 'API_KEY', 'TOKEN', 'AUTH', 'ADMIN'];
  const suspicious = envKeys.filter(k => patterns.some(p => k.toUpperCase().includes(p)));
  
  checks.push({ name: t('audit_total_env_vars'), status: 'pass', value: `${envKeys.length} ${t('found')}`, message: t('audit_env_scanned') });
  if (suspicious.length > 0) {
    suspicious.forEach(k => checks.push({ name: t('audit_sensitive_names'), status: 'warn', value: k, message: t('audit_sensitive_var_warning') }));
  } else {
    checks.push({ name: t('audit_sensitive_names'), status: 'pass', message: t('audit_no_sensitive_vars') });
  }
  return { title: t('section_env_audit'), icon: '🛡', checks, verboseLogs: logs };
}

// ---------------------------------------------------------------------------
// Summary & Execution
// ---------------------------------------------------------------------------

function printSummary(sections: SectionResult[]): void {
  const allChecks = sections.flatMap(s => s.checks);
  const fails = allChecks.filter(c => c.status === 'fail').length;
  const warns = allChecks.filter(c => c.status === 'warn').length;

  console.log(`\n${SEP}`);
  if (fails > 0) {
    console.log(`  ${chalk.bgRed(chalk.white(` ✖ ${t('summary_issues_found', { count: String(fails + warns) })} `))}  ${chalk.red(`${fails} ${t('summary_critical')}`)}, ${chalk.yellow(`${warns} ${t('summary_warnings')}`)}`);
  } else if (warns > 0) {
    console.log(`  ${chalk.bgYellow(chalk.black(` ⚠ ${warns} ${t('summary_warnings')} `))}  ${chalk.white.dim(t('summary_no_critical'))}`);
  } else {
    console.log(`  ${chalk.bgGreen(chalk.black(` ✔ ${t('summary_all_ok')} `))}`);
  }
  console.log(SEP + '\n');
}

async function runFullDiagnostic(target: string | undefined, transportOverride: string | undefined, options: DoctorOptions): Promise<void> {
  const verbose = !!options.verbose;
  
  if (!options.watch) {
    console.log(chalk.bold('\n' + chalk.bgWhite(chalk.black('  🩺  mcp-verify doctor  ')) + '\n'));
  }
  
  if (verbose) console.log(`  ${chalk.bgCyan(chalk.black(' VERBOSE '))}  ${chalk.white.dim(t('verbose_mode_active'))}`);
  if (target) console.log(chalk.white.dim(t('target') + ':') + '  ' + chalk.cyan(target));

  const sections: SectionResult[] = [];
  sections.push(await checkBinaryIntegrity(verbose));
  sections.push(await checkEnvironment(verbose));
  if (target) sections.push(await checkMcpServer(target, transportOverride, verbose));
  sections.push(checkEnvironmentAudit(verbose));

  sections.forEach(s => printSection(s, verbose));
  printSummary(sections);

  // Centralized Export
  if (options.md || options.html || options.json) {
    const formats: ReportFormat[] = [];
    if (options.md) formats.push('markdown');
    if (options.html) formats.push('html');
    if (options.json) formats.push('json');

    const saved = await ReportingService.saveReport(
      { kind: 'doctor', data: sections },
      {
        outputDir: options.output,
        formats,
        language: getCurrentLanguage(),
        filenamePrefix: 'doctor-diag'
      }
    );

    console.log(chalk.white.dim('  📦 ' + t('comparison_saved_at').split(':')[0] + ':'));
    if (saved.paths.markdown) console.log(chalk.green(`     • Markdown: ${chalk.cyan(saved.paths.markdown)}`));
    if (saved.paths.html) console.log(chalk.green(`     • HTML:     ${chalk.cyan(saved.paths.html)}`));
    if (saved.paths.json) console.log(chalk.green(`     • JSON:     ${chalk.cyan(saved.paths.json)}`));
  }
}

const WATCH_INTERVAL_MS = 5_000;

const DOCTOR_BANNER = `
  _____   ____   _____ _______ ____  _____  
 |  __ \\ / __ \\ / ____|__   __/ __ \\|  __ \\ 
 | |  | | |  | | |       | | | |  | | |__) |
 | |  | | |  | | |       | | | |  | |  _  / 
 | |__| | |__| | |____   | | | |__| | | \\ \\ 
 |_____/ \\____/ \\_____|  |_|  \\____/|_|  \\_\\
`;

async function runWatchMode(target: string | undefined, transportOverride: string | undefined, options: DoctorOptions): Promise<void> {
  const REFRESH_RATE = 5; // seconds
  let secondsLeft = REFRESH_RATE;

  const printHeader = () => {
    console.log(chalk.cyan(DOCTOR_BANNER));
    console.log(chalk.bold('  🩺  mcp-verify doctor dashboard'));
    console.log(chalk.white.dim('  ' + '─'.repeat(64)));
    if (target) {
      console.log(chalk.white.dim('  ' + t('target') + ': ') + chalk.cyan(target));
    }
  };

  const printTimer = () => {
    // ANSI Escape: Save cursor, Move to line 11 (approx), Clear line, Print, Restore cursor
    // Line 11 is a heuristic. A safer bet for CLI tools without blessed is clearing screen.
    // However, let's try to be smart.
    // We will clear screen, print header, print timer, print body.
    // But that flickers.
    // Let's stick to the previous logic but refined:
    // 1. Clear Screen
    // 2. Print Header
    // 3. Print Timer (placeholder)
    // 4. Print Diagnostics
    // 5. Start Interval that overwrites Line X (Timer)
    
    // Actually, simply putting the timer at the BOTTOM of the output is standard for CLIs to avoid messing with top content.
    // But the user liked it at the top.
    
    // Let's implement the "Clear & Redraw All" approach but optimized.
    // No, that's heavy.
    
    // Fix for "updating in place":
    // Use \r to overwrite the last line? No, user wants it at top.
    
    // Let's go with: Clean refresh every 5s. 
    // And for the countdown: 
    // We will save the cursor position RIGHT AFTER the header, print the timer, then print the body.
    // Then periodically move cursor back to that saved position to update timer.
  };

  const refresh = async () => {
    console.clear();
    printHeader();
    
    // Status bar line (Line ~10)
    process.stdout.write(`  ${chalk.bgCyan(chalk.black(' ◉ ' + t('watch_live') + ' '))}  ${chalk.white.dim(t('watch_next_in', { seconds: String(secondsLeft) }))}\n`);
    
    // Separator or empty line
    // console.log(''); 

    // Run diagnostics (this prints multiple lines)
    await runFullDiagnostic(target, transportOverride, { ...options, watch: false });
  };

  // Initial Run
  await refresh();

  // Timer Loop
  setInterval(async () => {
    secondsLeft--;
    if (secondsLeft <= 0) {
      secondsLeft = REFRESH_RATE;
      await refresh();
    } else {
      // Update JUST the timer line using ANSI escapes
      // Assuming header is ~10 lines.
      // \x1b[H moves to 0,0. \x1b[10B moves down 10 lines.
      // This is risky if terminal size changes.
      
      // Fallback: Just update the bottom line with a countdown?
      // "Monitor en vivo - Actualizando en X..."
      
      // Let's try the ANSI absolute positioning for the specific line we just wrote.
      // If we cleared screen, we are at 0,0.
      // Banner=7, Title=1, Sep=1, Target=1. Total=10 lines.
      // Timer is at line 11.
      const timerLine = target ? 12 : 11;
      
      process.stdout.write(`\x1b[${timerLine};0H`); // Move to absolute line
      process.stdout.write(`\x1b[2K`); // Clear line
      process.stdout.write(`  ${chalk.bgCyan(chalk.black(' ◉ ' + t('watch_live') + ' '))}  ${chalk.white.dim(t('watch_next_in', { seconds: String(secondsLeft) }))}`);
      
      // Move cursor back to bottom to not interfere? 
      // Actually, we can just leave it there or move to end.
      process.stdout.write(`\x1b[100;0H`); // Move way down to be safe
    }
  }, 1000);
}

export async function runDoctorAction(target: string | undefined, options: DoctorOptions): Promise<void> {
  let isVerbose = options.verbose === true;
  if (!isVerbose && typeof options.opts === 'function') isVerbose = options.opts().verbose === true;
  const mergedOptions: DoctorOptions = { ...options, verbose: isVerbose };

  // Handle new integrity-related options
  if (options.showHistory) {
    showIntegrityHistory();
    return;
  }

  if (options.fixIntegrity) {
    fixIntegrity();
    return;
  }

  if (options.cleanHistory !== undefined) {
    const keepLast = options.cleanHistory || 20; // Default to 20 if 0 provided
    cleanHistory(keepLast);
    return;
  }

  if (options.jsonStdout) {
    const s = [await checkBinaryIntegrity(false), await checkEnvironment(false)];
    if (target) s.push(await checkMcpServer(target, options.transport, false));
    s.push(checkEnvironmentAudit(false));
    console.log(JSON.stringify(s, null, 2));
    return;
  }

  if (options.watch) {
    await runWatchMode(target, options.transport, mergedOptions);
  } else {
    await runFullDiagnostic(target, options.transport, mergedOptions);
  }
}
