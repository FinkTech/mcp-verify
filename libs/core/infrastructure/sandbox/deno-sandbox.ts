/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Deno Sandbox
 *
 * Provides secure sandboxed execution for MCP servers using Deno's
 * permission system. Includes environment validation to ensure
 * the sandbox is properly configured before use.
 *
 * @module libs/core/infrastructure/sandbox/deno-sandbox
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { t } from '@mcp-verify/shared';
import { ISandbox, SandboxOptions, SandboxEnvironmentCheck } from '../../domain/sandbox/sandbox.interface';

/** Minimum required Deno version for sandbox features */
const MIN_DENO_VERSION = { major: 1, minor: 40, patch: 0 };

/**
 * Detect runtime from command string
 */
function detectRuntime(command: string, args: string[]): string {
  const cmdLower = command.toLowerCase();

  if (cmdLower.includes('python') || cmdLower === 'py') {
    return 'python';
  }
  if (cmdLower.includes('go') && args.some(arg => arg === 'run')) {
    return 'go';
  }
  if (cmdLower === 'node' || cmdLower === 'npx') {
    return 'node';
  }
  if (cmdLower === 'deno') {
    return 'deno';
  }

  return 'unknown';
}

/**
 * Parse version string into semantic version components
 */
function parseVersion(versionStr: string): { major: number; minor: number; patch: number } | null {
  // Handle "deno 1.40.5" or "1.40.5" formats
  const match = versionStr.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    return null;
  }
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10)
  };
}

/**
 * Compare two semantic versions
 * @returns -1 if a < b, 0 if equal, 1 if a > b
 */
function compareVersions(
  a: { major: number; minor: number; patch: number },
  b: { major: number; minor: number; patch: number }
): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

export class DenoSandbox implements ISandbox {
  private options: SandboxOptions;
  private static environmentCheck: SandboxEnvironmentCheck | null = null;

  constructor(options: SandboxOptions = {}) {
    this.options = {
      allowEnv: true,
      allowRead: options.allowRead || ['.'], // Default to current dir
      allowNet: options.allowNet || [],      // Restricted by default
      ...options
    };
  }

  /**
   * Check if the sandbox environment is properly configured.
   * This is a static method that can be called before creating a sandbox instance.
   *
   * @param forceRecheck - If true, bypass the cache and recheck
   * @returns Environment check result with detailed status
   */
  static checkEnvironment(forceRecheck = false): SandboxEnvironmentCheck {
    // Return cached result if available and not forcing recheck
    if (DenoSandbox.environmentCheck && !forceRecheck) {
      return DenoSandbox.environmentCheck;
    }

    const result: SandboxEnvironmentCheck = {
      available: false,
      versionCompatible: false,
      tempWritable: false,
      issues: [],
      suggestions: []
    };

    // 1. Check if Deno binary exists
    try {
      // Use 'where' on Windows, 'which' on Unix
      const whichCmd = process.platform === 'win32' ? 'where deno' : 'which deno';
      const binaryPath = execSync(whichCmd, {
        encoding: 'utf-8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe']
      }).trim().split('\n')[0]; // Take first result on Windows (where returns multiple)

      result.binaryPath = binaryPath;
    } catch {
      result.issues.push(t('sandbox_deno_not_found') || 'Deno binary not found in PATH');
      result.suggestions.push(t('sandbox_install_deno') || 'Install Deno: curl -fsSL https://deno.land/install.sh | sh');
      result.suggestions.push(t('sandbox_alt_docker') || 'Alternative: Use --sandbox=docker if Docker is available');

      DenoSandbox.environmentCheck = result;
      return result;
    }

    // 2. Check Deno version
    try {
      const versionOutput = execSync('deno --version', {
        encoding: 'utf-8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe']
      }).trim();

      // Extract version from output like "deno 1.40.5 (release, x86_64-unknown-linux-gnu)"
      const versionLine = versionOutput.split('\n')[0];
      result.version = versionLine;

      const semver = parseVersion(versionLine);
      if (semver) {
        result.semver = semver;
        const comparison = compareVersions(semver, MIN_DENO_VERSION);

        if (comparison >= 0) {
          result.versionCompatible = true;
        } else {
          result.issues.push(
            (t('sandbox_deno_version_too_old') || 'Deno version {current} is below minimum {required}')
              .replace('{current}', `${semver.major}.${semver.minor}.${semver.patch}`)
              .replace('{required}', `${MIN_DENO_VERSION.major}.${MIN_DENO_VERSION.minor}.${MIN_DENO_VERSION.patch}`)
          );
          result.suggestions.push(t('sandbox_update_deno') || 'Update Deno: deno upgrade');
        }
      } else {
        result.issues.push(t('sandbox_version_parse_failed') || 'Could not parse Deno version');
      }
    } catch (error) {
      result.issues.push(
        (t('sandbox_version_check_failed') || 'Failed to check Deno version: {error}')
          .replace('{error}', error instanceof Error ? error.message : String(error))
      );
    }

    // 3. Check temp directory is writable
    try {
      const tempDir = os.tmpdir();
      const testFile = path.join(tempDir, `.mcp-verify-sandbox-test-${Date.now()}`);

      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
      result.tempWritable = true;
    } catch (error) {
      result.issues.push(
        (t('sandbox_temp_not_writable') || 'Temp directory is not writable: {error}')
          .replace('{error}', error instanceof Error ? error.message : String(error))
      );
      result.suggestions.push(t('sandbox_check_temp_perms') || 'Check permissions on your temp directory');
    }

    // 4. Determine overall availability
    result.available = result.binaryPath !== undefined &&
                       result.versionCompatible &&
                       result.tempWritable;

    // Cache the result
    DenoSandbox.environmentCheck = result;

    return result;
  }

  /**
   * Get a human-readable status message for the environment check
   */
  static getStatusMessage(check?: SandboxEnvironmentCheck): string {
    const result = check || DenoSandbox.checkEnvironment();

    if (result.available) {
      return (t('sandbox_ready') || '✅ Deno sandbox ready (v{version})')
        .replace('{version}', result.semver
          ? `${result.semver.major}.${result.semver.minor}.${result.semver.patch}`
          : 'unknown');
    }

    const lines: string[] = [
      t('sandbox_not_available') || '⚠️  Deno sandbox not available',
      ''
    ];

    if (result.issues.length > 0) {
      lines.push(t('sandbox_issues_header') || 'Issues:');
      for (const issue of result.issues) {
        lines.push(`  • ${issue}`);
      }
      lines.push('');
    }

    if (result.suggestions.length > 0) {
      lines.push(t('sandbox_suggestions_header') || 'Suggestions:');
      for (const suggestion of result.suggestions) {
        lines.push(`  → ${suggestion}`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Check if sandbox is available (convenience method)
   */
  static isAvailable(): boolean {
    return DenoSandbox.checkEnvironment().available;
  }

  wrap(command: string, args: string[]): [string, string[]] {
    // Validate environment before wrapping
    const envCheck = DenoSandbox.checkEnvironment();
    if (!envCheck.available) {
      throw new Error(DenoSandbox.getStatusMessage(envCheck));
    }

    // Detect runtime and validate compatibility
    const runtime = detectRuntime(command, args);

    if (runtime === 'python' || runtime === 'go') {
      const commandStr = `${command} ${args.join(' ')}`;
      throw new Error(
`${t('sandbox_warning_title') || '⚠️  Sandbox Security Warning'}

${t('sandbox_deno_only') || 'The Deno sandbox only supports JavaScript/TypeScript runtimes.'}
${(t('sandbox_unsupported_runtime') || 'Detected runtime: {runtime}').replace('{runtime}', runtime)}

${t('sandbox_options_header') || 'Options:'}

${t('sandbox_option_audit') || '1. Audit the server code manually before running'}
${t('sandbox_option_risky') || '2. Run without sandbox (at your own risk):'}
   mcp-verify validate --server "${commandStr}" --no-sandbox

   ${t('sandbox_trust_notice') || '⚠️  Only do this if you trust the server code!'}

${t('sandbox_future_version') || 'Docker sandbox support for other runtimes coming soon.'}`
      );
    }

    const denoArgs: string[] = ['run', '--no-prompt'];

    // 1. Permissions
    if (this.options.allowEnv) {
      denoArgs.push('--allow-env');
    }

    if (this.options.allowRead && this.options.allowRead.length > 0) {
      const paths = this.options.allowRead.map(p => path.resolve(p)).join(',');
      denoArgs.push(`--allow-read=${paths}`);
    }

    if (this.options.allowNet && this.options.allowNet.length > 0) {
      denoArgs.push(`--allow-net=${this.options.allowNet.join(',')}`);
    }

    // 2. Add the original command and its args
    // Deno can run .js and .ts files directly.
    // If the command is 'node', we replace it with Deno's compatibility mode
    if (command === 'node' || command === 'npx') {
      // Deno handles node scripts automatically in newer versions
      denoArgs.push(...args);
    } else {
      // For other runtimes, we try to run it
      denoArgs.push(command, ...args);
    }

    return ['deno', denoArgs];
  }
}
