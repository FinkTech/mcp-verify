/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { exec } from 'child_process';
import { promisify } from 'util';
import { t } from '@mcp-verify/shared';
import type { IDiagnosticCheck, DiagnosticResult } from '../diagnostic-check.interface';

const execAsync = promisify(exec);

export class NodeRuntimeCheck implements IDiagnosticCheck {
  readonly name = t('diag_node_name');
  readonly description = t('diag_node_desc');

  async run(): Promise<DiagnosticResult> {
    const start = Date.now();
    try {
      const { stdout } = await execAsync('node --version');
      const version = stdout.trim();
      // Simple parsing v18.x.x
      const major = parseInt(version.replace('v', '').split('.')[0]);

      if (major < 18) {
        return {
          name: this.name,
          status: 'fail',
          message: t('diag_outdated', { name: 'Node.js', version }),
          details: t('diag_node_req'),
          remediation: t('diag_install_node'),
          durationMs: Date.now() - start
        };
      }

      return {
        name: this.name,
        status: 'pass',
        message: t('diag_installed', { version }),
        durationMs: Date.now() - start
      };
    } catch (error) {
      return {
        name: this.name,
        status: 'fail',
        message: t('diag_not_found', { name: 'Node.js' }),
        remediation: t('diag_install_node'),
        durationMs: Date.now() - start
      };
    }
  }
}

export class PythonRuntimeCheck implements IDiagnosticCheck {
  readonly name = t('diag_python_name');
  readonly description = t('diag_python_desc');

  async run(): Promise<DiagnosticResult> {
    const start = Date.now();
    try {
      // Try python3 first, then python
      let cmd = 'python3 --version';
      try {
        await execAsync(cmd);
      } catch {
        cmd = 'python --version';
      }

      const { stdout } = await execAsync(cmd);
      const version = stdout.trim(); // e.g., "Python 3.10.4"

      return {
        name: this.name,
        status: 'pass',
        message: t('diag_installed', { version }),
        durationMs: Date.now() - start
      };
    } catch (error) {
      return {
        name: this.name,
        status: 'warn',
        message: t('diag_not_found', { name: 'Python' }),
        details: t('diag_python_details'),
        remediation: t('diag_install_python'),
        durationMs: Date.now() - start
      };
    }
  }
}

export class GitInstallationCheck implements IDiagnosticCheck {
  readonly name = t('diag_git_name');
  readonly description = t('diag_git_desc');

  async run(): Promise<DiagnosticResult> {
    const start = Date.now();
    try {
      const { stdout } = await execAsync('git --version');
      return {
        name: this.name,
        status: 'pass',
        message: stdout.trim(),
        durationMs: Date.now() - start
      };
    } catch (error) {
      return {
        name: this.name,
        status: 'warn',
        message: t('diag_not_found', { name: 'Git' }),
        remediation: t('diag_install_git'),
        durationMs: Date.now() - start
      };
    }
  }
}

export class DenoRuntimeCheck implements IDiagnosticCheck {
  readonly name = t('diag_deno_name');
  readonly description = t('diag_deno_desc');

  async run(): Promise<DiagnosticResult> {
    const start = Date.now();
    try {
      const { stdout } = await execAsync('deno --version');
      // Output example: "deno 1.37.0 (release, x86_64-apple-darwin)\nv8 11.8.172.13\ntypescript 5.2.2"
      const versionLine = stdout.split('\n')[0];
      return {
        name: this.name,
        status: 'pass',
        message: versionLine,
        durationMs: Date.now() - start
      };
    } catch (error) {
      return {
        name: this.name,
        status: 'warn',
        message: t('diag_not_found', { name: 'Deno' }),
        details: t('diag_deno_details'),
        remediation: t('diag_install_deno'),
        durationMs: Date.now() - start
      };
    }
  }
}
