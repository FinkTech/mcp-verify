/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Shared Handler Utilities
 *
 * Extracted from interactive.ts - Section 10
 *
 * Common functions used by multiple command handlers:
 * - resolveTarget: Interactive target resolution with prompts
 * - mergeOptions: Merge session defaults with CLI flags
 * - validateTargetWithFeedback: Intelligent target validation
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';
import chalk from 'chalk';
import { spawnSync } from 'child_process';
import { t } from '@mcp-verify/shared';
import { ShellParser } from '../parser';
import type { ShellSession } from '../session';

/**
 * Merges session defaults with CLI flags.
 * Flags take precedence over session config.
 *
 * @param commandPrefix - Command prefix (e.g., 'validate', 'fuzz')
 * @param session - Shell session instance
 * @param flags - CLI flags parsed from command line
 * @returns Merged options object
 */
export function mergeOptions(
  commandPrefix: string,
  session: ShellSession,
  flags: Record<string, string | true>
): Record<string, unknown> {
  const defaults: Record<string, unknown> = {};

  // Extract defaults starting with "commandPrefix." (e.g. "validate.output")
  for (const [key, val] of Object.entries(session.state.config)) {
    if (key.startsWith(`${commandPrefix}.`)) {
      const shortKey = key.slice(commandPrefix.length + 1);
      defaults[shortKey] = val;
    }
  }

  return { ...defaults, ...flags };
}

/**
 * Resolves the active target. If missing, PROMPTS the user interactively.
 *
 * @param args - Command arguments
 * @param session - Shell session instance
 * @param rl - Readline interface for interactive prompts
 * @param example - Example usage to show if target is missing
 * @returns Resolved target or undefined if cancelled
 */
export async function resolveTarget(
  args:    string[],
  session: ShellSession,
  rl:      readline.Interface,
  example: string,
): Promise<string | undefined> {
  const positionals = ShellParser.extractPositionals(args);
  const target      = positionals[0] ?? session.state.target;

  if (target) return target;

  // Interactive Prompt Mode
  return new Promise((resolve) => {
    rl.question(chalk.yellow(`  ? ${t('interactive_target_not_set')} `), (answer) => {
      const input = answer.trim();
      if (!input) {
        console.log(chalk.red(`  ✗ ${t('interactive_operation_cancelled')}`));
        console.log(chalk.dim(`  ${t('interactive_example')}: ${example}\n`));
        resolve(undefined);
      } else {
        session.setTarget(input); // Auto-save for next time
        console.log(chalk.green(`  ✓ ${t('interactive_target_set_success')} ${chalk.white(input)}\n`));
        resolve(input);
      }
    });
  });
}

/**
 * Validates target and provides intelligent feedback about what was detected.
 *
 * @param target - Target string to validate
 * @returns Validation result with validity flag and detection message
 */
export function validateTargetWithFeedback(target: string): { valid: boolean; message: string } {
  // 1. Empty check
  if (!target || target.trim().length === 0) {
    return { valid: false, message: t('target_validation_empty') };
  }

  const trimmed = target.trim();

  // 2. HTTP/HTTPS URL detection
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    try {
      new URL(trimmed);
      const isSSE = trimmed.toLowerCase().includes('/sse') ||
                    trimmed.toLowerCase().includes('/events') ||
                    trimmed.toLowerCase().includes('/stream');
      return {
        valid: true,
        message: isSSE ? t('target_validation_detected_sse') : t('target_validation_detected_http')
      };
    } catch {
      return { valid: false, message: t('target_validation_invalid_url') };
    }
  }

  // 3. File path detection (server.js, ./server.py, /path/to/server)
  const firstToken = trimmed.split(/\s+/)[0];
  if (fs.existsSync(firstToken)) {
    const ext = path.extname(firstToken).toLowerCase();
    const runtimeMap: Record<string, string> = {
      '.js': t('target_validation_detected_nodejs'),
      '.mjs': t('target_validation_detected_nodejs_esm'),
      '.cjs': t('target_validation_detected_nodejs_cjs'),
      '.ts': t('target_validation_detected_typescript'),
      '.py': t('target_validation_detected_python'),
      '.sh': t('target_validation_detected_bash'),
      '.bat': t('target_validation_detected_batch'),
      '.cmd': t('target_validation_detected_cmd'),
      '.exe': t('target_validation_detected_executable'),
    };
    const detected = runtimeMap[ext] || t('target_validation_detected_executable');
    return { valid: true, message: detected };
  }

  // 4. npx command detection
  if (trimmed.startsWith('npx ')) {
    const packageName = trimmed.split(/\s+/)[1];
    const message = packageName
      ? `${t('target_validation_detected_npx')} (${packageName})`
      : t('target_validation_detected_npx');
    return { valid: true, message };
  }

  // 5. Known runtime command detection (node, python, deno, etc.)
  const knownRuntimes = ['node', 'python', 'python3', 'deno', 'bun', 'docker', 'uvx'];
  if (knownRuntimes.includes(firstToken)) {
    return {
      valid: true,
      message: t('target_validation_detected_runtime').replace('{runtime}', firstToken)
    };
  }

  // 6. Check if command exists in PATH (Unix: which, Windows: where)
  try {
    const checkCmd = process.platform === 'win32' ? 'where' : 'which';
    const result = spawnSync(checkCmd, [firstToken], {
      encoding: 'utf8',
      shell: false,
      timeout: 1000 // 1 second max
    });

    if (result.status === 0) {
      return {
        valid: true,
        message: t('target_validation_detected_shell').replace('{command}', firstToken)
      };
    }
  } catch {
    // Command check failed, continue to warning
  }

  // 7. Unknown command - give warning but allow it
  return {
    valid: false,
    message: t('target_validation_warning_not_found').replace('{command}', firstToken)
  };
}
