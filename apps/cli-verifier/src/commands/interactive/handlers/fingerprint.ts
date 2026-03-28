/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Fingerprint Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from 'readline';
import chalk from 'chalk';
import { McpFuzzTarget } from '../../fuzz';
import { Fingerprinter } from '@mcp-verify/fuzzer';
import type { ShellSession } from '../session';
import { resolveTarget } from './shared';

export async function handleFingerprint(
  args: string[],
  session: ShellSession,
  rl: readline.Interface
): Promise<void> {
  const target = await resolveTarget(args, session, rl, 'fingerprint "node server.js"');
  if (!target) return;

  session.setTarget(target);
  console.log(chalk.gray(`\n  🕵️  Fingerprinting ${target}...\n`));

  const fuzzTarget = new McpFuzzTarget(target, 'http', { timeout: 5000 });
  const fingerprinter = new Fingerprinter({ verbose: false });

  try {
    await fuzzTarget.connect();

    // Quick fingerprint (3 probes)
    const result = await fingerprinter.quickFingerprint(fuzzTarget, 'echo');

    console.log(chalk.bold('  Results:'));
    console.log(`  Language:  ${result.language === 'unknown' ? chalk.gray('Unknown') : chalk.green(result.language)}`);
    console.log(`  Framework: ${result.framework === 'unknown' ? chalk.gray('Unknown') : chalk.green(result.framework)}`);
    console.log(`  Database:  ${result.database === 'none' ? chalk.gray('None/Unknown') : chalk.yellow(result.database)}`);

    if (result.evidence.length > 0) {
      console.log(chalk.dim('\n  Evidence:'));
      result.evidence.forEach(e => console.log(`    - ${e.pattern}`));
    }

  } catch (error) {
    console.log(chalk.red(`  ✗ Fingerprint failed: ${error instanceof Error ? error.message : String(error)}`));
  } finally {
    await fuzzTarget.close();
  }
  console.log('');
}
