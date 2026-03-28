/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Inspect Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from 'readline';
import chalk from 'chalk';
import { runPlaygroundAction } from '../../play';
import type { ShellSession } from '../session';
import { resolveTarget } from './shared';

export async function handleInspect(
  args: string[],
  session: ShellSession,
  rl: readline.Interface
): Promise<void> {
  const target = await resolveTarget(args, session, rl, 'inspect "node server.js"');
  if (!target) return;

  session.setTarget(target);
  console.log(chalk.gray(`\n  📋 Inspecting capabilities of ${target}...\n`));

  // Reuse playground's listing capability
  await runPlaygroundAction(target, { 'list-only': true });
  console.log('');
}
