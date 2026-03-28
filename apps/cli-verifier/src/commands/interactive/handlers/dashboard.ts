/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Dashboard Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from 'readline';
import { runDashboardAction } from '../../dashboard';
import { ShellParser } from '../parser';
import type { ShellSession } from '../session';
import { resolveTarget } from './shared';

export async function handleDashboard(
  args: string[],
  session: ShellSession,
  rl: readline.Interface
): Promise<void> {
  const target = await resolveTarget(args, session, rl, 'dashboard "node server.js"');
  if (!target) return;

  session.setTarget(target);
  const flags = ShellParser.extractFlags(args);

  const options: Record<string, unknown> = {
    port: '5173',
    lang: session.state.lang,
    ...flags,
  };

  console.log('');
  await runDashboardAction(target, options);
  console.log('');
}
