/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Stress Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from 'readline';
import { runStressAction } from '../../stress';
import { ShellParser } from '../parser';
import type { ShellSession } from '../session';
import { resolveTarget } from './shared';

export async function handleStress(
  args: string[],
  session: ShellSession,
  rl: readline.Interface
): Promise<void> {
  const target = await resolveTarget(
    args, session, rl, 'stress "node server.js" --users 10 --duration 30'
  );
  if (!target) return;

  session.setTarget(target);
  const flags = ShellParser.extractFlags(args);

  const options: Record<string, string | true> = {
    server:   target,
    users:    '5',
    duration: '10',
    lang:     session.state.lang,
    ...flags,
  };

  console.log('');
  await runStressAction(target, options);
  console.log('');
}
