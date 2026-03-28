/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Playground Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from 'readline';
import { runPlaygroundAction } from '../../play';
import { ShellParser } from '../parser';
import type { ShellSession } from '../session';
import { resolveTarget } from './shared';

export async function handlePlay(
  args: string[],
  session: ShellSession,
  rl: readline.Interface
): Promise<void> {
  const target = await resolveTarget(args, session, rl, 'play "node server.js"');
  if (!target) return;

  session.setTarget(target);
  const flags = ShellParser.extractFlags(args);

  const options: Record<string, unknown> = {
    port: '8080',
    lang: session.state.lang,
    ...flags,
  };

  console.log('');
  await runPlaygroundAction(target, options);
  console.log('');
}
