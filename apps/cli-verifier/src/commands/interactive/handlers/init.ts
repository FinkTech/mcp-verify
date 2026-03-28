/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Init Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import { runInitAction } from '../../init';

export async function handleInit(args: string[]): Promise<void> {
  // Init action doesn't take parameters - it's interactive
  console.log('');
  await runInitAction();
  console.log('');
}
