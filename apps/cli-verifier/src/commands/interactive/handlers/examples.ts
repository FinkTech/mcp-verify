/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Examples Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import { runExamplesAction } from '../../examples';

export async function handleExamples(): Promise<void> {
  console.log('');
  await runExamplesAction();
  console.log('');
}
