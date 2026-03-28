/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Disclaimers Command
 *
 * Manage disclaimer preferences (reset, status)
 */

import chalk from 'chalk';
import { DisclaimerManager, type DisclaimerType } from '../utils/disclaimer-manager';

interface DisclaimersOptions {
  reset?: boolean;
  type?: string;
}

export async function runDisclaimersAction(options: DisclaimersOptions) {
  const manager = DisclaimerManager.getInstance();

  if (options.reset) {
    const type = options.type as DisclaimerType | undefined;
    manager.reset(type);
    return;
  }

  // Default: show status
  manager.status();
}
