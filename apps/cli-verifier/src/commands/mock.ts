/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Mock Server Command
 *
 * Start a dummy MCP server for testing purposes
 */

import chalk from 'chalk';
import { MockServer } from '@mcp-verify/core/use-cases/mock/mock-server';
import { t } from '@mcp-verify/shared';
import { registerCleanup } from '../utils/cleanup-handlers';

export async function runMockAction(options: Record<string, unknown>) {
  const port = parseInt(String(options.port || '3000'));
  const mockServer = new MockServer(port);
  await mockServer.start();

  // Register cleanup handler
  registerCleanup(async () => {
    await mockServer.stop();
  });

  console.log(chalk.yellow(t('press_ctrl_c')));

  // Handle auto-stop timeout if provided
  const timeoutMs = options.timeout ? parseInt(String(options.timeout)) : 0;
  if (timeoutMs > 0) {
    console.log(chalk.gray(t('proxy_auto_stopping', { ms: timeoutMs })));
    return new Promise<void>((resolve) => {
      setTimeout(async () => {
        await mockServer.stop();
        console.log(chalk.yellow(`\n✅ ${t('goodbye')}`));
        process.exit(0);
      }, timeoutMs);
    });
  }

  // Keep alive loop
  return new Promise<void>(() => { });
}
