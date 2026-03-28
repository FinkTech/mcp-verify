/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Logging Helper
 *
 * Utility to configure logging levels across the application
 */

import { Logger as AppLogger, LogLevel } from '@mcp-verify/shared';
import { Logger as InfrastructureLogger } from '@mcp-verify/core';

const logger = AppLogger.getInstance();

/**
 * Configure logging based on verbose flag
 * @param verbose Enable verbose/debug logging
 */
export function configureLogging(verbose: boolean): void {
  if (verbose) {
    logger.setLevel(LogLevel.DEBUG);
    InfrastructureLogger.getInstance().configure({
      enableConsole: true,
      prettyPrint: false
    });
  } else {
    logger.setLevel(LogLevel.INFO);
    InfrastructureLogger.getInstance().configure({
      enableConsole: false
    });
  }
}
