#!/usr/bin/env node
/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify Server - Entry Point
 *
 * This is the first MCP server that exposes security validation capabilities
 * that AI agents can call to validate other MCP servers.
 *
 * Usage:
 *   node dist/index.js
 *
 * Or in Claude Desktop config:
 *   {
 *     "mcpServers": {
 *       "mcp-verify": {
 *         "command": "node",
 *         "args": ["/path/to/mcp-verify/apps/mcp-server/dist/index.js"]
 *       }
 *     }
 *   }
 */

import { startServer } from './server';
import { createScopedLogger } from '@mcp-verify/core';

const logger = createScopedLogger('Main');

/**
 * Main entry point
 */
async function main(): Promise<void> {
  try {
    logger.info('Initializing mcp-verify server');

    await startServer();

    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      logger.info('Received SIGINT, shutting down gracefully');
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      logger.info('Received SIGTERM, shutting down gracefully');
      process.exit(0);
    });
  } catch (error) {
    logger.error('Fatal error starting server', error as Error);
    process.exit(1);
  }
}

// Start the server
main().catch((error) => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
