/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Cleanup Handlers
 *
 * Utility to setup graceful shutdown handlers for long-running processes
 */

import chalk from "chalk";
import { t } from "@mcp-verify/shared";

type CleanupCallback = () => Promise<void> | void;

const cleanupCallbacks: CleanupCallback[] = [];
let handlersRegistered = false;

/**
 * Register a cleanup callback to be called on process termination
 * @param callback Function to execute during cleanup
 */
export function registerCleanup(callback: CleanupCallback): void {
  cleanupCallbacks.push(callback);

  // Register signal handlers only once
  if (!handlersRegistered) {
    handlersRegistered = true;

    const shutdown = async (signal: string) => {
      console.log(chalk.yellow(`\n\n${t("received_signal")}: ${signal}`));
      console.log(chalk.gray(t("cleaning_up")));

      // Execute all cleanup callbacks
      for (const cleanup of cleanupCallbacks) {
        try {
          await cleanup();
        } catch (error) {
          console.error(chalk.red(t("cleanup_error")), error);
        }
      }

      console.log(chalk.green(t("cleanup_complete")));
      process.exit(0);
    };

    process.on("SIGINT", () => shutdown("SIGINT"));
    process.on("SIGTERM", () => shutdown("SIGTERM"));
  }
}

/**
 * Clear all registered cleanup callbacks (useful for testing)
 */
export function clearCleanupCallbacks(): void {
  cleanupCallbacks.length = 0;
}
