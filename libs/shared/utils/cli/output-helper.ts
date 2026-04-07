/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Output Helper for CLI Commands
 *
 * Centralizes console output handling to support --quiet mode.
 * All informational output should go through this helper.
 */

import chalk from "chalk";
import ora, { Ora } from "ora";

export interface CliLogger {
  /** Informational messages (silenced in quiet mode) */
  info(msg: string): void;
  /** Success messages (silenced in quiet mode) */
  success(msg: string): void;
  /** Warning messages (silenced in quiet mode) */
  warn(msg: string): void;
  /** Error messages (always shown) */
  error(msg: string): void;
  /** Debug messages (only in DEBUG env, silenced in quiet mode) */
  debug(msg: string): void;
  /** Raw console.log replacement (silenced in quiet mode) */
  log(msg: string): void;
}

export interface SpinnerFactory {
  /** Creates a spinner that respects quiet mode */
  create(text: string): Ora;
}

/**
 * Creates a logger that respects quiet mode
 */
export function createLogger(quiet: boolean): CliLogger {
  return {
    info: (msg) => {
      if (!quiet) console.log(msg);
    },
    success: (msg) => {
      if (!quiet) console.log(chalk.green(msg));
    },
    warn: (msg) => {
      if (!quiet) console.log(chalk.yellow(msg));
    },
    error: (msg) => console.error(chalk.red(msg)),
    debug: (msg) => {
      if (process.env.DEBUG && !quiet) console.log(chalk.gray(msg));
    },
    log: (msg) => {
      if (!quiet) console.log(msg);
    },
  };
}

/**
 * Creates a spinner factory that respects quiet mode
 */
export function createSpinnerFactory(quiet: boolean): SpinnerFactory {
  const noopSpinner = {
    start: () => noopSpinner,
    stop: () => noopSpinner,
    succeed: () => noopSpinner,
    fail: () => noopSpinner,
    warn: () => noopSpinner,
    info: () => noopSpinner,
    text: "",
    isSpinning: false,
  } as unknown as Ora;

  return {
    create: (text: string) => (quiet ? noopSpinner : ora(text)),
  };
}

/**
 * Convenience function to create both logger and spinner factory
 */
export function createOutputHandlers(quiet: boolean): {
  log: CliLogger;
  spinners: SpinnerFactory;
} {
  return {
    log: createLogger(quiet),
    spinners: createSpinnerFactory(quiet),
  };
}
