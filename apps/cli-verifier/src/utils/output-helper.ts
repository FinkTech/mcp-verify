/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Output Helper
 *
 * Utility to separate data output (stdout) from logging (stderr)
 * This ensures CI/CD pipelines can parse output cleanly
 */

/**
 * Write data output to stdout
 * Use this for machine-readable output (JSON, SARIF, text reports)
 *
 * @param data - The data to output (string or object)
 */
export function printOutput(data: string | object): void {
  if (typeof data === "object") {
    // Pretty-print JSON to stdout for readability
    process.stdout.write(JSON.stringify(data, null, 2) + "\n");
  } else {
    process.stdout.write(data + "\n");
  }
}

/**
 * Write raw data to stdout without newline
 * Use for streaming output or when you need precise control
 *
 * @param data - The data to output
 */
export function writeOutput(data: string): void {
  process.stdout.write(data);
}

/**
 * Check if output should be silent (suppressed)
 * Useful for --quiet or --silent flags
 *
 * @param options - CLI options object
 * @returns true if output should be suppressed
 */
export function isSilentMode(options: Record<string, unknown>): boolean {
  return Boolean(options?.silent) || Boolean(options?.quiet) || false;
}
