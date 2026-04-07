/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Environment Variable Parser
 *
 * Utilities for parsing and handling environment variables
 */

/**
 * Parse environment variable pairs from command line args
 * Format: KEY=VALUE
 * @param envPairs Array of "KEY=VALUE" strings
 * @returns Object with parsed environment variables
 */
export function parseEnvVars(envPairs: string[]): Record<string, string> {
  const envVars: Record<string, string> = {};

  envPairs.forEach((pair: string) => {
    const [key, ...rest] = pair.split("=");
    const value = rest.join("="); // Re-join in case value contains '='
    if (key) {
      envVars[key] = value || "";
    }
  });

  return envVars;
}

/**
 * Validate environment variable format
 * @param pair String in "KEY=VALUE" format
 * @returns true if valid format
 */
export function isValidEnvPair(pair: string): boolean {
  return pair.includes("=") && pair.split("=")[0].trim().length > 0;
}

/**
 * Parse and validate environment variables
 * @param envPairs Array of "KEY=VALUE" strings
 * @returns Object with parsed and validated environment variables
 * @throws Error if invalid format found
 */
export function parseAndValidateEnvVars(
  envPairs: string[],
): Record<string, string> {
  const invalidPairs = envPairs.filter((pair) => !isValidEnvPair(pair));

  if (invalidPairs.length > 0) {
    throw new Error(
      `Invalid environment variable format: ${invalidPairs.join(", ")}. Expected format: KEY=VALUE`,
    );
  }

  return parseEnvVars(envPairs);
}
