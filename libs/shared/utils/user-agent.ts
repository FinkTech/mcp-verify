/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * User-Agent utility for mcp-verify
 *
 * Provides a consistent User-Agent string for all HTTP requests
 * to help network administrators identify mcp-verify traffic.
 */

const PACKAGE_VERSION = "1.0.0";
const GITHUB_URL = "https://github.com/FinkTech/mcp-verify";

/**
 * Get the User-Agent string for HTTP requests
 * Format: mcp-verify/1.0.0 (+https://github.com/FinkTech/mcp-verify) Node.js/v18.x.x
 */
export function getUserAgent(): string {
  const nodeVersion = process.version;
  return `mcp-verify/${PACKAGE_VERSION} (+${GITHUB_URL}) Node.js/${nodeVersion}`;
}

/**
 * Get default headers including User-Agent and Audit markers
 */
export function getDefaultHeaders(
  customHeaders: Record<string, string> = {},
): Record<string, string> {
  return {
    "User-Agent": getUserAgent(),
    "X-Audit-Tool": "mcp-verify",
    "X-Audit-Version": PACKAGE_VERSION,
    "X-Scanner": "mcp-verify",
    ...customHeaders,
  };
}

/**
 * Package version for display purposes
 */
export const VERSION = PACKAGE_VERSION;
