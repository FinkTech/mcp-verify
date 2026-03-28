/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export function safeJsonParse<T = unknown>(jsonString: string, fallback?: T): T | undefined {
  try {
    return JSON.parse(jsonString) as T;
  } catch (error) {
    if (fallback !== undefined) {
      return fallback;
    }
    return undefined;
  }
}
