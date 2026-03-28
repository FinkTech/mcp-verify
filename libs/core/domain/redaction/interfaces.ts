/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export interface IDetector {
  /** The unique name of the detector (e.g., "entropy", "high-confidence"). */
  readonly name: string;

  /**
   * Detects if a given string token is a secret.
   * @param token The string token to analyze.
   * @returns `true` if the token is identified as a secret, otherwise `false`.
   */
  detect(token: string): boolean;
}
