/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { IDetector } from "../interfaces";

const MIN_ENTROPY_LENGTH = 20;
const ENTROPY_THRESHOLD = 4.5;

export class EntropyDetector implements IDetector {
  readonly name = "entropy";

  public detect(token: string): boolean {
    // Pre-condition 1: length guard
    if (token.length <= MIN_ENTROPY_LENGTH) {
      return false;
    }

    // Pre-condition 2: must contain uppercase, lowercase AND digits
    const hasUpper = /[A-Z]/.test(token);
    const hasLower = /[a-z]/.test(token);
    const hasDigits = /[0-9]/.test(token);
    if (!(hasUpper && hasLower && hasDigits)) {
      return false;
    }

    // Pre-condition 3: skip obvious non-secrets
    if (
      token.startsWith("/") ||
      /^https?:\/\//i.test(token) ||
      /^\d+\.\d+\.\d+/.test(token) ||
      /^[A-Z][A-Z0-9_]{2,}$/.test(token)
    ) {
      return false;
    }

    return this.calculateShannonEntropy(token) > ENTROPY_THRESHOLD;
  }

  private calculateShannonEntropy(str: string): number {
    if (str.length === 0) {
      return 0;
    }

    const freq = new Map<string, number>();
    for (const ch of str) {
      freq.set(ch, (freq.get(ch) ?? 0) + 1);
    }

    const len = str.length;
    let entropy = 0;

    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }
}
