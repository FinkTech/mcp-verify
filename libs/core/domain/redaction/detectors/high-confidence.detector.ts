/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { IDetector } from "../interfaces";
import { HIGH_CONFIDENCE_PATTERNS } from "./patterns/high-confidence-patterns";

export class HighConfidenceDetector implements IDetector {
  readonly name = "high-confidence";
  private patterns: RegExp[] = HIGH_CONFIDENCE_PATTERNS.map((p) => p.pattern);

  public detect(token: string): boolean {
    for (const regex of this.patterns) {
      if (regex.test(token)) {
        return true;
      }
    }
    return false;
  }
}
