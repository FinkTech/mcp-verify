/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { IDetector } from "./interfaces";

export class SecretScanner {
  private detectors: IDetector[];

  /**
   * @param detectors An ordered array of secret detectors.
   *                  They will be executed in the order they are provided.
   */
  constructor(detectors: IDetector[]) {
    this.detectors = detectors;
  }

  /**
   * Checks a token against all registered detectors.
   * @param token The token to check.
   * @returns `true` if any detector identifies the token as a secret.
   */
  public isSecret(token: string): boolean {
    if (token.length < 8) {
      // console.log(`SecretScanner: Token too short (${token.length} < 8): '${token}'`); // Opcional: log para tokens cortos
      return false;
    }

    // console.log(`SecretScanner: Checking token '${token}'`); // Debug: token que entra
    for (const detector of this.detectors) {
      const isDetected = detector.detect(token);
      // console.log(`  - Detector '${detector.name}' for token '${token}': ${isDetected}`); // Debug: resultado por detector
      if (isDetected) {
        // console.log(`SecretScanner: Token '${token}' identified as secret by '${detector.name}'`); // Debug: secreto encontrado
        return true;
      }
    }
    // console.log(`SecretScanner: Token '${token}' not identified as secret.`); // Debug: no secreto
    return false;
  }
}
