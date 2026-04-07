/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import {
  IDiagnosticCheck,
  DiagnosticResult,
} from "./diagnostic-check.interface";

export class DiagnosticRunner {
  private checks: IDiagnosticCheck[] = [];

  register(check: IDiagnosticCheck) {
    this.checks.push(check);
  }

  async runAll(): Promise<DiagnosticResult[]> {
    // Run all checks in parallel for performance
    const promises = this.checks.map(async (check) => {
      try {
        return await check.run();
      } catch (error) {
        // Safety net: checks should handle their own errors, but just in case
        return {
          name: check.name,
          status: "fail" as const,
          message: `Check crashed: ${error instanceof Error ? error.message : String(error)}`,
          durationMs: 0,
        };
      }
    });

    return Promise.all(promises);
  }
}
