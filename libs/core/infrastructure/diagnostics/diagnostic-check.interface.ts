/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export type DiagnosticStatus = "pass" | "fail" | "warn" | "skip";

export interface DiagnosticResult {
  name: string;
  status: DiagnosticStatus;
  message?: string;
  details?: string;
  remediation?: string;
  durationMs: number;
}

export interface IDiagnosticCheck {
  readonly name: string;
  readonly description: string;
  run(): Promise<DiagnosticResult>;
}
