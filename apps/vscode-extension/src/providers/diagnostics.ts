/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import * as vscode from "vscode";
import { SecurityReport, SecurityFinding, Severity } from "@mcp-verify/core";

/**
 * Maps core security findings to VSCode diagnostics.
 */
export class McpDiagnosticProvider {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor(collectionName: string) {
    this.diagnosticCollection =
      vscode.languages.createDiagnosticCollection(collectionName);
  }

  /**
   * Clears existing diagnostics.
   */
  public clear(): void {
    this.diagnosticCollection.clear();
  }

  /**
   * Updates diagnostics based on a security report.
   * Since findings are runtime-based and not tied to a specific text file line,
   * we will attach them to the currently active editor or a virtual file if possible.
   * For MVP, we attach to the workspace root or display as general information.
   *
   * @param report The security report from the scanner
   */
  public updateDiagnostics(report: SecurityReport): void {
    this.clear();

    const diagnostics: vscode.Diagnostic[] = [];

    // Group findings by "file" if we can map them, otherwise generic.
    // Since MCP findings are about the *server* behavior, not source code lines,
    // we'll create a virtual mapping or show them on the active config file.

    // Strategy: Create diagnostics associated with the project root URI
    // or the active text editor if applicable.
    const currentUri = vscode.window.activeTextEditor?.document.uri;

    if (!currentUri) {
      // If no file is open, we can't show "sqiggles".
      // We might rely on the Output Channel instead or a WebView report.
      // But to use the "Problems" panel, we need a URI.
      return;
    }

    report.findings.forEach((finding) => {
      const severity = this.mapSeverity(finding.severity);

      // Create a diagnostic range. Since we don't have line numbers,
      // we'll put it at the top of the file (0,0) or generic range.
      const range = new vscode.Range(0, 0, 0, 1);

      const diagnostic = new vscode.Diagnostic(
        range,
        `[${finding.ruleCode}] ${finding.message} - ${finding.remediation}`,
        severity,
      );

      diagnostic.source = "MCP Security";
      diagnostic.code = finding.ruleCode; // Allows linking to documentation

      diagnostics.push(diagnostic);
    });

    this.diagnosticCollection.set(currentUri, diagnostics);
  }

  private mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
      case "critical":
      case "high":
        return vscode.DiagnosticSeverity.Error;
      case "medium":
        return vscode.DiagnosticSeverity.Warning;
      case "low":
      case "info":
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Hint;
    }
  }

  public dispose() {
    this.diagnosticCollection.dispose();
  }
}
