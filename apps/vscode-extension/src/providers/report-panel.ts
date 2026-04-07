/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import * as vscode from "vscode";
import { HtmlReportGenerator, Report, Language } from "@mcp-verify/core";

/**
 * Manages the WebView panel for displaying MCP validation reports.
 */
export class McpReportPanel {
  public static currentPanel: McpReportPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private readonly _extensionUri: vscode.Uri;
  private _disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this._panel = panel;
    this._extensionUri = extensionUri;

    // Listen for when the panel is disposed
    // This happens when the user closes the panel or when the panel is closed programmatically
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
  }

  /**
   * Creates or shows the report panel.
   */
  public static createOrShow(
    extensionUri: vscode.Uri,
    report: Report,
    lang: Language = "en",
  ) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    // If we already have a panel, show it.
    if (McpReportPanel.currentPanel) {
      McpReportPanel.currentPanel.update(report, lang);
      McpReportPanel.currentPanel._panel.reveal(column);
      return;
    }

    // Otherwise, create a new panel.
    const panel = vscode.window.createWebviewPanel(
      "mcpVerifyReport",
      "MCP Validation Report",
      column || vscode.ViewColumn.One,
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(extensionUri, "media")],
      },
    );

    McpReportPanel.currentPanel = new McpReportPanel(panel, extensionUri);
    McpReportPanel.currentPanel.update(report, lang);
  }

  public update(report: Report, lang: Language) {
    this._panel.title = `MCP Report: ${report.server_name}`;
    this._panel.webview.html = this._getHtmlForWebview(report, lang);
  }

  public dispose() {
    McpReportPanel.currentPanel = undefined;

    this._panel.dispose();

    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }

  private _getHtmlForWebview(report: Report, lang: Language): string {
    // Determine language if not provided (default to 'en')
    const finalLang = lang || "en";

    // Use the core HtmlReportGenerator
    // This ensures consistency with the CLI report
    const html = HtmlReportGenerator.generate(report, finalLang);

    // Adjust Content Security Policy (CSP) if needed
    // For now, the raw HTML generation embeds styles/scripts, so it should work out of the box
    // But we might need to fix image paths if they were absolute.
    // However, HtmlReportGenerator uses base64 images mostly.

    return html;
  }
}
