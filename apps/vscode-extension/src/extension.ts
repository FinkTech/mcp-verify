/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - VS Code Extension
 *
 * Enterprise-grade security validation for MCP servers.
 * Full feature parity with the CLI tool.
 */

import * as vscode from "vscode";
import { translations, Language } from "@mcp-verify/core";

// State
import { globalState } from "./state/global-state";

// Views
import {
  ResultsTreeProvider,
  ServersTreeProvider,
  ToolsTreeProvider,
  HistoryTreeProvider,
} from "./views";

// Providers
import { McpDiagnosticProvider } from "./providers/diagnostics";
import { McpReportPanel } from "./providers/report-panel";
import { McpCodeActionProvider } from "./providers/code-actions";

// Commands
import {
  runValidateCommand,
  runFuzzCommand,
  runStressCommand,
  runDoctorCommand,
  runExportSarifCommand,
  runGenerateBadgeCommand,
  runClearHistoryCommand,
  runRefreshResultsCommand,
  runShowFindingDetailsCommand,
  runShowHistoryReportCommand,
  runSuggestSecureSchemaCommand,
} from "./commands";

// Utils
import { OutputChannelLogger } from "./utils/logger";

// Extension state
let logger: OutputChannelLogger;
let statusBarItem: vscode.StatusBarItem;
let diagnosticProvider: McpDiagnosticProvider;

// Tree providers
let serversTreeProvider: ServersTreeProvider;
let resultsTreeProvider: ResultsTreeProvider;
let toolsTreeProvider: ToolsTreeProvider;
let historyTreeProvider: HistoryTreeProvider;

/**
 * Get user language setting
 */
function getLanguage(): Language {
  const config = vscode.workspace.getConfiguration("mcpVerify");
  const lang = config.get<string>("language");

  if (lang === "es" || lang === "en") {
    return lang;
  }

  return vscode.env.language.startsWith("es") ? "es" : "en";
}

/**
 * Get translated message
 */
function t(key: keyof typeof translations.en): string {
  const lang = getLanguage();
  // @ts-ignore
  return translations[lang][key] || translations["en"][key] || key;
}

/**
 * Update status bar with score
 */
function updateStatusBar(score?: number): void {
  if (!statusBarItem) return;

  if (score === undefined) {
    statusBarItem.text = "$(shield) MCP Verify";
    statusBarItem.tooltip = "MCP Verify - Click to validate";
    statusBarItem.backgroundColor = undefined;
    return;
  }

  let icon = "$(shield)";
  let bgColor: vscode.ThemeColor | undefined;

  if (score >= 90) {
    icon = "$(shield)";
    bgColor = undefined;
  } else if (score >= 70) {
    icon = "$(shield)";
    bgColor = new vscode.ThemeColor("statusBarItem.warningBackground");
  } else {
    icon = "$(shield)";
    bgColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  }

  statusBarItem.text = `${icon} MCP: ${score}`;
  statusBarItem.tooltip = `Security Score: ${score}/100\nClick to run validation`;
  statusBarItem.backgroundColor = bgColor;
}

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext): void {
  try {
    // Initialize logger
    logger = new OutputChannelLogger("MCP Verify");
    context.subscriptions.push(logger.getChannel());
    logger.info("MCP Verify extension activating...");

    // Initialize global state
    globalState.initialize(context);

    // Initialize diagnostics
    diagnosticProvider = new McpDiagnosticProvider("mcp-verify");
    context.subscriptions.push(diagnosticProvider);

    // Initialize status bar
    statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100,
    );
    statusBarItem.command = "mcp-verify.validate";
    updateStatusBar();
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Initialize tree views
    serversTreeProvider = new ServersTreeProvider();
    resultsTreeProvider = new ResultsTreeProvider();
    toolsTreeProvider = new ToolsTreeProvider();
    historyTreeProvider = new HistoryTreeProvider();

    context.subscriptions.push(
      vscode.window.registerTreeDataProvider(
        "mcp-verify.servers",
        serversTreeProvider,
      ),
      vscode.window.registerTreeDataProvider(
        "mcp-verify.results",
        resultsTreeProvider,
      ),
      vscode.window.registerTreeDataProvider(
        "mcp-verify.tools",
        toolsTreeProvider,
      ),
      vscode.window.registerTreeDataProvider(
        "mcp-verify.history",
        historyTreeProvider,
      ),
    );

    // Listen to results changes to update status bar and diagnostics
    globalState.onResultsChanged((results) => {
      const latest = globalState.getLatestResult();
      if (latest) {
        updateStatusBar(latest.score);

        // Update diagnostics
        if (latest.report.security) {
          diagnosticProvider.updateDiagnostics(latest.report.security);
        }
      }
    });

    // Register code action provider
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
      { pattern: "**/*" },
      new McpCodeActionProvider(),
      {
        providedCodeActionKinds: McpCodeActionProvider.providedCodeActionKinds,
      },
    );
    context.subscriptions.push(codeActionProvider);

    // === Register Commands ===

    // Validate
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.validate", () =>
        runValidateCommand(context, logger),
      ),
    );

    // Fuzz
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.fuzz", () =>
        runFuzzCommand(context, logger),
      ),
    );

    // Stress
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.stress", () =>
        runStressCommand(context, logger),
      ),
    );

    // Doctor
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.doctor", () =>
        runDoctorCommand(logger),
      ),
    );

    // Show Results
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.showResults", () => {
        vscode.commands.executeCommand("mcp-verify.results.focus");
      }),
    );

    // Clear History
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.clearHistory", () =>
        runClearHistoryCommand(logger),
      ),
    );

    // Export SARIF
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.exportSarif", () =>
        runExportSarifCommand(logger),
      ),
    );

    // Generate Badge
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.generateBadge", () =>
        runGenerateBadgeCommand(logger),
      ),
    );

    // Compare Baseline
    context.subscriptions.push(
      vscode.commands.registerCommand(
        "mcp-verify.compareBaseline",
        async () => {
          const uri = await vscode.window.showOpenDialog({
            canSelectFiles: true,
            canSelectFolders: false,
            filters: { Baseline: ["json"] },
          });

          if (uri && uri[0]) {
            vscode.window.showInformationMessage(
              `Baseline comparison with ${uri[0].fsPath} coming soon!`,
            );
          }
        },
      ),
    );

    // Suggest Secure Schema
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.suggestSecureSchema", () =>
        runSuggestSecureSchemaCommand(context, logger),
      ),
    );

    // Refresh Results
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.refreshResults", () => {
        resultsTreeProvider.refresh();
        toolsTreeProvider.refresh();
        historyTreeProvider.refresh();
      }),
    );

    // Select Server
    context.subscriptions.push(
      vscode.commands.registerCommand("mcp-verify.selectServer", (server) => {
        globalState.setActiveServer(server);
        vscode.window.showInformationMessage(`Selected server: ${server.name}`);
      }),
    );

    // Show Finding Details
    context.subscriptions.push(
      vscode.commands.registerCommand(
        "mcp-verify.showFindingDetails",
        (finding) => runShowFindingDetailsCommand(finding),
      ),
    );

    // Show History Report
    context.subscriptions.push(
      vscode.commands.registerCommand(
        "mcp-verify.showHistoryReport",
        (result) => runShowHistoryReportCommand(context, result),
      ),
    );

    // Execute Tool (from tools tree)
    context.subscriptions.push(
      vscode.commands.registerCommand(
        "mcp-verify.executeTool",
        async (tool) => {
          vscode.window.showInformationMessage(
            `Tool execution for "${tool.name}" coming soon!`,
          );
        },
      ),
    );

    // Generate Suggestion (from code actions)
    context.subscriptions.push(
      vscode.commands.registerCommand(
        "mcp-verify.generateSuggestion",
        async (
          document: vscode.TextDocument,
          diagnostic: vscode.Diagnostic,
        ) => {
          const { generateSuggestionFile } =
            await import("./providers/code-actions");
          await generateSuggestionFile(document, diagnostic);
        },
      ),
    );

    // Show welcome message
    logger.success("MCP Verify extension activated");
    vscode.window.showInformationMessage(`MCP Verify: ${t("welcome_title")}`);
  } catch (error) {
    console.error("Failed to activate MCP Verify:", error);
    if (error instanceof Error) {
      vscode.window.showErrorMessage(
        `MCP Verify activation failed: ${error.message}`,
      );
    }
  }
}

/**
 * Extension deactivation
 */
export function deactivate(): void {
  if (diagnosticProvider) {
    diagnosticProvider.dispose();
  }
  if (logger) {
    logger.dispose();
  }
  globalState.dispose();
}
