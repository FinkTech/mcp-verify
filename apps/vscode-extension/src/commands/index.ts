/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify - Commands Module
 *
 * All command handlers for the VS Code extension.
 */

import * as vscode from "vscode";
import { parse as parseShellCommand } from "shell-quote";
import {
  StdioTransport,
  MCPValidator,
  Report,
  SecurityFinding,
  SarifGenerator,
  BadgeGenerator,
  translations,
  Language,
  JsonValue,
  McpTool,
  McpResource,
  McpPrompt,
} from "@mcp-verify/core";

import {
  globalState,
  ServerInfo,
  ScanResult,
  ToolInfo,
} from "../state/global-state";
import { McpReportPanel } from "../providers/report-panel";
import { OutputChannelLogger } from "../utils/logger";

/**
 * Convert unknown value to JsonValue for safe JSON-RPC transmission
 */
function toJsonValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value as JsonValue;
  }
  if (Array.isArray(value)) {
    return value.map(toJsonValue) as JsonValue[];
  }
  if (typeof value === "object") {
    const obj: Record<string, JsonValue> = {};
    for (const [k, v] of Object.entries(value)) {
      obj[k] = toJsonValue(v);
    }
    return obj;
  }
  // Fallback for unsupported types
  return String(value);
}

// Helper to get user language
function getLanguage(): Language {
  const config = vscode.workspace.getConfiguration("mcpVerify");
  const lang = config.get<string>("language");

  if (lang === "es" || lang === "en") {
    return lang;
  }

  // Auto-detect
  return vscode.env.language.startsWith("es") ? "es" : "en";
}

// Helper to get translated message
function t(key: keyof typeof translations.en): string {
  const lang = getLanguage();
  // @ts-ignore
  return translations[lang][key] || translations["en"][key] || key;
}

// Helper to prompt for server command
async function promptForServerCommand(): Promise<
  { command: string; executable: string; args: string[] } | undefined
> {
  const config = vscode.workspace.getConfiguration("mcpVerify");
  const recentCommands = config.get<string[]>("recentCommands") || [];

  let command: string | undefined;

  if (recentCommands.length > 0) {
    const items = [
      { label: "$(add) Enter new command...", command: null as string | null },
      {
        label: "",
        kind: vscode.QuickPickItemKind.Separator,
        command: null as string | null,
      },
      ...recentCommands.map((cmd) => ({
        label: `$(history) ${cmd}`,
        description: "Recent",
        command: cmd,
      })),
    ];

    const selected = await vscode.window.showQuickPick(items, {
      placeHolder: "Select an MCP server command or enter a new one",
    });

    if (!selected) return undefined;

    if (selected.command === null) {
      command = await vscode.window.showInputBox({
        prompt: "Enter MCP Server Command",
        placeHolder: "npx -y @modelcontextprotocol/server-memory",
      });
    } else {
      command = selected.command;
    }
  } else {
    command = await vscode.window.showInputBox({
      prompt: "Enter MCP Server Command",
      placeHolder: "npx -y @modelcontextprotocol/server-memory",
    });
  }

  if (!command) return undefined;

  // Save to recent commands
  const filtered = recentCommands.filter((c) => c !== command);
  const updated = [command, ...filtered].slice(0, 10);
  config.update("recentCommands", updated, vscode.ConfigurationTarget.Global);

  // Parse command
  const parsed = parseShellCommand(command);
  const executable = String(parsed[0] || "");
  const args = parsed.slice(1).map((arg) => String(arg));

  if (!executable) {
    vscode.window.showErrorMessage("Invalid command: executable is required");
    return undefined;
  }

  return { command, executable, args };
}

/**
 * Validate Command Handler
 */
export async function runValidateCommand(
  context: vscode.ExtensionContext,
  logger: OutputChannelLogger,
): Promise<void> {
  const cmdInfo = await promptForServerCommand();
  if (!cmdInfo) return;

  const config = vscode.workspace.getConfiguration("mcpVerify");
  const enableFuzzing = config.get<boolean>("validation.enableFuzzing", false);
  const enableSemanticCheck = config.get<boolean>(
    "validation.enableSemanticCheck",
    false,
  );

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "MCP Verify: Validating",
      cancellable: true,
    },
    async (progress, token) => {
      let transport: StdioTransport | undefined;
      const startTime = Date.now();

      try {
        progress.report({ message: "Connecting to server..." });
        logger.info(`Starting validation: ${cmdInfo.command}`);

        transport = StdioTransport.create(cmdInfo.executable, cmdInfo.args);
        const validator = new MCPValidator(transport);

        // Handshake
        progress.report({ message: "Performing handshake..." });
        const handshake = await validator.testHandshake();

        if (!handshake.success) {
          throw new Error(`Handshake failed: ${handshake.error}`);
        }

        logger.success(`Connected to ${handshake.serverName}`);

        // Add/Update server in state
        const serverId =
          `${cmdInfo.executable}-${cmdInfo.args.join("-")}`.replace(
            /[^a-zA-Z0-9-]/g,
            "_",
          );
        const existingServer = globalState
          .getServers()
          .find((s) => s.command === cmdInfo.executable);

        let server: ServerInfo;
        if (existingServer) {
          globalState.updateServer(existingServer.id, { status: "scanning" });
          server = existingServer;
        } else {
          server = globalState.addServer({
            name: handshake.serverName || cmdInfo.executable,
            command: cmdInfo.executable,
            args: cmdInfo.args,
            status: "scanning",
          });
        }

        // Discovery
        progress.report({ message: "Discovering capabilities..." });
        const discovery = await validator.discoverCapabilities();
        logger.info(
          `Found ${discovery.tools?.length || 0} tools, ${discovery.resources?.length || 0} resources`,
        );

        // Update tools in state
        if (discovery.tools) {
          const toolInfos: ToolInfo[] = discovery.tools.map((tool) => ({
            name: tool.name,
            description: tool.description || "",
            serverId: server.id,
            serverName: server.name,
            inputSchema: tool.inputSchema as Record<string, unknown>,
            hasSecurityIssues: false, // Will be updated after security scan
          }));
          globalState.setTools(toolInfos);
        }

        // Schema validation
        progress.report({ message: "Validating schemas..." });
        const validation = await validator.validateSchema();

        // Generate report
        progress.report({ message: "Running security scan..." });
        const report = await validator.generateReport({
          handshake,
          discovery,
          validation,
        });

        const duration = Date.now() - startTime;

        // Update tools with security info
        if (report.security?.findings) {
          const vulnTools = new Set(
            report.security.findings.map((f) => f.toolName).filter(Boolean),
          );
          const tools = globalState.getTools().map((t) => ({
            ...t,
            hasSecurityIssues: vulnTools.has(t.name),
          }));
          globalState.setTools(tools);
        }

        // Add result to state
        const result: Omit<ScanResult, "id"> = {
          serverId: server.id,
          serverName: server.name,
          timestamp: new Date(),
          report,
          findings: report.security?.findings || [],
          score: report.security?.score || 100,
          duration,
        };
        globalState.addResult(result);

        // Update server status
        globalState.updateServer(server.id, {
          status: "idle",
          lastScanned: new Date(),
          lastScore: report.security?.score,
        });

        // Show results
        const findingCount = report.security?.findings?.length || 0;
        if (findingCount === 0) {
          logger.success("Validation passed! No security issues found.");
          vscode.window.showInformationMessage(
            `MCP Verify: Validation passed! Score: ${report.security?.score || 100}/100`,
          );
        } else {
          logger.warn(`Found ${findingCount} security issues`);
          vscode.window.showWarningMessage(
            `MCP Verify: Found ${findingCount} issues. Score: ${report.security?.score || 0}/100`,
          );
        }

        // Show report panel
        McpReportPanel.createOrShow(
          context.extensionUri,
          report,
          getLanguage(),
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.error("Validation failed", error);
        vscode.window.showErrorMessage(`MCP Verify: ${message}`);
      } finally {
        transport?.close();
      }
    },
  );
}

/**
 * Fuzz Command Handler
 */
export async function runFuzzCommand(
  context: vscode.ExtensionContext,
  logger: OutputChannelLogger,
): Promise<void> {
  const cmdInfo = await promptForServerCommand();
  if (!cmdInfo) return;

  const config = vscode.workspace.getConfiguration("mcpVerify");
  const concurrency = config.get<number>("fuzzing.concurrency", 1);
  const timeout = config.get<number>("fuzzing.timeout", 5000);
  const stopOnFirst = config.get<boolean>("fuzzing.stopOnFirst", false);
  const enableFingerprinting = config.get<boolean>(
    "fuzzing.enableFingerprinting",
    false,
  );

  // Show tool picker
  const tools = globalState.getTools();
  let selectedTool: string | undefined;

  if (tools.length > 0) {
    const toolItems = tools.map((t) => ({
      label: t.name,
      description: t.description.substring(0, 50),
    }));

    const selected = await vscode.window.showQuickPick(toolItems, {
      placeHolder: "Select a tool to fuzz (or press Escape to fuzz all)",
    });

    selectedTool = selected?.label;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "MCP Verify: Fuzzing",
      cancellable: true,
    },
    async (progress, token) => {
      let transport: StdioTransport | undefined;

      try {
        progress.report({ message: "Connecting to server..." });
        logger.info(`Starting fuzzing: ${cmdInfo.command}`);

        transport = StdioTransport.create(cmdInfo.executable, cmdInfo.args);

        // Import fuzzer components dynamically
        const {
          FuzzerEngine,
          PromptInjectionGenerator,
          ClassicPayloadGenerator,
          JwtAttackGenerator,
          PrototypePollutionGenerator,
          TimingDetector,
          ErrorDetector,
          XssDetector,
          PromptLeakDetector,
          JailbreakDetector,
        } = await import("@mcp-verify/fuzzer");

        // Create FuzzTarget wrapper
        const fuzzTarget = {
          async execute(payload: { value: unknown }): Promise<{
            response: unknown;
            responseTimeMs: number;
            isError: boolean;
            error?: { code: number; message: string };
          }> {
            const startTime = Date.now();
            try {
              // Convert payload.value to JsonValue
              const payloadValue = toJsonValue(payload.value);

              const result = await transport!.send({
                jsonrpc: "2.0",
                id: Math.random(),
                method: "tools/call",
                params: {
                  name: selectedTool || "unknown",
                  arguments: { input: payloadValue },
                },
              });

              const responseTimeMs = Date.now() - startTime;

              return {
                response: result,
                responseTimeMs,
                isError: false,
              };
            } catch (error) {
              const responseTimeMs = Date.now() - startTime;
              const errorObj =
                error instanceof Error
                  ? { code: -1, message: error.message }
                  : { code: -1, message: String(error) };

              return {
                response: null,
                responseTimeMs,
                isError: true,
                error: errorObj,
              };
            }
          },
        };

        // Initialize generators based on config
        const generators = [
          new PromptInjectionGenerator(),
          new ClassicPayloadGenerator({
            categories: ["sqli", "xss", "cmdInjection", "pathTraversal"],
            maxPerCategory: 5,
          }),
          new JwtAttackGenerator(),
          new PrototypePollutionGenerator(),
        ];

        // Initialize detectors
        const detectors = [
          new TimingDetector({ minSamples: 5 }),
          new ErrorDetector(),
          new XssDetector(),
          new PromptLeakDetector(),
          new JailbreakDetector(),
        ];

        let vulnerabilitiesFound = 0;
        const currentTool = selectedTool || "all tools";

        // Create FuzzerEngine
        const engine = new FuzzerEngine({
          generators,
          detectors,
          concurrency,
          timeout,
          stopOnFirstVulnerability: stopOnFirst,
          enableFingerprinting,
          onProgress: (fuzzProgress) => {
            if (!token.isCancellationRequested) {
              progress.report({
                message: `Fuzzing ${currentTool}: ${fuzzProgress.percentage}% (${fuzzProgress.current}/${fuzzProgress.total}) | Vulns: ${fuzzProgress.vulnerabilitiesFound}`,
                increment: 0,
              });
            }
          },
          onVulnerability: (detection, payload) => {
            vulnerabilitiesFound++;
            logger.warn(
              `Vulnerability found: ${detection.vulnerabilityType} (${detection.severity})`,
            );
          },
          onFingerprint: (fingerprint) => {
            logger.info(
              `Server fingerprint: ${fingerprint.language}/${fingerprint.framework}`,
            );
          },
        });

        // Handshake first
        progress.report({ message: "Performing handshake..." });
        const initResponse = await transport.send({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "mcp-verify-vscode", version: "1.0.0" },
          },
        });

        if (!initResponse) {
          throw new Error("Failed to initialize MCP connection");
        }

        // Discovery
        progress.report({ message: "Discovering tools..." });
        const listToolsResponse = await transport.send({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
          params: {},
        });

        const discoveredTools =
          (listToolsResponse as { tools?: Array<{ name: string }> }).tools ||
          [];

        if (discoveredTools.length === 0) {
          throw new Error("No tools discovered from server");
        }

        logger.info(`Discovered ${discoveredTools.length} tools`);

        // Run fuzzing session
        progress.report({
          message: `Running fuzzing engine on ${selectedTool || "all tools"}...`,
        });
        const session = await engine.fuzz(
          fuzzTarget,
          selectedTool || "all",
          undefined,
        );

        // Close transport
        transport.close();

        // Show results
        logger.success(
          `Fuzzing complete: ${session.payloadsExecuted} payloads executed, ${session.vulnerabilities.length} vulnerabilities found`,
        );

        if (session.vulnerabilities.length === 0) {
          vscode.window.showInformationMessage(
            `MCP Verify: Fuzzing complete. No vulnerabilities found.`,
          );
        } else {
          vscode.window.showWarningMessage(
            `MCP Verify: Found ${session.vulnerabilities.length} potential vulnerabilities.`,
          );

          // Update global state with vulnerabilities
          // Convert fuzzer DetectionResult to SecurityFinding format
          const findings: SecurityFinding[] = session.vulnerabilities.map(
            (vuln) => {
              // Convert evidence to Record<string, JsonValue>
              const evidence: Record<string, JsonValue> | undefined =
                vuln.evidence
                  ? {
                      payload: toJsonValue(vuln.evidence.payload),
                      response: toJsonValue(vuln.evidence.response),
                      ...(vuln.evidence.matchedPatterns && {
                        matchedPatterns: vuln.evidence.matchedPatterns,
                      }),
                    }
                  : undefined;

              const finding: SecurityFinding = {
                severity: vuln.severity as
                  | "critical"
                  | "high"
                  | "medium"
                  | "low"
                  | "info",
                message: vuln.description,
                component: `tool:${selectedTool || "unknown"}`,
                ruleCode: vuln.detectorId,
                evidence,
                remediation: vuln.remediation,
                toolName: selectedTool,
                ruleName: vuln.vulnerabilityType,
                cwe: vuln.cweId,
              };

              return finding;
            },
          );

          // Add scan result to global state
          const serverId =
            `${cmdInfo.executable}-${cmdInfo.args.join("-")}`.replace(
              /[^a-zA-Z0-9-]/g,
              "_",
            );
          const score = Math.max(0, 100 - session.vulnerabilities.length * 10);
          const duration = session.endedAt
            ? session.endedAt.getTime() - session.startedAt.getTime()
            : 0;

          // Build complete Report object matching validation.types.ts
          const report: Report = {
            server_name: cmdInfo.executable,
            url: `stdio://${cmdInfo.executable}`,
            status: session.vulnerabilities.length > 0 ? "invalid" : "valid",
            protocol_version: "2024-11-05",
            timestamp: new Date().toISOString(),
            duration_ms: duration,
            security: {
              score,
              level:
                score >= 90 ? "safe" : score >= 70 ? "moderate" : "critical",
              findings,
              criticalCount: findings.filter((f) => f.severity === "critical")
                .length,
              highCount: findings.filter((f) => f.severity === "high").length,
              mediumCount: findings.filter((f) => f.severity === "medium")
                .length,
              lowCount: findings.filter((f) => f.severity === "low").length,
              infoCount: findings.filter((f) => f.severity === "info").length,
            },
            quality: {
              score: 100,
              issues: [],
            },
            tools: {
              count: 0,
              valid: 0,
              invalid: 0,
              items: [],
            },
            resources: {
              count: 0,
              valid: 0,
              invalid: 0,
              items: [],
            },
            prompts: {
              count: 0,
              valid: 0,
              invalid: 0,
              items: [],
            },
          };

          const scanResult = {
            serverId,
            serverName: cmdInfo.executable,
            timestamp: new Date(),
            report,
            findings,
            score,
            duration,
          };

          globalState.addResult(scanResult);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.error("Fuzzing failed", error);
        vscode.window.showErrorMessage(`MCP Verify Fuzz: ${message}`);
      } finally {
        if (transport) {
          try {
            transport.close();
          } catch (closeError) {
            logger.warn(
              `Error closing transport: ${closeError instanceof Error ? closeError.message : String(closeError)}`,
            );
          }
        }
      }
    },
  );
}

/**
 * Stress Test Command Handler
 */
export async function runStressCommand(
  context: vscode.ExtensionContext,
  logger: OutputChannelLogger,
): Promise<void> {
  const cmdInfo = await promptForServerCommand();
  if (!cmdInfo) return;

  const config = vscode.workspace.getConfiguration("mcpVerify");
  const users = config.get<number>("stress.concurrentUsers", 5);
  const duration = config.get<number>("stress.duration", 10);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `MCP Verify: Stress Test (${users} users, ${duration}s)`,
      cancellable: true,
    },
    async (progress, token) => {
      let transport: StdioTransport | undefined;

      try {
        logger.info(`Starting stress test: ${users} users, ${duration}s`);
        progress.report({ message: "Connecting..." });

        transport = StdioTransport.create(cmdInfo.executable, cmdInfo.args);
        const validator = new MCPValidator(transport);

        const handshake = await validator.testHandshake();
        if (!handshake.success) {
          throw new Error(`Handshake failed: ${handshake.error}`);
        }

        progress.report({ message: "Running stress test..." });

        // Simplified stress test - just make repeated calls
        const startTime = Date.now();
        const endTime = startTime + duration * 1000;
        let requestCount = 0;
        let errorCount = 0;

        while (Date.now() < endTime && !token.isCancellationRequested) {
          try {
            await validator.discoverCapabilities();
            requestCount++;
          } catch {
            errorCount++;
          }

          const elapsed = Date.now() - startTime;
          const remaining = Math.max(0, duration - Math.floor(elapsed / 1000));
          progress.report({
            message: `${remaining}s remaining... (${requestCount} requests)`,
          });
        }

        const totalTime = (Date.now() - startTime) / 1000;
        const rps = requestCount / totalTime;

        logger.success(
          `Stress test complete: ${requestCount} requests, ${errorCount} errors, ${rps.toFixed(2)} RPS`,
        );

        vscode.window.showInformationMessage(
          `Stress Test Complete: ${requestCount} requests in ${totalTime.toFixed(1)}s (${rps.toFixed(2)} RPS)`,
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.error("Stress test failed", error);
        vscode.window.showErrorMessage(`MCP Verify Stress: ${message}`);
      } finally {
        transport?.close();
      }
    },
  );
}

/**
 * Doctor Command Handler
 */
export async function runDoctorCommand(
  logger: OutputChannelLogger,
): Promise<void> {
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "MCP Verify: Running Diagnostics",
      cancellable: false,
    },
    async (progress) => {
      const issues: string[] = [];
      const successes: string[] = [];

      // Check Node.js
      progress.report({ message: "Checking Node.js..." });
      try {
        const { execSync } = require("child_process");
        const nodeVersion = execSync("node --version", {
          encoding: "utf8",
        }).trim();
        const major = parseInt(nodeVersion.replace("v", "").split(".")[0]);
        if (major >= 18) {
          successes.push(`Node.js ${nodeVersion}`);
        } else {
          issues.push(`Node.js ${nodeVersion} (18+ recommended)`);
        }
      } catch {
        issues.push("Node.js not found");
      }

      // Check npm
      progress.report({ message: "Checking npm..." });
      try {
        const { execSync } = require("child_process");
        const npmVersion = execSync("npm --version", {
          encoding: "utf8",
        }).trim();
        successes.push(`npm ${npmVersion}`);
      } catch {
        issues.push("npm not found");
      }

      // Check npx
      progress.report({ message: "Checking npx..." });
      try {
        const { execSync } = require("child_process");
        execSync("npx --version", { encoding: "utf8" });
        successes.push("npx available");
      } catch {
        issues.push("npx not found");
      }

      // Check environment variables
      progress.report({ message: "Checking API keys..." });
      if (process.env.ANTHROPIC_API_KEY) {
        successes.push("ANTHROPIC_API_KEY configured");
      }
      if (process.env.OPENAI_API_KEY) {
        successes.push("OPENAI_API_KEY configured");
      }

      // Show results
      const outputChannel = vscode.window.createOutputChannel(
        "MCP Verify Diagnostics",
      );
      outputChannel.clear();
      outputChannel.appendLine("=== MCP Verify Diagnostics ===\n");

      outputChannel.appendLine("Passed:");
      successes.forEach((s) => outputChannel.appendLine(`  [OK] ${s}`));

      if (issues.length > 0) {
        outputChannel.appendLine("\nIssues:");
        issues.forEach((i) => outputChannel.appendLine(`  [!] ${i}`));
      }

      outputChannel.appendLine("\n=== End Diagnostics ===");
      outputChannel.show();

      if (issues.length === 0) {
        vscode.window.showInformationMessage(
          "MCP Verify: All diagnostics passed!",
        );
      } else {
        vscode.window.showWarningMessage(
          `MCP Verify: ${issues.length} issue(s) found. Check output for details.`,
        );
      }
    },
  );
}

/**
 * Export SARIF Command Handler
 */
export async function runExportSarifCommand(
  logger: OutputChannelLogger,
): Promise<void> {
  const result = globalState.getLatestResult();

  if (!result) {
    vscode.window.showWarningMessage(
      "No scan results to export. Run a validation first.",
    );
    return;
  }

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(
      `mcp-verify-${result.serverName}-${Date.now()}.sarif`,
    ),
    filters: {
      SARIF: ["sarif", "json"],
    },
  });

  if (!uri) return;

  try {
    const sarif = SarifGenerator.generate(result.report);
    const content = JSON.stringify(sarif, null, 2);

    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, "utf8"));

    logger.success(`SARIF exported to ${uri.fsPath}`);
    vscode.window.showInformationMessage(
      `SARIF report exported: ${uri.fsPath}`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error("SARIF export failed", error);
    vscode.window.showErrorMessage(`Export failed: ${message}`);
  }
}

/**
 * Generate Badge Command Handler
 */
export async function runGenerateBadgeCommand(
  logger: OutputChannelLogger,
): Promise<void> {
  const result = globalState.getLatestResult();

  if (!result) {
    vscode.window.showWarningMessage(
      "No scan results. Run a validation first.",
    );
    return;
  }

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(`mcp-verify-badge-${result.score}.svg`),
    filters: {
      SVG: ["svg"],
    },
  });

  if (!uri) return;

  try {
    const badgeData = BadgeGenerator.generate(result.report);

    // Use the markdown or URL from the badge
    const badgeContent = badgeData.html || badgeData.markdown;

    await vscode.workspace.fs.writeFile(uri, Buffer.from(badgeContent, "utf8"));

    logger.success(`Badge exported to ${uri.fsPath}`);
    vscode.window.showInformationMessage(
      `Security badge exported: ${uri.fsPath}`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error("Badge generation failed", error);
    vscode.window.showErrorMessage(`Badge generation failed: ${message}`);
  }
}

/**
 * Clear History Command Handler
 */
export function runClearHistoryCommand(logger: OutputChannelLogger): void {
  globalState.clearHistory();
  logger.info("Scan history cleared");
  vscode.window.showInformationMessage("MCP Verify: Scan history cleared.");
}

/**
 * Suggest Secure Schema Command Handler
 * Applies "Shield Pattern" - adds security constraints to tool schemas
 */
export async function runSuggestSecureSchemaCommand(
  context: vscode.ExtensionContext,
  logger: OutputChannelLogger,
): Promise<void> {
  try {
    // Get active editor
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage(
        "MCP Verify: No active editor found. Please open a file containing a tool schema.",
      );
      return;
    }

    // Get document text
    const documentText = editor.document.getText();
    let toolSchema: unknown;

    try {
      toolSchema = JSON.parse(documentText);
    } catch (parseError) {
      vscode.window.showErrorMessage(
        "MCP Verify: Active file is not valid JSON. Please open a tool schema file.",
      );
      return;
    }

    // Validate it looks like a tool schema
    if (!toolSchema || typeof toolSchema !== "object") {
      vscode.window.showErrorMessage(
        "MCP Verify: Active file does not contain a valid tool schema object.",
      );
      return;
    }

    // Apply schema hardening
    logger.info("Applying schema security constraints (Shield Pattern)");
    const hardenedSchema = applyShieldPattern(toolSchema);

    // Format as pretty JSON
    const hardenedJson = JSON.stringify(hardenedSchema, null, 2);

    // Open in new "Untitled" editor (side-by-side)
    const newDocument = await vscode.workspace.openTextDocument({
      content: hardenedJson,
      language: "json",
    });

    await vscode.window.showTextDocument(newDocument, {
      viewColumn: vscode.ViewColumn.Beside,
      preserveFocus: false,
      preview: false,
    });

    logger.success("Secure schema suggestion generated");
    vscode.window.showInformationMessage(
      "MCP Verify: Secure schema opened in new editor. Review and apply changes manually.",
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error("Secure schema suggestion failed", error);
    vscode.window.showErrorMessage(
      `MCP Verify: Failed to generate secure schema - ${message}`,
    );
  }
}

/**
 * Applies "Shield Pattern" security constraints to a tool schema.
 * Adds missing input validation constraints based on SEC-019 rule recommendations.
 *
 * @param schema - Original tool schema
 * @returns Hardened schema with security constraints
 */
function applyShieldPattern(schema: unknown): unknown {
  if (!schema || typeof schema !== "object") {
    return schema;
  }

  const result = JSON.parse(JSON.stringify(schema)); // Deep clone

  // If it's a tool schema with inputSchema
  if (
    "inputSchema" in result &&
    result.inputSchema &&
    typeof result.inputSchema === "object"
  ) {
    result.inputSchema = hardenInputSchema(result.inputSchema);
  }

  // If it's just a schema object itself
  if ("properties" in result || "type" in result) {
    return hardenInputSchema(result);
  }

  return result;
}

/**
 * Hardens an input schema by adding security constraints
 */
function hardenInputSchema(
  inputSchema: Record<string, unknown>,
): Record<string, unknown> {
  const hardened = { ...inputSchema };

  // Add additionalProperties: false for security (prevent injection)
  if ("properties" in hardened && !("additionalProperties" in hardened)) {
    hardened.additionalProperties = false;
  }

  // Process properties
  if (
    "properties" in hardened &&
    hardened.properties &&
    typeof hardened.properties === "object"
  ) {
    const properties = hardened.properties as Record<string, unknown>;
    hardened.properties = Object.fromEntries(
      Object.entries(properties).map(([name, prop]) => [
        name,
        hardenProperty(name, prop as Record<string, unknown>),
      ]),
    );
  }

  // Process array items
  if (
    "items" in hardened &&
    hardened.items &&
    typeof hardened.items === "object"
  ) {
    hardened.items = hardenInputSchema(
      hardened.items as Record<string, unknown>,
    );
  }

  return hardened;
}

/**
 * Hardens an individual property schema
 */
function hardenProperty(
  name: string,
  prop: Record<string, unknown>,
): Record<string, unknown> {
  const hardened = { ...prop };
  const propType = hardened.type as string | undefined;

  // Critical parameter names that need extra validation
  const CRITICAL_PARAMS = [
    "query",
    "sql",
    "command",
    "script",
    "code",
    "path",
    "url",
    "uri",
    "filename",
    "email",
    "username",
    "password",
  ];
  const isCritical = CRITICAL_PARAMS.some((kw) =>
    name.toLowerCase().includes(kw),
  );

  // String constraints
  if (propType === "string") {
    // Add maxLength if missing (10MB max, recommended)
    if (!hardened.maxLength && !hardened.pattern && !hardened.enum) {
      hardened.maxLength = 10 * 1024 * 1024; // 10MB
    }

    // Add pattern for critical parameters
    if (isCritical && !hardened.pattern && !hardened.enum) {
      // Add appropriate pattern based on parameter name
      if (name.toLowerCase().includes("email")) {
        hardened.pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
      } else if (
        name.toLowerCase().includes("url") ||
        name.toLowerCase().includes("uri")
      ) {
        hardened.pattern = "^https://[a-zA-Z0-9.-]+(/.*)?$";
      } else if (
        name.toLowerCase().includes("path") ||
        name.toLowerCase().includes("filename")
      ) {
        hardened.pattern = "^[a-zA-Z0-9/_.-]+$";
      } else {
        // Generic safe pattern (alphanumeric + common safe chars)
        hardened.pattern = "^[a-zA-Z0-9 ._-]+$";
      }
    }
  }

  // Numeric constraints
  if (propType === "number" || propType === "integer") {
    // Add minimum if missing
    if (
      hardened.minimum === undefined &&
      hardened.exclusiveMinimum === undefined
    ) {
      hardened.minimum = 0; // Safe default for most numeric inputs
    }

    // Add maximum if missing
    if (
      hardened.maximum === undefined &&
      hardened.exclusiveMaximum === undefined
    ) {
      hardened.maximum =
        propType === "integer" ? Number.MAX_SAFE_INTEGER : Number.MAX_VALUE;
    }
  }

  // Array constraints
  if (propType === "array") {
    // Add maxItems if missing
    if (!hardened.maxItems) {
      hardened.maxItems = 10000; // Recommended max
    }

    // Add minItems if missing
    if (hardened.minItems === undefined) {
      hardened.minItems = 0;
    }

    // Harden array items schema
    if (hardened.items && typeof hardened.items === "object") {
      hardened.items = hardenInputSchema(
        hardened.items as Record<string, unknown>,
      );
    }
  }

  // Object constraints
  if (propType === "object") {
    // Add maxProperties if missing
    if (!hardened.maxProperties && !hardened.properties) {
      hardened.maxProperties = 100; // Reasonable limit
    }

    // Add additionalProperties: false if missing
    if (!("additionalProperties" in hardened)) {
      hardened.additionalProperties = false;
    }

    // Recursively harden nested properties
    if (hardened.properties && typeof hardened.properties === "object") {
      const props = hardened.properties as Record<string, unknown>;
      hardened.properties = Object.fromEntries(
        Object.entries(props).map(([nestedName, nestedProp]) => [
          nestedName,
          hardenProperty(nestedName, nestedProp as Record<string, unknown>),
        ]),
      );
    }
  }

  return hardened;
}

/**
 * Refresh Results Command Handler
 */
export function runRefreshResultsCommand(): void {
  // Triggers tree view refresh via state change
  const latest = globalState.getLatestResult();
  if (latest) {
    // Re-add to trigger refresh
    globalState.addResult({
      serverId: latest.serverId,
      serverName: latest.serverName,
      timestamp: latest.timestamp,
      report: latest.report,
      findings: latest.findings,
      score: latest.score,
      duration: latest.duration,
    });
  }
}

/**
 * Show Finding Details Command Handler
 */
export function runShowFindingDetailsCommand(finding: SecurityFinding): void {
  const panel = vscode.window.createWebviewPanel(
    "mcpFindingDetails",
    `${finding.ruleCode}: ${finding.ruleName}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );

  panel.webview.html = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: var(--vscode-font-family);
            padding: 20px;
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
        h1 { color: var(--vscode-errorForeground); margin-bottom: 5px; }
        h2 { color: var(--vscode-foreground); opacity: 0.8; font-weight: normal; margin-top: 0; }
        .section { margin: 20px 0; }
        .label { font-weight: bold; color: var(--vscode-textLink-foreground); }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #17a2b8; }
        .severity-info { color: #6c757d; }
        pre {
            background: var(--vscode-textBlockQuote-background);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .remediation {
            background: var(--vscode-inputValidation-infoBackground);
            border-left: 3px solid var(--vscode-inputValidation-infoBorder);
            padding: 15px;
            margin: 15px 0;
        }
    </style>
</head>
<body>
    <h1>${finding.ruleCode}</h1>
    <h2>${finding.ruleName}</h2>

    <div class="section">
        <span class="label">Severity:</span>
        <span class="severity-${finding.severity}">${finding.severity.toUpperCase()}</span>
    </div>

    <div class="section">
        <span class="label">Description:</span>
        <p>${finding.message}</p>
    </div>

    ${
      finding.toolName
        ? `
    <div class="section">
        <span class="label">Affected Tool:</span>
        <code>${finding.toolName}</code>
    </div>
    `
        : ""
    }

    ${
      finding.evidence
        ? `
    <div class="section">
        <span class="label">Evidence:</span>
        <pre>${typeof finding.evidence === "string" ? finding.evidence : JSON.stringify(finding.evidence, null, 2)}</pre>
    </div>
    `
        : ""
    }

    ${
      finding.remediation
        ? `
    <div class="remediation">
        <span class="label">Remediation:</span>
        <p>${finding.remediation}</p>
    </div>
    `
        : ""
    }

    ${
      finding.cwe
        ? `
    <div class="section">
        <span class="label">CWE:</span>
        <a href="https://cwe.mitre.org/data/definitions/${finding.cwe}.html">CWE-${finding.cwe}</a>
    </div>
    `
        : ""
    }
</body>
</html>
    `;
}

/**
 * Show History Report Command Handler
 */
export function runShowHistoryReportCommand(
  context: vscode.ExtensionContext,
  result: ScanResult,
): void {
  McpReportPanel.createOrShow(
    context.extensionUri,
    result.report,
    getLanguage(),
  );
}
