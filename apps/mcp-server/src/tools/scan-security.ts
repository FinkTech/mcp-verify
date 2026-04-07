/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * scanSecurity Tool
 *
 * Security-focused scan of an MCP server:
 * - Runs 60 comprehensive security rules
 * - Detects vulnerabilities (SQL injection, XSS, SSRF, etc.)
 * - Returns security score and findings
 */

import {
  MCPValidator,
  SecurityScanner,
  createScopedLogger,
  DEFAULT_CONFIG,
  StdioTransport,
  translations,
  Language,
  Report,
} from "@mcp-verify/core";
import { formatForLLM } from "../utils/llm-formatter.js";
import { ReportingService } from "@mcp-verify/shared";

const logger = createScopedLogger("scanSecurityTool");
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || "en";
const t = translations[lang];

interface ScanSecurityArgs {
  command: string;
  args?: string[];
  rules?: string[];
}

interface ScanSecurityResult {
  content: Array<{
    type: "text";
    text: string;
  }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/**
 * Execute security scan on an MCP server
 */
export async function scanSecurityTool(
  args: unknown,
): Promise<ScanSecurityResult> {
  const { command, args: serverArgs = [], rules } = args as ScanSecurityArgs;

  logger.info("Starting scanSecurity", {
    metadata: {
      command,
      args: serverArgs,
      rules: rules || "all",
    },
  });

  try {
    // Create transport
    const transport = StdioTransport.create(command, serverArgs);

    // Create validator
    const validator = new MCPValidator(transport);

    // Connect and discover
    logger.info("Connecting to server");
    const handshake = await validator.testHandshake();

    if (!handshake.success) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "error",
                error: handshake.error || t.mcp_error_connection_failed,
                message: t.mcp_error_failed_to_connect_security,
              },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }

    logger.info("Discovering capabilities");
    const discovery = await validator.discoverCapabilities();

    // Run security scan
    logger.info("Running security scan");
    const scanner = new SecurityScanner(DEFAULT_CONFIG);
    const securityReport = scanner.scan(discovery);

    // Filter by specific rules if requested
    let findings = securityReport.findings || [];
    if (rules && rules.length > 0) {
      findings = findings.filter((f) => rules.includes(f.ruleCode || ""));
    }

    // Cleanup
    validator.cleanup();

    // Save report files (like CLI does)
    logger.info("Saving security report files");

    // Build minimal Report structure for LLM formatting
    const miniReport: Report = {
      status: "valid",
      server_name: handshake.serverName || t.mcp_unknown_server,
      url: command,
      protocol_version: handshake.protocolVersion || "N/A",
      timestamp: new Date().toISOString(),
      duration_ms: 0,

      // Security results
      security: {
        score: securityReport.score,
        level: securityReport.level || t.risk_level_low,
        findings: findings,
        criticalCount: findings.filter((f) => f.severity === "critical").length,
        highCount: findings.filter((f) => f.severity === "high").length,
        mediumCount: findings.filter((f) => f.severity === "medium").length,
        lowCount: findings.filter((f) => f.severity === "low").length,
        infoCount: findings.filter((f) => f.severity === "info").length,
      },

      // Capabilities from discovery
      tools: {
        count: discovery.tools?.length || 0,
        valid: discovery.tools?.length || 0,
        invalid: 0,
        items: (discovery.tools || []).map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
          status: "valid" as const,
        })),
      },
      resources: {
        count: discovery.resources?.length || 0,
        valid: discovery.resources?.length || 0,
        invalid: 0,
        items: (discovery.resources || []).map((r) => ({
          ...r,
          status: "valid" as const,
        })),
      },
      prompts: {
        count: discovery.prompts?.length || 0,
        valid: discovery.prompts?.length || 0,
        invalid: 0,
        items: (discovery.prompts || []).map((p) => ({
          ...p,
          status: "valid" as const,
        })),
      },

      // Quality (not scanned, use defaults)
      quality: {
        score: 100,
        issues: [],
      },

      // Protocol compliance (not scanned, assume passed)
      protocolCompliance: {
        passed: true,
        score: 100,
        issues: [],
      },

      badges: undefined,
      metadata: {
        toolVersion: "1.0.0",
        modulesExecuted: ["security"],
        llmUsed: false,
      },
    };

    // Save files to disk
    const savedReports = await ReportingService.saveReport(
      {
        kind: "validation",
        data: miniReport,
      },
      {
        outputDir: "./reports",
        formats: ["json", "markdown", "html"],
        language: lang,
        filenamePrefix: "mcp-security",
        organizeByFormat: true,
      },
    );

    const savedPaths = savedReports.paths;

    logger.info("Security reports saved to disk", {
      metadata: savedPaths as unknown as Record<string, unknown>,
    });

    // Format for LLM consumption
    const llmOutput = formatForLLM(miniReport);

    // Add scan metadata
    const response = {
      ...llmOutput,
      serverInfo: {
        name: handshake.serverName || t.mcp_unknown_server,
        protocolVersion: handshake.protocolVersion || "N/A",
      },
      scannedRules: rules || "all",
    };

    logger.info("Security scan completed", {
      metadata: {
        score: securityReport.score,
        findings: findings.length,
        recommendation: llmOutput.recommendation,
      },
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(response, null, 2),
        },
      ],
    };
  } catch (error) {
    logger.error("Security scan failed", error as Error);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              status: "error",
              error: (error as Error).message,
              message: t.mcp_error_failed_to_scan_security,
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }
}
