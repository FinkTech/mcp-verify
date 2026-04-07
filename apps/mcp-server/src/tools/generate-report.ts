/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * generateReport Tool
 *
 * Generate detailed validation report:
 * - Full validation report in JSON/SARIF format
 * - Can save to file or return as text
 * - Includes all findings, scores, and badges
 */

import {
  MCPValidator,
  SarifGenerator,
  createScopedLogger,
  StdioTransport,
  translations,
  Language,
  SecurityFinding,
  QualityIssue,
  Report,
} from "@mcp-verify/core";
import { MarkdownReportGenerator } from "@mcp-verify/core/domain/reporting/markdown-generator";
import { formatForLLM } from "../utils/llm-formatter";
import * as fs from "fs";
import * as path from "path";

const logger = createScopedLogger("generateReportTool");
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || "en";
const t = translations[lang];

interface GenerateReportArgs {
  command: string;
  args?: string[];
  format?: "json" | "sarif" | "text" | "markdown";
  outputPath?: string;
}

interface GenerateReportResult {
  content: Array<{
    type: "text";
    text: string;
  }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/**
 * Generate a detailed validation report
 */
export async function generateReportTool(
  args: unknown,
): Promise<GenerateReportResult> {
  const {
    command,
    args: serverArgs = [],
    format = "json",
    outputPath,
  } = args as GenerateReportArgs;

  logger.info("Starting generateReport", {
    metadata: {
      command,
      args: serverArgs,
      format,
      outputPath,
    },
  });

  try {
    // Create transport
    const transport = StdioTransport.create(command, serverArgs);

    // Create validator
    const validator = new MCPValidator(transport);

    // Run complete validation
    logger.info("Running complete validation");
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
                message: t.mcp_error_failed_to_connect,
              },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }

    const discovery = await validator.discoverCapabilities();
    const validation = await validator.validateSchema();

    logger.info("Generating report");
    const report = await validator.generateReport({
      handshake,
      discovery,
      validation,
    });

    // Cleanup
    validator.cleanup();

    // Format report based on requested format
    let reportContent: string;
    let fileExtension: string;
    let subfolder: string;

    switch (format) {
      case "sarif":
        const sarifReport = SarifGenerator.generate(report);
        reportContent = JSON.stringify(sarifReport, null, 2);
        fileExtension = ".sarif";
        subfolder = "json";
        break;

      case "text":
        reportContent = formatTextReport(report);
        fileExtension = ".txt";
        subfolder = "text";
        break;

      case "markdown":
        reportContent = MarkdownReportGenerator.generate(report, lang);
        fileExtension = ".md";
        subfolder = "md";
        break;

      case "json":
      default:
        reportContent = JSON.stringify(report, null, 2);
        fileExtension = ".json";
        subfolder = "json";
        break;
    }

    // Determine output path (default or custom)
    let fullPath = outputPath;

    if (!fullPath) {
      // Default structure: reportes/{subfolder}/{timestamp}-report.{ext}
      const reportDir = path.join(process.cwd(), "reportes", subfolder);

      if (!fs.existsSync(reportDir)) {
        fs.mkdirSync(reportDir, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const safeName = report.server_name.replace(/[^a-zA-Z0-9]/g, "-");
      const filename = `report-${safeName}-${timestamp}${fileExtension}`;
      fullPath = path.join(reportDir, filename);
    } else {
      // Ensure directory exists for custom path
      const dir = path.dirname(fullPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      if (!fullPath.endsWith(fileExtension)) {
        fullPath += fileExtension;
      }
    }

    // Always save to file
    fs.writeFileSync(fullPath, reportContent, "utf-8");

    logger.info("Report saved to file", {
      metadata: {
        path: fullPath,
        format,
        size: reportContent.length,
      },
    });

    // Return LLM-friendly summary when saving JSON report
    if (format === "json") {
      const llmOutput = formatForLLM(report);
      const { status: validationStatus, ...llmRest } = llmOutput;

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "success",
                validationStatus,
                message: `Report saved to ${fullPath}`,
                savedFormat: format,
                fileSize: reportContent.length,
                ...llmRest,
                serverInfo: {
                  name: report.server_name,
                  protocolVersion: report.protocol_version,
                },
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    // For Markdown, SARIF and text, return simple confirmation
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              status: "success",
              message: `Report saved to ${fullPath}`,
              format,
              size: reportContent.length,
              summary: {
                serverName: report.server_name,
                status: report.status,
                securityScore: report.security.score,
                qualityScore: report.quality.score,
              },
            },
            null,
            2,
          ),
        },
      ],
    };
  } catch (error) {
    logger.error("Report generation failed", error as Error);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              status: "error",
              error: (error as Error).message,
              message: t.mcp_error_failed_to_generate_report,
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

/**
 * Format report as human-readable text
 */
function formatTextReport(report: Report): string {
  const lines: string[] = [];

  lines.push("=".repeat(80));
  lines.push(`MCP VERIFY REPORT - ${report.server_name}`);
  lines.push("=".repeat(80));
  lines.push("");

  lines.push(`Status: ${report.status.toUpperCase()}`);
  lines.push(`Protocol Version: ${report.protocol_version}`);
  lines.push(`Duration: ${report.duration_ms}ms`);
  lines.push(`Timestamp: ${report.timestamp}`);
  lines.push("");

  lines.push("-".repeat(80));
  lines.push("CAPABILITIES");
  lines.push("-".repeat(80));
  lines.push(
    `Tools: ${report.tools.count} (${report.tools.valid} valid, ${report.tools.invalid} invalid)`,
  );
  lines.push(
    `Resources: ${report.resources.count} (${report.resources.valid} valid, ${report.resources.invalid} invalid)`,
  );
  lines.push(
    `Prompts: ${report.prompts.count} (${report.prompts.valid} valid, ${report.prompts.invalid} invalid)`,
  );
  lines.push("");

  lines.push("-".repeat(80));
  lines.push("SECURITY SCAN");
  lines.push("-".repeat(80));
  lines.push(`Score: ${report.security.score}/100`);
  lines.push(`Total Findings: ${report.security.findings?.length || 0}`);
  lines.push(`  Critical: ${report.security.criticalCount || 0}`);
  lines.push(`  High: ${report.security.highCount || 0}`);
  lines.push(`  Medium: ${report.security.mediumCount || 0}`);
  lines.push(`  Low: ${report.security.lowCount || 0}`);
  lines.push("");

  if (report.security.findings && report.security.findings.length > 0) {
    lines.push("Findings:");
    (report.security.findings as SecurityFinding[]).forEach(
      (f: SecurityFinding, i: number) => {
        lines.push(`  ${i + 1}. [${f.severity.toUpperCase()}] ${f.message}`);
        lines.push(`     Component: ${f.component}`);
        if (f.remediation) {
          lines.push(`     Fix: ${f.remediation}`);
        }
        lines.push("");
      },
    );
  }

  lines.push("-".repeat(80));
  lines.push("QUALITY ANALYSIS");
  lines.push("-".repeat(80));
  lines.push(`Score: ${report.quality.score}/100`);
  lines.push(`Total Issues: ${report.quality.issues?.length || 0}`);
  lines.push("");

  if (report.quality.issues && report.quality.issues.length > 0) {
    lines.push("Issues:");
    (report.quality.issues as QualityIssue[]).forEach(
      (i: QualityIssue, idx: number) => {
        lines.push(`  ${idx + 1}. [${i.severity.toUpperCase()}] ${i.message}`);
        lines.push(`     Component: ${i.component}`);
        if (i.suggestion) {
          lines.push(`     Suggestion: ${i.suggestion}`);
        }
        lines.push("");
      },
    );
  }

  if (report.protocolCompliance) {
    lines.push("-".repeat(80));
    lines.push("PROTOCOL COMPLIANCE");
    lines.push("-".repeat(80));
    lines.push(
      `Tests Passed: ${report.protocolCompliance.testsPassed ?? 0}/${report.protocolCompliance.totalTests ?? 0}`,
    );
    lines.push(`Tests Failed: ${report.protocolCompliance.testsFailed ?? 0}`);
    lines.push("");
  }

  lines.push("=".repeat(80));
  lines.push("END OF REPORT");
  lines.push("=".repeat(80));

  return lines.join("\n");
}
