/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * validateServer Tool
 *
 * Comprehensive validation of an MCP server:
 * - Handshake (initialize/initialized)
 * - Discovery (tools, resources, prompts)
 * - Schema validation
 * - Security scan (12 OWASP-aligned rules)
 * - Quality analysis
 * - Protocol compliance
 */

import {
  MCPValidator,
  createScopedLogger,
  StdioTransport,
  translations,
  Language,
} from "@mcp-verify/core";
import { formatForLLM } from "../utils/llm-formatter.js";
import { ReportingService } from "@mcp-verify/shared";

const logger = createScopedLogger("validateServerTool");
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || "en";
const t = translations[lang];

interface ValidateServerArgs {
  command: string;
  args?: string[];
  configPath?: string;
}

interface ValidateServerResult {
  content: Array<{
    type: "text";
    text: string;
  }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/**
 * Execute comprehensive validation on an MCP server
 */
export async function validateServerTool(
  args: unknown,
): Promise<ValidateServerResult> {
  const {
    command,
    args: serverArgs = [],
    configPath,
  } = args as ValidateServerArgs;

  logger.info("Starting validateServer", {
    metadata: {
      command,
      args: serverArgs,
      configPath,
    },
  });

  try {
    // Create transport
    const transport = StdioTransport.create(command, serverArgs);

    // Create validator
    const validator = new MCPValidator(transport, configPath);

    // Run complete validation workflow
    logger.info("Testing handshake");
    const handshake = await validator.testHandshake();

    if (!handshake.success) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "error",
                error: handshake.error || t.mcp_error_handshake_failed,
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

    logger.info("Discovering capabilities");
    const discovery = await validator.discoverCapabilities();

    logger.info("Validating schemas");
    const validation = await validator.validateSchema();

    logger.info("Generating comprehensive report");
    const report = await validator.generateReport({
      handshake,
      discovery,
      validation,
    });

    // Cleanup
    validator.cleanup();

    // Save report files (like CLI does)
    logger.info("Saving report files");
    const savedReports = await ReportingService.saveReport(
      {
        kind: "validation",
        data: report,
      },
      {
        outputDir: "./reports",
        formats: ["json", "markdown", "html"],
        language: lang,
        filenamePrefix: "mcp-report",
        organizeByFormat: true,
      },
    );

    const savedPaths = savedReports.paths;

    logger.info("Reports saved to disk", {
      metadata: savedPaths as unknown as Record<string, unknown>,
    });

    // Format response for LLM consumption
    const llmOutput = formatForLLM(report);

    // Add server metadata
    const response = {
      ...llmOutput,
      serverInfo: {
        name: report.server_name,
        protocolVersion: report.protocol_version,
        duration: `${report.duration_ms}ms`,
      },
      badges: report.badges,
    };

    logger.info("Validation completed successfully", {
      metadata: {
        status: report.status,
        recommendation: llmOutput.recommendation,
        securityScore: report.security.score,
        qualityScore: report.quality.score,
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
    logger.error("Validation failed", error as Error);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              status: "error",
              error: (error as Error).message,
              message: t.mcp_error_failed_to_validate,
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
