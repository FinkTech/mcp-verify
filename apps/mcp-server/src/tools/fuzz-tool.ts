/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * fuzzTool - Selective Fuzzing for Specific Tools
 *
 * Enables targeted security fuzzing of a single MCP tool instead of the entire server.
 * Perfect for agents that detect suspicious tools and want to verify their security
 * without running a full fuzzing campaign.
 *
 * Use case: "This query_db tool looks suspicious, let me fuzz it specifically"
 */

import {
  MCPValidator,
  createScopedLogger,
  StdioTransport,
  translations,
  Language,
  type DiscoveryResult,
} from "@mcp-verify/core";
import { SmartFuzzer } from "@mcp-verify/core/use-cases/fuzzer/fuzzer";
import type { McpTool } from "@mcp-verify/core/domain/shared/common.types";
import { formatForLLM } from "../utils/llm-formatter.js";

const logger = createScopedLogger("fuzzToolTool");
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || "en";
const t = translations[lang];

interface FuzzToolArgs {
  command: string;
  args?: string[];
  toolName: string;
  profile?: "light" | "balanced" | "aggressive";
  maxDuration?: number;
}

interface FuzzToolResult {
  content: Array<{
    type: "text";
    text: string;
  }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/**
 * Execute selective fuzzing on a specific tool
 */
export async function fuzzToolTool(args: unknown): Promise<FuzzToolResult> {
  const {
    command,
    args: serverArgs = [],
    toolName,
    profile = "balanced",
    maxDuration = 120,
  } = args as FuzzToolArgs;

  logger.info("Starting fuzzTool", {
    metadata: {
      command,
      args: serverArgs,
      toolName,
      profile,
      maxDuration,
    },
  });

  try {
    // Create transport
    const transport = StdioTransport.create(command, serverArgs);

    // Create validator
    const validator = new MCPValidator(transport);

    // Test handshake
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

    // Discover capabilities
    logger.info("Discovering capabilities to find target tool");
    const discovery = await validator.discoverCapabilities();

    // Find the target tool
    const targetTool = discovery.tools?.find((tool) => tool.name === toolName);

    if (!targetTool) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "error",
                error: `Tool "${toolName}" not found`,
                message: `Available tools: ${discovery.tools?.map((t) => t.name).join(", ") || "none"}`,
                availableTools: discovery.tools?.map((t) => t.name) || [],
              },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }

    // Configure fuzzer based on profile
    const fuzzConfig = {
      light: {
        useSecurityPayloads: true,
        useMutations: false,
        mutationsPerPayload: 0,
        analyzeResponses: true,
        detectVulnerabilities: true,
        timeout: 30000,
        delayBetweenTests: 100,
      },
      balanced: {
        useSecurityPayloads: true,
        useMutations: true,
        mutationsPerPayload: 3,
        analyzeResponses: true,
        detectVulnerabilities: true,
        timeout: 60000,
        delayBetweenTests: 50,
      },
      aggressive: {
        useSecurityPayloads: true,
        useMutations: true,
        mutationsPerPayload: 5,
        analyzeResponses: true,
        detectVulnerabilities: true,
        timeout: 120000,
        delayBetweenTests: 0,
      },
    }[profile];

    logger.info(`Fuzzing tool "${toolName}" with ${profile} profile`);

    // Create fuzzer
    const fuzzer = new SmartFuzzer(transport, fuzzConfig);

    // Create discovery result with only the target tool
    const filteredDiscovery: DiscoveryResult = {
      tools: [targetTool],
      resources: [],
      prompts: [],
    };

    // Execute fuzzing on single tool
    const startTime = Date.now();
    const fuzzingResult = await fuzzer.run(filteredDiscovery);
    const executionTime = Math.round((Date.now() - startTime) / 1000);

    // Extract vulnerabilities found (flatten findings from all payloads)
    const vulnerabilities = fuzzingResult.vulnerabilities || [];
    const allFindings = vulnerabilities.flatMap((v) => v.findings);
    const criticalVulns = allFindings.filter((f) => f.severity === "critical");
    const highVulns = allFindings.filter((f) => f.severity === "high");
    const mediumVulns = allFindings.filter((f) => f.severity === "medium");

    // Cleanup
    validator.cleanup();

    // Format response for LLM
    const response = {
      status: criticalVulns.length > 0 ? "vulnerable" : "completed",
      recommendation:
        criticalVulns.length > 0
          ? "blocking_issues"
          : highVulns.length > 0
            ? "review_required"
            : "safe",

      llm_summary:
        `🎯 Fuzzing completed for tool "${toolName}" in ${executionTime}s. ` +
        `Found ${allFindings.length} potential vulnerabilities: ` +
        `${criticalVulns.length} CRITICAL, ${highVulns.length} HIGH, ${mediumVulns.length} MEDIUM.` +
        (criticalVulns.length > 0
          ? " ⚠️  CRITICAL vulnerabilities detected - DO NOT USE this tool in production!"
          : highVulns.length > 0
            ? " ⚡ HIGH severity issues found - review and fix before deployment."
            : " ✅ No critical issues detected, but verify findings."),

      fuzzing_stats: {
        tool: toolName,
        profile,
        payloads_tested: fuzzingResult.totalTests,
        mutations_used: fuzzConfig.useMutations
          ? fuzzConfig.mutationsPerPayload
          : 0,
        execution_time_seconds: executionTime,
        max_duration_seconds: maxDuration,
        failed_tests: fuzzingResult.failedTests,
        crashes: fuzzingResult.crashes,
      },

      vulnerabilities_found: {
        total: allFindings.length,
        critical: criticalVulns.length,
        high: highVulns.length,
        medium: mediumVulns.length,
      },

      top_findings: allFindings.slice(0, 5).map((f) => ({
        severity: f.severity,
        type: f.type,
        description: f.description,
        evidence: f.evidence.substring(0, 100),
        remediation: f.remediation,
      })),

      next_steps:
        allFindings.length > 0
          ? [
              ...criticalVulns.map(
                (v) => `FIX CRITICAL: ${v.description} - ${v.remediation}`,
              ),
              ...highVulns
                .slice(0, 3)
                .map((v) => `FIX HIGH: ${v.description} - ${v.remediation}`),
              `Re-run fuzzing after fixes: fuzzTool({command: "${command}", toolName: "${toolName}", profile: "${profile}"})`,
            ]
          : [
              `✅ No vulnerabilities found in initial fuzzing`,
              `Consider running aggressive profile for deeper testing: fuzzTool({..., profile: "aggressive"})`,
              `Validate the entire server: validateServer({command: "${command}"})`,
            ],
    };

    logger.info("Fuzzing completed", {
      metadata: {
        vulnerabilitiesFound: allFindings.length,
        executionTime,
      },
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(response, null, 2),
        },
      ],
      _meta: {
        toolName,
        profile,
        vulnerabilitiesCount: allFindings.length,
        executionTimeSeconds: executionTime,
      },
    };
  } catch (error) {
    logger.error("fuzzTool failed", error as Error);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              status: "error",
              error: (error as Error).message,
              message: "Fuzzing failed",
              stack:
                process.env.NODE_ENV === "development"
                  ? (error as Error).stack
                  : undefined,
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
