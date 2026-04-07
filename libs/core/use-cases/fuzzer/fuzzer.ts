/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import {
  t,
  normalizeCommand,
  normalizeArguments,
  detectDangerousPatterns,
} from "@mcp-verify/shared";
import type { ITransport } from "../../domain/transport";
import type {
  DiscoveryResult,
  FuzzingReport,
  FuzzingResult,
} from "../../domain/mcp-server/entities/validation.types";
import type { McpTool, JsonObject } from "../../domain/shared/common.types";
import {
  getAllPayloads,
  getPayloadsByType,
  getRandomPayloads,
  ATTACK_PAYLOADS,
} from "./payloads";
import type { AttackPayload } from "./payloads";
import { ResponseAnalyzer } from "./response-analyzer";
import type { AnalysisResult } from "./response-analyzer";
import { MutationEngine, BatchMutator } from "./mutation-engine";
import type { MutatedPayload } from "./mutation-engine";

/**
 * Type-safe definitions for fuzzer internals
 */
type ToolArguments = JsonObject;

type ToolCallResponse = ToolCallSuccess | ToolCallError;

interface ToolCallSuccess {
  result: unknown;
  error?: never;
}

interface ToolCallError {
  result?: never;
  error: {
    code: number;
    message: string;
  };
}

interface FuzzPayload {
  type: string;
  args: ToolArguments;
  attackPayload?: AttackPayload;
}

interface JSONSchemaProperty {
  type?: "string" | "integer" | "number" | "boolean" | "object" | "array";
  pattern?: string;
  minimum?: number;
  maximum?: number;
  items?: JSONSchemaProperty;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
  description?: string;
}

/**
 * Safety Blacklist: Commands and patterns that should NEVER be executed during fuzzing
 * Prevents accidental execution of destructive operations even if a mutation generates them
 */
const DANGEROUS_COMMANDS = [
  "rm -rf",
  "rm -fr",
  "del /s",
  "format",
  "mkfs",
  "dd if=",
  "DROP TABLE",
  "DROP DATABASE",
  "TRUNCATE",
  "DELETE FROM",
  ":(){:|:&};:", // Fork bomb
  "wget",
  "curl",
  "> /dev/sda",
  "chmod 777",
  "chmod -R 777",
] as const;

export interface FuzzerConfig {
  // Advanced fuzzing (v1.0)
  useSecurityPayloads: boolean;
  useMutations: boolean;
  mutationsPerPayload: number;

  // Payload filtering
  payloadTypes?: string[]; // Only use specific types (e.g., ['sqli', 'xss'])
  maxSeverity?: "critical" | "high" | "medium" | "low";

  // Response analysis
  analyzeResponses: boolean;
  detectVulnerabilities: boolean;

  // Performance
  timeout: number;
  delayBetweenTests: number;
}

export class SmartFuzzer {
  private transport: ITransport;
  private requestId = 5000;

  // v1.0 Components
  private responseAnalyzer: ResponseAnalyzer;
  private mutationEngine: MutationEngine;
  private batchMutator: BatchMutator;

  // Configuration
  private config: FuzzerConfig;

  constructor(transport: ITransport, config?: Partial<FuzzerConfig>) {
    this.transport = transport;
    this.responseAnalyzer = new ResponseAnalyzer();
    this.mutationEngine = new MutationEngine();
    this.batchMutator = new BatchMutator();

    // Default configuration
    this.config = {
      useSecurityPayloads: true,
      useMutations: false,
      mutationsPerPayload: 3,
      analyzeResponses: true,
      detectVulnerabilities: true,
      timeout: 5000,
      delayBetweenTests: 100,
      ...config,
    };
  }

  /**
   * Safety Check: Validates that a payload does not contain dangerous commands
   * This prevents accidental execution of destructive operations during fuzzing
   *
   * Uses multi-layered detection:
   * 1. Command normalization to defeat obfuscation (whitespace, shell vars, encoding)
   * 2. Static blacklist check (legacy compatibility)
   * 3. Pattern-based detection (shell metacharacters, dangerous operations)
   *
   * @param args - The payload arguments to validate
   * @returns Object with safety status and reason if dangerous
   */
  private isSafePayload(args: Record<string, unknown>): {
    safe: boolean;
    reason?: string;
  } {
    // Layer 1: Normalize all arguments to detect obfuscated commands
    const normalizedArgs = normalizeArguments(args);

    // Layer 2: Check normalized args against static blacklist (backwards compatibility)
    for (const normalized of normalizedArgs) {
      for (const dangerousCmd of DANGEROUS_COMMANDS) {
        if (normalized.includes(dangerousCmd.toLowerCase())) {
          return {
            safe: false,
            reason: `Blacklist match: "${dangerousCmd}" detected in normalized payload`,
          };
        }
      }
    }

    // Layer 3: Pattern-based detection on normalized commands
    for (const normalized of normalizedArgs) {
      const detectedPatterns = detectDangerousPatterns(normalized);
      if (detectedPatterns.length > 0) {
        return {
          safe: false,
          reason: `Dangerous patterns detected: ${detectedPatterns.join(", ")}`,
        };
      }
    }

    // Layer 4: Raw check (in case normalization removed something important)
    const argsString = JSON.stringify(args).toLowerCase();
    for (const dangerousCmd of DANGEROUS_COMMANDS) {
      if (argsString.includes(dangerousCmd.toLowerCase())) {
        return {
          safe: false,
          reason: `Blacklist match in raw payload: "${dangerousCmd}"`,
        };
      }
    }

    return { safe: true };
  }

  async run(discovery: DiscoveryResult): Promise<FuzzingReport> {
    const report: FuzzingReport = {
      executed: true,
      totalTests: 0,
      failedTests: 0,
      crashes: 0,
      results: [],
      vulnerabilities: [], // v1.0: Track detected vulnerabilities
    };

    if (!discovery.tools) return report;

    // Connect just in case (though validator usually connects)
    try {
      await this.transport.connect();
    } catch (e) {
      // ignore if already connected
    }

    // Calibrate baseline response time
    if (this.config.analyzeResponses && discovery.tools.length > 0) {
      const baselineTime = await this.calibrateBaseline(
        discovery.tools[0].name,
      );
      this.responseAnalyzer.setBaselineResponseTime(baselineTime);
    }

    for (const tool of discovery.tools) {
      // Generate all payloads for this tool
      const allPayloads = this.generateAllPayloads(tool);

      for (const payload of allPayloads) {
        report.totalTests++;

        // Safety Check: Skip dangerous payloads
        const safetyCheck = this.isSafePayload(payload.args);
        if (!safetyCheck.safe) {
          // Log skipped dangerous payload (but don't execute it)
          report.results.push({
            toolName: tool.name,
            input: payload.args,
            payloadType: payload.type,
            passed: true, // Mark as "passed" since we safely skipped it
            durationMs: 0,
            skipped: true,
            skipReason: safetyCheck.reason || t("fuzz_dangerous_detected"),
          });
          continue;
        }

        // Execute test
        const result = await this.executeFuzzTest(
          tool.name,
          payload.args,
          payload.type,
          payload.attackPayload,
        );
        report.results.push(result);

        // Track failures
        if (!result.passed) {
          report.failedTests++;
          if (
            result.serverError &&
            result.serverError.includes("Connection closed")
          ) {
            report.crashes++;
          }
        }

        // Track vulnerabilities
        if (
          result.vulnerabilityAnalysis &&
          result.vulnerabilityAnalysis.vulnerable
        ) {
          report.vulnerabilities = report.vulnerabilities || [];
          report.vulnerabilities.push({
            toolName: tool.name,
            payloadType: payload.type,
            findings: result.vulnerabilityAnalysis.findings,
          });
        }

        // Delay between tests to avoid overwhelming the server
        if (this.config.delayBetweenTests > 0) {
          await this.sleep(this.config.delayBetweenTests);
        }
      }
    }

    return report;
  }

  private async executeFuzzTest(
    toolName: string,
    args: ToolArguments,
    payloadType: string,
    attackPayload?: AttackPayload,
  ): Promise<FuzzingResult> {
    const start = Date.now();
    let response: unknown = null;
    const statusCode: number | undefined = undefined;

    try {
      // Send the fuzz test
      response = await this.transport.send({
        jsonrpc: "2.0",
        id: this.requestId++,
        method: "tools/call",
        params: {
          name: toolName,
          arguments: args,
        },
      });

      const durationMs = Date.now() - start;

      // Analyze response for vulnerabilities (v1.0)
      let vulnerabilityAnalysis: AnalysisResult | undefined;
      if (this.config.analyzeResponses && attackPayload) {
        vulnerabilityAnalysis = this.responseAnalyzer.analyze(
          attackPayload,
          response,
          durationMs,
          statusCode,
        );
      }

      return {
        toolName,
        input: args,
        payloadType,
        passed: true,
        durationMs,
        vulnerabilityAnalysis,
      };
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      const durationMs = Date.now() - start;
      const isCrash =
        msg.includes("Socket closed") || msg.includes("ECONNRESET");

      // Analyze error response for vulnerabilities
      let vulnerabilityAnalysis: AnalysisResult | undefined;
      if (this.config.analyzeResponses && attackPayload) {
        // Analyze the error message as the "response"
        vulnerabilityAnalysis = this.responseAnalyzer.analyze(
          attackPayload,
          { error: msg },
          durationMs,
          statusCode,
        );
      }

      return {
        toolName,
        input: args,
        payloadType,
        serverError: msg,
        passed: !isCrash, // Only fail if it crashed the transport
        durationMs,
        vulnerabilityAnalysis,
      };
    }
  }

  /**
   * Generate all payloads for a tool (v1.0)
   */
  private generateAllPayloads(tool: McpTool): FuzzPayload[] {
    const allPayloads: FuzzPayload[] = [];

    // Security attack payloads (v1.0)
    if (this.config.useSecurityPayloads) {
      const securityPayloads = this.generateSecurityPayloads(tool);
      allPayloads.push(...securityPayloads);
    }

    return allPayloads;
  }

  /**
   * Generate security attack payloads (v1.0)
   */
  private generateSecurityPayloads(tool: McpTool): Array<{
    type: string;
    args: ToolArguments;
    attackPayload: AttackPayload;
  }> {
    const securityPayloads: Array<{
      type: string;
      args: ToolArguments;
      attackPayload: AttackPayload;
    }> = [];
    if (!tool.inputSchema?.properties) return securityPayloads;

    // Get attack payloads from library
    let attackPayloads: AttackPayload[] = [];

    if (this.config.payloadTypes && this.config.payloadTypes.length > 0) {
      // Use specific payload types
      for (const type of this.config.payloadTypes) {
        // Validate type is a valid payload type
        if (type in ATTACK_PAYLOADS) {
          attackPayloads.push(
            ...getPayloadsByType(type as keyof typeof ATTACK_PAYLOADS),
          );
        }
      }
    } else {
      // Use all payloads
      attackPayloads = getAllPayloads();
    }

    // Filter by severity if configured
    if (this.config.maxSeverity) {
      const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
      const maxSeverityLevel = severityOrder[this.config.maxSeverity];
      attackPayloads = attackPayloads.filter(
        (p) => severityOrder[p.severity] <= maxSeverityLevel,
      );
    }

    // Inject attack payloads into each string parameter
    for (const [key, prop] of Object.entries(tool.inputSchema.properties) as [
      string,
      JSONSchemaProperty,
    ][]) {
      if (prop.type === "string") {
        for (const attackPayload of attackPayloads) {
          const args = { ...this.generateValidMock(tool.inputSchema) };
          args[key] = attackPayload.value;

          securityPayloads.push({
            type: t("fuzz_security_attack", { type: attackPayload.type, key }),
            args,
            attackPayload,
          });

          // Apply mutations if enabled
          if (this.config.useMutations) {
            const mutations = this.mutationEngine.mutate(
              attackPayload,
              this.config.mutationsPerPayload,
            );

            for (const mutation of mutations) {
              const mutatedArgs = {
                ...this.generateValidMock(tool.inputSchema),
              };
              mutatedArgs[key] = mutation.value;

              securityPayloads.push({
                type: t("fuzz_mutated_attack", {
                  mutation: mutation.mutationType || "unknown",
                  type: attackPayload.type,
                  key,
                }),
                args: mutatedArgs,
                attackPayload: mutation,
              });
            }
          }
        }
      }
    }

    return securityPayloads;
  }

  private generateValidMock(schema: McpTool["inputSchema"]): ToolArguments {
    // Very basic mock generator to create a "base" valid object to corrupt
    const mock: ToolArguments = {};
    if (!schema.properties) return mock;

    for (const [key, prop] of Object.entries(schema.properties) as [
      string,
      JSONSchemaProperty,
    ][]) {
      if (prop.type === "string") mock[key] = "test";
      else if (prop.type === "integer" || prop.type === "number") mock[key] = 1;
      else if (prop.type === "boolean") mock[key] = true;
    }
    return mock;
  }

  /**
   * Calibrate baseline response time by making a benign request
   */
  private async calibrateBaseline(toolName: string): Promise<number> {
    const start = Date.now();
    try {
      await this.transport.send({
        jsonrpc: "2.0",
        id: this.requestId++,
        method: "tools/call",
        params: {
          name: toolName,
          arguments: {},
        },
      });
    } catch (e) {
      // Ignore errors, we're just measuring time
    }
    return Date.now() - start;
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Update fuzzer configuration
   */
  configure(config: Partial<FuzzerConfig>) {
    Object.assign(this.config, config);
  }

  /**
   * Get current configuration
   */
  getConfig(): FuzzerConfig {
    return { ...this.config };
  }
}
