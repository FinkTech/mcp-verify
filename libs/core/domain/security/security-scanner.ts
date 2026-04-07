/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import * as fs from "fs";
import * as path from "path";
import { t } from "@mcp-verify/shared";
import type {
  DiscoveryResult,
  SecurityFinding,
  SecurityReport,
} from "../mcp-server/entities/validation.types";
import { PathTraversalRule } from "./rules/path-traversal.rule";
import { CommandInjectionRule } from "./rules/command-injection.rule";
import { SSRFDetectionRule } from "./rules/ssrf.rule";
import { DataLeakageRule } from "./rules/data-leakage.rule";
import { XXEInjectionRule } from "./rules/xxe-injection.rule";
import { InsecureDeserializationRule } from "./rules/insecure-deserialization.rule";
import { SQLInjectionRule } from "./rules/sql-injection.rule";
import { ReDoSDetectionRule } from "./rules/redos-detection.rule";
import { AuthenticationBypassRule } from "./rules/auth-bypass.rule";
import { SensitiveDataExposureRule } from "./rules/sensitive-exposure.rule";
import { RateLimitingRule } from "./rules/rate-limiting.rule";
import { WeakCryptographyRule } from "./rules/weak-crypto.rule";
import { PromptInjectionRule } from "./rules/prompt-injection.rule";
import { ExposedEndpointRule } from "./rules/exposed-endpoint.rule";
import { MissingAuthenticationRule } from "./rules/missing-authentication.rule";
import { InsecureURISchemeRule } from "./rules/insecure-uri-scheme.rule";
import { ExcessivePermissionsRule } from "./rules/excessive-permissions.rule";
import { SecretsInDescriptionsRule } from "./rules/secrets-in-descriptions.rule";
import { MissingInputConstraintsRule } from "./rules/missing-input-constraints.rule";
import { DangerousToolChainingRule } from "./rules/dangerous-tool-chaining.rule";
import { UnencryptedCredentialsRule } from "./rules/unencrypted-credentials.rule";
import { MissingAuditLoggingRule } from "./rules/missing-audit-logging.rule";
import { InsecureOutputHandlingRule } from "./rules/insecure-output-handling.rule";
import { ExcessiveAgencyRule } from "./rules/excessive-agency.rule";
import { PromptInjectionViaToolsRule } from "./rules/prompt-injection-via-tools.rule";
import { SupplyChainToolDepsRule } from "./rules/supply-chain-tool-deps.rule";
import { SensitiveDataInToolResponsesRule } from "./rules/sensitive-data-in-tool-responses.rule";
import { TrainingDataPoisoningRule } from "./rules/training-data-poisoning.rule";
import { ModelDosViaToolsRule } from "./rules/model-dos-via-tools.rule";
import { InsecurePluginDesignRule } from "./rules/insecure-plugin-design.rule";
import { ExcessiveDataDisclosureRule } from "./rules/excessive-data-disclosure.rule";
import { AgentIdentitySpoofingRule } from "./rules/agent-identity-spoofing.rule";
import { ToolResultTamperingRule } from "./rules/tool-result-tampering.rule";
import { RecursiveAgentLoopRule } from "./rules/recursive-agent-loop.rule";
import { MultiAgentPrivilegeEscalationRule } from "./rules/multi-agent-privilege-escalation.rule";
import { AgentStatePoisoningRule } from "./rules/agent-state-poisoning.rule";
import { DistributedAgentDdosRule } from "./rules/distributed-agent-ddos.rule";
import { CrossAgentPromptInjectionRule } from "./rules/cross-agent-prompt-injection.rule";
import { AgentReputationHijackingRule } from "./rules/agent-reputation-hijacking.rule";
import { ToolChainingPathTraversalRule } from "./rules/tool-chaining-path-traversal.rule";
import { AgentSwarmCoordinationAttackRule } from "./rules/agent-swarm-coordination-attack.rule";
import { AgentMemoryInjectionRule } from "./rules/agent-memory-injection.rule";
import { InsecureSessionManagementRule } from "./rules/insecure-session-management.rule";
import { SchemaVersioningAbsentRule } from "./rules/schema-versioning-absent.rule";
import { InsufficientErrorGranularityRule } from "./rules/insufficient-error-granularity.rule";
import { MissingCorsValidationRule } from "./rules/missing-cors-validation.rule";
import { InsecureDefaultConfigurationRule } from "./rules/insecure-default-configuration.rule";
import { MissingCapabilityNegotiationRule } from "./rules/missing-capability-negotiation.rule";
import { TimingSideChannelAuthRule } from "./rules/timing-side-channel-auth.rule";
import { InsufficientOutputEntropyRule } from "./rules/insufficient-output-entropy.rule";
import { WeaponizedMcpFuzzerRule } from "./rules/weaponized-mcp-fuzzer.rule";
import { AutonomousMcpBackdoorRule } from "./rules/autonomous-mcp-backdoor.rule";
import { MaliciousConfigFileRule } from "./rules/malicious-config-file.rule";
import { ApiEndpointHijackingRule } from "./rules/api-endpoint-hijacking.rule";
import { JailbreakAsServiceRule } from "./rules/jailbreak-as-service.rule";
import { PhishingViaMcpRule } from "./rules/phishing-via-mcp.rule";
import { DataExfiltrationSteganographyRule } from "./rules/data-exfiltration-steganography.rule";
import { SelfReplicatingMcpRule } from "./rules/self-replicating-mcp.rule";
import { UnvalidatedToolAuthorizationRule } from "./rules/unvalidated-tool-authorization.rule";
import { MissingTransactionSemanticsRule } from "./rules/missing-transaction-semantics.rule";
import { HomoglyphSpoofingRule } from "./rules/homoglyph-spoofing.rule";
import type { ISecurityRule } from "./rule.interface";
import type {
  McpVerifyConfig,
  SecurityRuleBlock,
} from "../config/config.types";
import { DEFAULT_CONFIG, RULE_BLOCK_RANGES } from "../config/config.types";
import { McpIgnoreParser } from "./mcpignore-parser";
import type { IgnoreRule } from "./mcpignore-parser";

// ─────────────────────────────────────────────────────────────────────────────
// SCORING WEIGHTS
// Enterprise-grade scoring with dynamic (fuzzer) vs static differentiation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Base severity penalties for static analysis findings
 * These represent theoretical risk based on pattern detection
 */
const STATIC_SEVERITY_PENALTIES = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
  info: 0,
} as const;

/**
 * Multiplier for dynamically confirmed vulnerabilities (fuzzer findings)
 * Fuzzer-confirmed vulnerabilities represent PROVEN exploitability
 * and should weigh significantly more than theoretical risk
 */
const FUZZER_WEIGHT_MULTIPLIER = 1.75;

/**
 * Confidence-based weight adjustments for fuzzer findings
 * High confidence = proven exploit, Low confidence = possible issue
 */
const FUZZER_CONFIDENCE_WEIGHTS = {
  high: 1.0, // 100% of multiplied penalty
  medium: 0.75, // 75% of multiplied penalty
  low: 0.5, // 50% of multiplied penalty
} as const;

/**
 * Fuzzer finding structure for unified scoring
 */
export interface FuzzerFinding {
  /** Detector ID that found this vulnerability */
  detectorId: string;
  /** Severity level */
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Confidence level from fuzzer */
  confidence: "high" | "medium" | "low";
  /** Tool that was fuzzed */
  toolName: string;
  /** Payload category that triggered the finding */
  payloadCategory?: string;
  /** Description of the vulnerability */
  description: string;
  /** CWE identifier if available */
  cwe?: string;
  /** OWASP reference if available */
  owasp?: string;
  /** Evidence of exploitation */
  evidence?: Record<string, unknown>;
  /** Remediation recommendation */
  remediation?: string;
}

/**
 * Extended security report with scoring breakdown
 */
export interface EnhancedSecurityReport extends SecurityReport {
  /** Breakdown of score by source */
  scoreBreakdown?: {
    /** Starting score */
    baseScore: number;
    /** Penalty from static analysis */
    staticPenalty: number;
    /** Penalty from fuzzer findings (weighted) */
    fuzzerPenalty: number;
    /** Penalty from LLM semantic analysis */
    llmPenalty: number;
    /** Number of static findings */
    staticFindingsCount: number;
    /** Number of fuzzer findings */
    fuzzerFindingsCount: number;
    /** Weighted multiplier applied to fuzzer */
    fuzzerMultiplier: number;
  };
}

export class SecurityScanner {
  private rules: ISecurityRule[];
  private config: McpVerifyConfig;
  private ignoreRules: IgnoreRule[] = [];

  constructor(config: McpVerifyConfig = DEFAULT_CONFIG) {
    this.config = config;
    this.loadIgnoreFile();
    this.rules = [
      // Critical severity rules
      new AuthenticationBypassRule(), // SEC-001
      new CommandInjectionRule(), // SEC-002
      new SQLInjectionRule(), // SEC-003

      // High severity rules
      new SSRFDetectionRule(), // SEC-004
      new XXEInjectionRule(), // SEC-005
      new InsecureDeserializationRule(), // SEC-006
      new PathTraversalRule(), // SEC-007

      // Medium severity rules
      new DataLeakageRule(), // SEC-008
      new SensitiveDataExposureRule(), // SEC-009
      new RateLimitingRule(), // SEC-010
      new ReDoSDetectionRule(), // SEC-011
      new WeakCryptographyRule(), // SEC-012
      new PromptInjectionRule(), // SEC-013

      // Network and authentication security
      new ExposedEndpointRule(), // SEC-014
      new MissingAuthenticationRule(), // SEC-015

      // Advanced security rules
      new InsecureURISchemeRule(), // SEC-016
      new ExcessivePermissionsRule(), // SEC-017
      new SecretsInDescriptionsRule(), // SEC-018
      new MissingInputConstraintsRule(), // SEC-019 (opt-in recommended)
      new DangerousToolChainingRule(), // SEC-020
      new UnencryptedCredentialsRule(), // SEC-021

      // Block A: OWASP LLM Top 10 in MCP Context (SEC-022 to SEC-030)
      new InsecureOutputHandlingRule(), // SEC-022
      new ExcessiveAgencyRule(), // SEC-023
      new PromptInjectionViaToolsRule(), // SEC-024
      new SupplyChainToolDepsRule(), // SEC-025
      new SensitiveDataInToolResponsesRule(), // SEC-026
      new TrainingDataPoisoningRule(), // SEC-027
      new ModelDosViaToolsRule(), // SEC-028
      new InsecurePluginDesignRule(), // SEC-029
      new ExcessiveDataDisclosureRule(), // SEC-030

      // Block B: Multi-Agent & Agentic Chain Attacks (SEC-031 to SEC-041)
      new AgentIdentitySpoofingRule(), // SEC-031
      new ToolResultTamperingRule(), // SEC-032
      new RecursiveAgentLoopRule(), // SEC-033
      new MultiAgentPrivilegeEscalationRule(), // SEC-034
      new AgentStatePoisoningRule(), // SEC-035
      new DistributedAgentDdosRule(), // SEC-036
      new CrossAgentPromptInjectionRule(), // SEC-037
      new AgentReputationHijackingRule(), // SEC-038
      new ToolChainingPathTraversalRule(), // SEC-039
      new AgentSwarmCoordinationAttackRule(), // SEC-040
      new AgentMemoryInjectionRule(), // SEC-041

      // Block C: Operational Security & Enterprise Compliance (SEC-042 to SEC-050)
      new MissingAuditLoggingRule(), // SEC-042
      new InsecureSessionManagementRule(), // SEC-043
      new SchemaVersioningAbsentRule(), // SEC-044
      new InsufficientErrorGranularityRule(), // SEC-045
      new MissingCorsValidationRule(), // SEC-046
      new InsecureDefaultConfigurationRule(), // SEC-047
      new MissingCapabilityNegotiationRule(), // SEC-048
      new TimingSideChannelAuthRule(), // SEC-049
      new InsufficientOutputEntropyRule(), // SEC-050

      // Block D: AI Weaponization & Supply Chain MCP (SEC-051 to SEC-069)
      new WeaponizedMcpFuzzerRule(), // SEC-051
      new AutonomousMcpBackdoorRule(), // SEC-052
      new MaliciousConfigFileRule(), // SEC-053
      new ApiEndpointHijackingRule(), // SEC-054
      new JailbreakAsServiceRule(), // SEC-055
      new PhishingViaMcpRule(), // SEC-056
      new DataExfiltrationSteganographyRule(), // SEC-057
      new SelfReplicatingMcpRule(), // SEC-058
      new UnvalidatedToolAuthorizationRule(), // SEC-059
      new MissingTransactionSemanticsRule(), // SEC-060

      // Block E: Identity & Supply Chain (SEC-061+)
      new HomoglyphSpoofingRule(), // SEC-061
    ];
  }

  /**
   * Load .mcpverifyignore file from current working directory
   */
  private loadIgnoreFile(): void {
    const possiblePaths = [
      path.join(process.cwd(), ".mcpverifyignore"),
      path.join(process.cwd(), ".mcp-verify", "ignore"),
    ];

    for (const ignoreFilePath of possiblePaths) {
      if (fs.existsSync(ignoreFilePath)) {
        try {
          const content = fs.readFileSync(ignoreFilePath, "utf-8");
          this.ignoreRules = McpIgnoreParser.parse(content);
          break; // Use first found file
        } catch (error) {
          // Silently fail if can't read .mcpverifyignore
          // Don't block security scanning due to ignore file issues
        }
      }
    }
  }

  /**
   * Extract tool name from component string (e.g., "tool:execute_sql" -> "execute_sql")
   */
  private extractToolName(component: string): string | undefined {
    const match = component.match(/^tool:(.+)$/);
    return match ? match[1] : undefined;
  }

  /**
   * Determine if a rule should be executed based on block filtering and explicit disables
   * @param ruleCode - Rule ID (e.g., 'SEC-001', 'SEC-022')
   * @returns True if rule should run, false otherwise
   */
  private shouldExecuteRule(ruleCode: string): boolean {
    // 1. Check if rule is explicitly disabled in config
    const disabledRules = this.config.security.disabledRules || [];
    if (disabledRules.includes(ruleCode)) {
      return false;
    }

    // 2. Extract rule number from code (e.g., 'SEC-022' -> 22)
    const ruleNumberMatch = ruleCode.match(/^SEC-(\d+)$/);
    if (!ruleNumberMatch) {
      // If rule doesn't match SEC-NNN format, default to execute (e.g., 'HEURISTIC')
      return true;
    }

    const ruleNumber = parseInt(ruleNumberMatch[1], 10);

    // 3. Determine which block this rule belongs to
    let enabledBlocks = this.config.security.enabledBlocks || [
      "OWASP",
      "MCP",
      "A",
      "B",
      "C",
      "D",
    ];

    // Allow enabling Block D via environment variable for testing/advanced use
    if (
      process.env.MCP_VERIFY_ENABLE_BLOCK_D === "true" &&
      !enabledBlocks.includes("D")
    ) {
      enabledBlocks = [...enabledBlocks, "D"];
    }

    for (const block of enabledBlocks) {
      const range = RULE_BLOCK_RANGES[block as SecurityRuleBlock];
      if (range && ruleNumber >= range.start && ruleNumber <= range.end) {
        return true; // Rule is in an enabled block
      }
    }

    // Rule not in any enabled block
    return false;
  }

  /**
   * Filter findings based on .mcpignore rules
   */
  private filterIgnoredFindings(
    findings: SecurityFinding[],
  ): SecurityFinding[] {
    if (this.ignoreRules.length === 0) {
      return findings; // No ignore rules, return all findings
    }

    return findings.filter((finding) => {
      const toolName = this.extractToolName(finding.component);
      const ruleCode = finding.ruleCode || "";

      // Check if this finding should be ignored
      const shouldIgnore = McpIgnoreParser.shouldIgnore(
        ruleCode,
        toolName,
        this.ignoreRules,
      );

      return !shouldIgnore; // Keep finding if NOT ignored
    });
  }

  scan(discovery: DiscoveryResult): SecurityReport {
    // Normalize discovery to ensure arrays exist
    const normalizedDiscovery: DiscoveryResult = {
      ...discovery,
      tools: Array.isArray(discovery.tools) ? discovery.tools : [],
      resources: Array.isArray(discovery.resources) ? discovery.resources : [],
      prompts: Array.isArray(discovery.prompts) ? discovery.prompts : [],
    };

    let score = 100;
    const findings: SecurityFinding[] = [];

    // 1. Run Modular Rules (if enabled)
    for (const rule of this.rules) {
      const ruleConfig = this.config.security.rules[rule.code];

      // Check if rule is enabled based on:
      // - Block filtering (enabledBlocks)
      // - Explicit disables (disabledRules)
      // - Per-rule config (rules[SEC-XXX].enabled)
      const isEnabledByConfig = ruleConfig?.enabled !== false;
      const isEnabledByBlock = this.shouldExecuteRule(rule.code);

      if (isEnabledByConfig && isEnabledByBlock) {
        const ruleFindings = rule.evaluate(normalizedDiscovery);

        // Apply overrides (severity) if config exists
        if (ruleConfig?.severity) {
          ruleFindings.forEach((f) => (f.severity = ruleConfig.severity!));
        }

        // Apply Ignore Filter immediately
        // Also check if the rule itself was disabled dynamically (though the outer check handles static config)
        const activeFindings = this.filterIgnoredFindings(ruleFindings);

        findings.push(...activeFindings);

        // Deduct score only for ACTIVE findings
        activeFindings.forEach((f) => {
          if (f.severity === "critical") score -= 40;
          if (f.severity === "high") score -= 25;
          if (f.severity === "medium") score -= 15;
          if (f.severity === "low") score -= 5;
        });
      }
    }

    // 2. Legacy Heuristics
    // Can be disabled via config too in future
    this.runLegacyHeuristics(
      discovery,
      findings,
      (penalty) => (score -= penalty),
    );

    // 3. Filter ignored findings (AFTER score calculation to maintain score impact)
    const filteredFindings = this.filterIgnoredFindings(findings);

    score = Math.max(0, score);
    let level = t("risk_level_low");
    if (score < 50) level = t("risk_level_critical");
    else if (score < 70) level = t("risk_level_high");
    else if (score < 90) level = t("risk_level_medium");

    return { score, level, findings: filteredFindings };
  }

  private runLegacyHeuristics(
    discovery: DiscoveryResult,
    findings: SecurityFinding[],
    deductScore: (n: number) => void,
  ) {
    const riskPatterns = [
      {
        regex: /exec|shell|bash|cmd|system|run|eval/i,
        penalty: 30,
        severity: "critical",
        key: "sec_heuristic_rce" as const,
      },
      {
        regex: /auth|login|password|key|token|secret/i,
        penalty: 20,
        severity: "high",
        key: "sec_heuristic_auth" as const,
      },
      {
        regex: /write|delete|remove|fs|file|upload/i,
        penalty: 15,
        severity: "medium",
        key: "sec_heuristic_fs" as const,
      },
      {
        regex: /sql|query|db|database|drop/i,
        penalty: 15,
        severity: "medium",
        key: "sec_heuristic_db" as const,
      },
      {
        regex: /curl|fetch|request|http|proxy/i,
        penalty: 10,
        severity: "low",
        key: "sec_heuristic_net" as const,
      },
    ] as const;

    if (discovery.tools) {
      discovery.tools.forEach((tool) => {
        riskPatterns.forEach((pattern) => {
          if (
            pattern.regex.test(tool.name) ||
            (tool.description && pattern.regex.test(tool.description))
          ) {
            deductScore(pattern.penalty);
            const msg = t(pattern.key);
            findings.push({
              severity: pattern.severity as
                | "critical"
                | "high"
                | "medium"
                | "low",
              message: t("sec_heuristic_detected", { msg }),
              component: `tool:${tool.name}`,
              ruleCode: "HEURISTIC",
            });
          }
        });
      });
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // UNIFIED SCORING: Static + Fuzzer + LLM
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Enhanced scan that unifies static analysis, fuzzer findings, and LLM analysis
   * into a single security score with appropriate weighting.
   *
   * Key Insight: Fuzzer-confirmed vulnerabilities represent PROVEN exploitability
   * and should weigh significantly more than theoretical risk from static analysis.
   *
   * Scoring Formula:
   *   Score = 100 - StaticPenalty - (FuzzerPenalty * FUZZER_WEIGHT_MULTIPLIER * ConfidenceWeight) - LLMPenalty
   *
   * @param discovery - MCP server capabilities discovered
   * @param fuzzerFindings - Optional findings from dynamic fuzzing
   * @param llmFindings - Optional findings from LLM semantic analysis
   * @returns Enhanced security report with score breakdown
   */
  scanUnified(
    discovery: DiscoveryResult,
    fuzzerFindings?: FuzzerFinding[],
    llmFindings?: SecurityFinding[],
  ): EnhancedSecurityReport {
    // Normalize discovery
    const normalizedDiscovery: DiscoveryResult = {
      ...discovery,
      tools: Array.isArray(discovery.tools) ? discovery.tools : [],
      resources: Array.isArray(discovery.resources) ? discovery.resources : [],
      prompts: Array.isArray(discovery.prompts) ? discovery.prompts : [],
    };

    const findings: SecurityFinding[] = [];
    let staticPenalty = 0;
    let fuzzerPenalty = 0;
    let llmPenalty = 0;

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 1: Static Analysis (theoretical risk)
    // ─────────────────────────────────────────────────────────────────────────
    for (const rule of this.rules) {
      const ruleConfig = this.config.security.rules[rule.code];
      const isEnabled = ruleConfig?.enabled !== false;

      if (isEnabled) {
        const ruleFindings = rule.evaluate(normalizedDiscovery);

        // Apply severity overrides if configured
        if (ruleConfig?.severity) {
          ruleFindings.forEach((f) => (f.severity = ruleConfig.severity!));
        }

        // Mark as static finding
        ruleFindings.forEach((f) => {
          (f as SecurityFinding & { source?: string }).source = "static";
        });

        findings.push(...ruleFindings);

        // Calculate static penalty
        for (const finding of ruleFindings) {
          const penalty = STATIC_SEVERITY_PENALTIES[finding.severity] || 0;
          staticPenalty += penalty;
        }
      }
    }

    // Legacy heuristics (also static)
    this.runLegacyHeuristics(normalizedDiscovery, findings, (penalty) => {
      staticPenalty += penalty;
    });

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 2: Fuzzer Findings (confirmed vulnerabilities - HIGHER WEIGHT)
    // ─────────────────────────────────────────────────────────────────────────
    if (fuzzerFindings && fuzzerFindings.length > 0) {
      for (const fuzzerFinding of fuzzerFindings) {
        // Convert fuzzer finding to security finding
        const securityFinding: SecurityFinding = {
          ruleCode: `FUZZ-${fuzzerFinding.detectorId.toUpperCase()}`,
          severity: fuzzerFinding.severity,
          message: `[CONFIRMED] ${fuzzerFinding.description}`,
          component: `tool:${fuzzerFinding.toolName}`,
          location: {
            type: "tool",
            name: fuzzerFinding.toolName,
          },
          evidence: {
            detectorId: fuzzerFinding.detectorId,
            confidence: fuzzerFinding.confidence,
            payloadCategory: fuzzerFinding.payloadCategory ?? null,
            cwe: fuzzerFinding.cwe ?? null,
            owasp: fuzzerFinding.owasp ?? null,
            source: "fuzzer",
            ...fuzzerFinding.evidence,
          },
          remediation:
            fuzzerFinding.remediation || t("remediation_fuzzer_confirmed"),
        };

        // Mark as fuzzer finding for reporting
        (securityFinding as SecurityFinding & { source?: string }).source =
          "fuzzer";

        findings.push(securityFinding);

        // Calculate weighted fuzzer penalty
        const basePenalty =
          STATIC_SEVERITY_PENALTIES[fuzzerFinding.severity] || 0;
        const confidenceWeight =
          FUZZER_CONFIDENCE_WEIGHTS[fuzzerFinding.confidence] || 0.5;
        const weightedPenalty =
          basePenalty * FUZZER_WEIGHT_MULTIPLIER * confidenceWeight;

        fuzzerPenalty += weightedPenalty;
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 3: LLM Semantic Analysis (AI-detected risks)
    // ─────────────────────────────────────────────────────────────────────────
    if (llmFindings && llmFindings.length > 0) {
      for (const llmFinding of llmFindings) {
        // Mark as LLM finding
        (llmFinding as SecurityFinding & { source?: string }).source = "llm";

        // Prefix rule code if not already prefixed
        if (!llmFinding.ruleCode?.startsWith("LLM-")) {
          llmFinding.ruleCode = `LLM-${llmFinding.ruleCode || "SEMANTIC"}`;
        }

        findings.push(llmFinding);

        // LLM findings use standard penalties (between static and fuzzer)
        const penalty = STATIC_SEVERITY_PENALTIES[llmFinding.severity] || 0;
        llmPenalty += penalty;
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 4: Calculate Final Score
    // ─────────────────────────────────────────────────────────────────────────
    const totalPenalty = staticPenalty + fuzzerPenalty + llmPenalty;
    const score = Math.max(0, Math.round(100 - totalPenalty));

    // Determine risk level
    let level = t("risk_level_low");
    if (score < 50) level = t("risk_level_critical");
    else if (score < 70) level = t("risk_level_high");
    else if (score < 90) level = t("risk_level_medium");

    // Filter ignored findings
    const filteredFindings = this.filterIgnoredFindings(findings);

    // Count findings by source
    const staticFindingsCount = filteredFindings.filter(
      (f) =>
        (f as SecurityFinding & { source?: string }).source === "static" ||
        !(f as SecurityFinding & { source?: string }).source,
    ).length;
    const fuzzerFindingsCount = filteredFindings.filter(
      (f) => (f as SecurityFinding & { source?: string }).source === "fuzzer",
    ).length;

    return {
      score,
      level,
      findings: filteredFindings,
      scoreBreakdown: {
        baseScore: 100,
        staticPenalty: Math.round(staticPenalty),
        fuzzerPenalty: Math.round(fuzzerPenalty),
        llmPenalty: Math.round(llmPenalty),
        staticFindingsCount,
        fuzzerFindingsCount,
        fuzzerMultiplier: FUZZER_WEIGHT_MULTIPLIER,
      },
    };
  }

  /**
   * Converts fuzzer session vulnerabilities to FuzzerFinding format
   * Helper for integration with the new fuzzer engine
   */
  static convertFuzzerVulnerabilities(
    vulnerabilities: Array<{
      detectorId: string;
      severity: string;
      confidence: string;
      description: string;
      evidence?: Record<string, unknown>;
      recommendation?: string;
      cwe?: string;
      owasp?: string;
    }>,
    toolName: string,
  ): FuzzerFinding[] {
    return vulnerabilities.map((v) => ({
      detectorId: v.detectorId,
      severity:
        (v.severity as "critical" | "high" | "medium" | "low" | "info") ||
        "medium",
      confidence: (v.confidence as "high" | "medium" | "low") || "medium",
      toolName,
      payloadCategory: (v.evidence?.payloadCategory as string) || undefined,
      description: v.description,
      cwe: v.cwe,
      owasp: v.owasp,
      evidence: v.evidence,
      remediation: v.recommendation,
    }));
  }

  /**
   * Get the current fuzzer weight multiplier
   * Useful for reporting and documentation
   */
  static getFuzzerWeightMultiplier(): number {
    return FUZZER_WEIGHT_MULTIPLIER;
  }

  /**
   * Get the severity penalty values
   * Useful for reporting and documentation
   */
  static getSeverityPenalties(): typeof STATIC_SEVERITY_PENALTIES {
    return { ...STATIC_SEVERITY_PENALTIES };
  }
}
