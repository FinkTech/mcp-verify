/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import type { McpTool, McpResource, McpPrompt, JsonObject, JsonValue, JsonArray, JsonPrimitive } from '../../shared/common.types';
export type { McpTool, McpResource, McpPrompt, JsonObject, JsonValue, JsonArray, JsonPrimitive };

/**
 * Represents a specific security vulnerability identified during analysis.
 */
export interface SecurityFinding {
  /** The severity of the finding. */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Descriptive message explaining the vulnerability. */
  message: string;
  /** The component where the issue was found (e.g., tool name). */
  component: string;
  /** The code of the rule that triggered this finding (e.g., 'SEC-001'). */
  ruleCode?: string;
  /** detailed evidence payload (e.g., specific parameters, regex matches). */
  evidence?: Record<string, JsonValue>;
  /** Steps to fix the vulnerability. */
  remediation?: string;
  /** References to security standards, CVEs, CWEs, or compliance frameworks. */
  references?: string[];
  /** Precise location of the issue within the component. */
  location?: {
    type?: string;
    name?: string;
    parameter?: string;
    uri?: string;
    [key: string]: string | undefined;
  };

  // Optional compatibility properties for vscode-extension and reporting
  /** Alias for component - the tool where the issue was found. */
  toolName?: string;
  /** Human-readable rule name. */
  ruleName?: string;
  /** Short rule identifier (alias for ruleCode). */
  rule?: string;
  /** CWE (Common Weakness Enumeration) number. */
  cwe?: string;
}

/**
 * Summary report of all security analysis performed on the server.
 */
export interface SecurityReport {
  /** Numeric security score (0-100). */
  score: number;
  /** Overall risk level based on findings. */
  level: string;
  /** List of all individual findings. */
  findings: SecurityFinding[];
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  infoCount?: number;
}

/**
 * Issue related to code quality, documentation, or best practices (non-security).
 */
export interface QualityIssue {
  severity: 'high' | 'medium' | 'low' | 'info' | 'warning';
  message: string;
  component: string;
  /** Suggestion for improvement. */
  suggestion: string;
  /** Category of the quality issue. */
  category?: 'naming' | 'documentation' | 'clarity';
}

/**
 * Report on the quality of the MCP server definition.
 */
export interface QualityReport {
  score: number;
  issues: QualityIssue[];
  /** Detailed analysis provided by an LLM (if enabled). */
  llmAnalysis?: {
    enabled: boolean;
    findings?: Array<{
      type: 'tool' | 'resource' | 'prompt';
      name: string;
      severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
      issue: string;
      reasoning: string;
      recommendation?: string;
    }>;
    cost?: {
      inputTokens: number;
      outputTokens: number;
      estimatedCostUSD: number;
    };
    error?: string;
  };
}

/**
 * Issue related to MCP protocol compliance violations.
 */
export interface ProtocolIssue {
  code: string;
  message: string;
  severity: 'error' | 'warning';
}

/**
 * Report on MCP protocol compliance.
 */
export interface ProtocolComplianceReport {
  passed: boolean;
  score: number;
  issues: ProtocolIssue[];
  testsPassed?: number;
  testsFailed?: number;
  totalTests?: number;
}

/**
 * Result of a single fuzzing test execution.
 */
export interface FuzzingResult {
  toolName: string;
  input: JsonValue;
  payloadType: string;
  serverError?: string;
  passed: boolean;
  durationMs: number;
  // v1.0: Safety blacklist
  skipped?: boolean;
  skipReason?: string;
  // v1.0: Vulnerability analysis
  vulnerabilityAnalysis?: {
    vulnerable: boolean;
    confidence: 'high' | 'medium' | 'low';
    findings: Array<{
      type: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      description: string;
      evidence: string;
      remediation: string;
    }>;
    baselineDeviation?: number;
  };
}

/**
 * Report on dynamic fuzzing tests.
 */
export interface FuzzingReport {
  executed: boolean;
  totalTests: number;
  failedTests: number;
  crashes: number;
  results: FuzzingResult[];
  // v1.0: Detected vulnerabilities summary
  vulnerabilities?: Array<{
    toolName: string;
    payloadType: string;
    findings: Array<{
      type: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      description: string;
      evidence: string;
      remediation: string;
    }>;
  }>;
}

export interface HandshakeResult {
  success: boolean;
  protocolVersion?: string;
  serverName?: string;
  error?: string;
}

/**
 * Server metadata information (from package.json or MCP server info)
 */
export interface ServerInfo {
  /** Server name */
  name?: string;
  /** Server version */
  version?: string;
  /** Server description */
  description?: string;
  /** Server license */
  license?: string;
  /** Production dependencies */
  dependencies?: Record<string, string>;
  /** Development dependencies */
  devDependencies?: Record<string, string>;
  /** Additional metadata */
  [key: string]: unknown;
}

/**
 * Structure containing all discovered capabilities of the MCP server.
 */
export interface DiscoveryResult {
  tools: McpTool[];
  resources: McpResource[];
  prompts: McpPrompt[];
  /** Optional server metadata (from package.json or server info) */
  serverInfo?: ServerInfo;
}

export interface ValidationResult {
  schemaValid: boolean;
  toolsValid: number;
  toolsInvalid: number;
  resourcesValid: number;
  resourcesInvalid: number;
  promptsValid: number;
  promptsInvalid: number;
}

// Reporting Types
export interface ToolReportItem extends McpTool {
  status: 'valid' | 'invalid';
}

export interface ResourceReportItem extends McpResource {
  status: 'valid' | 'invalid';
}

export interface PromptReportItem extends McpPrompt {
  status: 'valid' | 'invalid';
}

export interface Badge {
  markdown: string;
  html: string;
  url: string;
}

/**
 * Metadata about the report generation
 */
export interface ReportMetadata {
  /** mcp-verify version that generated this report */
  toolVersion: string;
  /** Analysis modules that were executed */
  modulesExecuted: Array<'security' | 'quality' | 'fuzzing' | 'protocol'>;
  /** Whether LLM analysis was used (data sent to third-party API) */
  llmUsed: boolean;
  /** LLM provider if used */
  llmProvider?: 'anthropic' | 'openai' | 'ollama';
}

/**
 * Legal disclaimer included in all reports
 */
export interface ReportDisclaimer {
  /** Main disclaimer text */
  text: string;
  /** What this tool analyzes */
  scope: string[];
  /** What this tool does NOT analyze */
  limitations: string[];
  /** Additional notice when LLM was used */
  llmNotice?: string;
}

/**
 * Comprehensive report generated by the mcp-verify tool.
 */
export interface Report {
  server_name: string;
  url: string;
  status: 'valid' | 'invalid';
  transport?: 'http' | 'stdio';
  protocol_version: string;

  security: SecurityReport;
  quality: QualityReport;
  protocolCompliance?: ProtocolComplianceReport;
  fuzzing?: FuzzingReport;

  badges?: Badge;

  tools: {
    count: number;
    valid: number;
    invalid: number;
    items: ToolReportItem[];
  };
  resources: {
    count: number;
    valid: number;
    invalid: number;
    items: ResourceReportItem[];
  };
  prompts: {
    count: number;
    valid: number;
    invalid: number;
    items: PromptReportItem[];
  };
  timestamp: string;
  duration_ms: number;

  /** Report metadata */
  metadata?: ReportMetadata;
  /** Legal disclaimer - always included in reports */
  disclaimer?: ReportDisclaimer;
  /** Git repository info for SARIF versionControlProvenance */
  gitInfo?: GitInfo;
}

/**
 * Git repository information for SARIF reports
 * Used to populate versionControlProvenance for GitHub Code Scanning
 */
export interface GitInfo {
  /** Repository URL (e.g., https://github.com/org/repo) */
  repositoryUri: string;
  /** Current commit SHA */
  revisionId: string;
  /** Current branch name */
  branch: string;
}
