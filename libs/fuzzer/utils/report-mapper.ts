/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Report Mapper
 *
 * Transforms FuzzingSession from the new fuzzer into the
 * standard Report format used by the core reporting infrastructure.
 *
 * This allows seamless integration with:
 * - HTML Report Generator
 * - JSON Report Generator
 * - SARIF Report Generator
 * - Markdown Report Generator
 */

import type { FuzzingSession, FuzzingError } from "../engine/fuzzer-engine";
import type { DetectionResult } from "../detectors/detector.interface";
import type { GeneratedPayload } from "../generators/generator.interface";
import {
  Report,
  FuzzingReport,
  FuzzingResult,
  SecurityReport,
  SecurityFinding,
  QualityReport,
} from "@mcp-verify/core/domain/mcp-server/entities/validation.types";

/**
 * Options for report mapping
 */
export interface ReportMapperOptions {
  /** Server name for the report */
  serverName?: string;
  /** Server URL/path */
  serverUrl?: string;
  /** Target tool name */
  toolName?: string;
  /** Include detailed payload info in evidence */
  includePayloads?: boolean;
  /** Maximum evidence length per finding */
  maxEvidenceLength?: number;
}

/**
 * Extended security finding with fuzzer-specific fields
 */
export interface FuzzerSecurityFinding extends SecurityFinding {
  /** Detector that found this */
  detectorId: string;
  /** Confidence level */
  confidence: "high" | "medium" | "low";
  /** CWE identifier if available */
  cwe?: string;
  /** OWASP reference if available */
  owasp?: string;
  /** The payload that triggered this finding */
  payload?: string;
  /** Category of the payload */
  payloadCategory?: string;
}

/**
 * Maps a FuzzingSession to a FuzzingReport
 */
export function sessionToFuzzingReport(
  session: FuzzingSession,
  toolName: string,
  options: ReportMapperOptions = {},
): FuzzingReport {
  const maxEvidence = options.maxEvidenceLength || 500;

  // Convert session results to FuzzingResult format
  const results: FuzzingResult[] = [];

  // We need to track which payloads were executed
  // Since the session doesn't store individual payload results,
  // we create synthetic results based on vulnerabilities and errors

  // Create results for vulnerabilities found
  for (const vuln of session.vulnerabilities) {
    const evidence = vuln.evidence;
    const payload = evidence?.payload || "N/A";
    const payloadStr =
      typeof payload === "string"
        ? payload.substring(0, 200)
        : truncate(JSON.stringify(payload), 200);

    results.push({
      toolName,
      input: { payload: payloadStr },
      payloadType: vuln.detectorId,
      passed: false, // Vulnerability = failed test
      durationMs: 0,
      vulnerabilityAnalysis: {
        vulnerable: true,
        confidence: mapConfidence(vuln.confidence),
        findings: [
          {
            type: vuln.detectorId,
            severity: mapSeverity(vuln.severity),
            description: vuln.description,
            evidence: truncate(JSON.stringify(evidence || {}), maxEvidence),
            remediation:
              vuln.remediation || "Review and fix the identified vulnerability",
          },
        ],
      },
    });
  }

  // Create results for errors
  for (const error of session.errors) {
    results.push({
      toolName,
      input: { payload: truncate(String(error.payload.value), 200) },
      payloadType: error.payload.category,
      serverError: error.message,
      passed: true, // Errors are expected in fuzzing
      durationMs: 0,
      skipped: false,
    });
  }

  // Group vulnerabilities by tool and payload type
  type VulnGroup = {
    toolName: string;
    payloadType: string;
    findings: Array<{
      type: string;
      severity: "critical" | "high" | "medium" | "low";
      description: string;
      evidence: string;
      remediation: string;
    }>;
  };

  const vulnsByTool = new Map<string, Map<string, VulnGroup>>();

  for (const vuln of session.vulnerabilities) {
    const payloadType = vuln.detectorId;

    if (!vulnsByTool.has(toolName)) {
      vulnsByTool.set(toolName, new Map());
    }

    const toolVulns = vulnsByTool.get(toolName)!;
    if (!toolVulns.has(payloadType)) {
      toolVulns.set(payloadType, {
        toolName,
        payloadType,
        findings: [],
      });
    }

    toolVulns.get(payloadType)!.findings.push({
      type: vuln.detectorId,
      severity: mapSeverity(vuln.severity),
      description: vuln.description,
      evidence: truncate(JSON.stringify(vuln.evidence || {}), maxEvidence),
      remediation:
        vuln.remediation || "Review and fix the identified vulnerability",
    });
  }

  // Flatten vulnerabilities map
  const vulnerabilities: FuzzingReport["vulnerabilities"] = [];
  for (const [, toolVulns] of vulnsByTool) {
    for (const [, vuln] of toolVulns) {
      vulnerabilities.push(vuln);
    }
  }

  return {
    executed: true,
    totalTests: session.totalPayloads,
    failedTests: session.vulnerabilities.length,
    crashes: session.errors.filter(
      (e) =>
        e.message.includes("ECONNRESET") ||
        e.message.includes("Socket closed") ||
        e.message.includes("Connection refused"),
    ).length,
    results,
    vulnerabilities,
  };
}

/**
 * Maps a FuzzingSession to SecurityFindings for the SecurityReport
 */
export function sessionToSecurityFindings(
  session: FuzzingSession,
  toolName: string,
): FuzzerSecurityFinding[] {
  return session.vulnerabilities.map((vuln) => {
    const evidence = vuln.evidence;

    return {
      // Standard SecurityFinding fields
      rule: vuln.detectorId,
      severity: mapSeverity(vuln.severity),
      component: toolName,
      message: vuln.description,
      remediation: vuln.remediation,
      // Extended fields
      detectorId: vuln.detectorId,
      confidence: mapConfidence(vuln.confidence),
      cwe: vuln.cweId,
      owasp: vuln.owaspCategory,
      payload: truncate(String(evidence?.payload || ""), 200),
      payloadCategory: vuln.detectorId,
    };
  });
}

/**
 * Creates a minimal Report structure with fuzzing results
 * Useful for standalone fuzzing reports
 */
export function sessionToReport(
  session: FuzzingSession,
  options: ReportMapperOptions = {},
): Report {
  const toolName = options.toolName || "unknown";
  const fuzzingReport = sessionToFuzzingReport(session, toolName, options);
  const securityFindings = sessionToSecurityFindings(session, toolName);

  // Calculate security score based on findings
  const criticalCount = securityFindings.filter(
    (f) => f.severity === "critical",
  ).length;
  const highCount = securityFindings.filter(
    (f) => f.severity === "high",
  ).length;
  const mediumCount = securityFindings.filter(
    (f) => f.severity === "medium",
  ).length;

  // Score: Start at 100, deduct based on severity
  let score = 100;
  score -= criticalCount * 25;
  score -= highCount * 15;
  score -= mediumCount * 5;
  score = Math.max(0, score);

  const securityReport: SecurityReport = {
    score,
    level: score >= 70 ? "low" : score >= 40 ? "medium" : "high",
    findings: securityFindings as SecurityFinding[],
    criticalCount,
    highCount,
    mediumCount,
    lowCount: securityFindings.filter((f) => f.severity === "low").length,
  };

  const qualityReport: QualityReport = {
    score: 100, // Fuzzer doesn't assess quality
    issues: [],
  };

  return {
    server_name: options.serverName || "MCP Server",
    url: options.serverUrl || "unknown",
    status: score >= 70 ? "valid" : "invalid",
    protocol_version: "2024-11-05",
    security: securityReport,
    quality: qualityReport,
    fuzzing: fuzzingReport,
    tools: {
      count: 1,
      valid: 1,
      invalid: 0,
      items: [
        {
          name: toolName,
          description: "Target tool for fuzzing",
          inputSchema: {
            type: "object",
            properties: {},
          },
          status: "valid",
        },
      ],
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
    timestamp: new Date().toISOString(),
    duration_ms:
      session.endedAt && session.startedAt
        ? session.endedAt.getTime() - session.startedAt.getTime()
        : 0,
  };
}

/**
 * Generates a summary object for quick display
 */
export interface FuzzingSummary {
  sessionId: string;
  duration: number;
  totalPayloads: number;
  payloadsExecuted: number;
  vulnerabilities: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  errors: number;
  crashes: number;
  aborted: boolean;
  categories: Record<string, number>;
  topFindings: Array<{
    detector: string;
    severity: string;
    description: string;
  }>;
}

export function sessionToSummary(session: FuzzingSession): FuzzingSummary {
  const duration = session.endedAt
    ? (session.endedAt.getTime() - session.startedAt.getTime()) / 1000
    : 0;

  const criticalCount = session.vulnerabilities.filter(
    (v) => v.severity === "critical",
  ).length;
  const highCount = session.vulnerabilities.filter(
    (v) => v.severity === "high",
  ).length;
  const mediumCount = session.vulnerabilities.filter(
    (v) => v.severity === "medium",
  ).length;
  const lowCount = session.vulnerabilities.filter(
    (v) => v.severity === "low",
  ).length;

  const crashes = session.errors.filter(
    (e) =>
      e.message.includes("ECONNRESET") ||
      e.message.includes("Socket closed") ||
      e.message.includes("Connection refused"),
  ).length;

  // Top 5 findings by severity
  const sortedFindings = [...session.vulnerabilities].sort((a, b) => {
    const severityOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };
    return (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3);
  });

  return {
    sessionId: session.id,
    duration,
    totalPayloads: session.totalPayloads,
    payloadsExecuted: session.payloadsExecuted,
    vulnerabilities: {
      total: session.vulnerabilities.length,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
    },
    errors: session.errors.length,
    crashes,
    aborted: session.aborted,
    categories: session.payloadsByCategory,
    topFindings: sortedFindings.slice(0, 5).map((v) => ({
      detector: v.detectorId,
      severity: v.severity,
      description: v.description,
    })),
  };
}

// Helper functions

function mapSeverity(severity: string): "critical" | "high" | "medium" | "low" {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
    default:
      return "low";
  }
}

function mapConfidence(confidence: string): "high" | "medium" | "low" {
  switch (confidence) {
    case "definite":
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
    default:
      return "low";
  }
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + "...";
}
