/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Response Analyzer
 *
 * Analyzes server responses to fuzzing payloads to detect
 * vulnerabilities based on response content, timing, and patterns.
 *
 * Detection methods:
 * - Error message analysis (stack traces, SQL errors)
 * - Timing analysis (blind injection)
 * - Content reflection (XSS)
 * - Status code analysis
 * - Response size analysis
 *
 * @module libs/core/use-cases/fuzzer/response-analyzer
 */

import { t } from "@mcp-verify/shared";
import type { AttackPayload } from "./payloads";

export interface AnalysisResult {
  vulnerable: boolean;
  confidence: "high" | "medium" | "low";
  findings: VulnerabilityFinding[];
  baselineDeviation?: number;
}

export interface VulnerabilityFinding {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  evidence: string;
  remediation: string;
}

export class ResponseAnalyzer {
  /**
   * Patterns indicating potential vulnerabilities
   */
  private patterns = {
    // SQL Error patterns
    sqlErrors: [
      /SQL syntax.*?error/i,
      /mysql_fetch/i,
      /Unclosed quotation mark/i,
      /ORA-\d{5}/i, // Oracle errors
      /Microsoft SQL Server/i,
      /PostgreSQL.*?ERROR/i,
      /SQLite3::SQLException/i,
      /SQLSTATE\[/i,
      /Invalid column name/i,
      /Incorrect syntax near/i,
    ],

    // Stack trace patterns (information disclosure)
    stackTraces: [
      /at\s+[\w$.]+\([\w$.]+:\d+:\d+\)/, // JavaScript
      /File ".*?", line \d+/, // Python
      /\w+Exception.*?at.*?:\d+/, // Java/C#
      /Traceback \(most recent call last\)/,
      /Fatal error.*?in.*?on line \d+/, // PHP
    ],

    // XSS reflection patterns
    xssReflection: [
      /<script[^>]*>.*?alert\(/i,
      /<img[^>]*onerror=/i,
      /<svg[^>]*onload=/i,
      /javascript:alert\(/i,
    ],

    // Command injection indicators
    commandInjection: [
      /root:.*?:0:0:/, // /etc/passwd content
      /uid=\d+.*?gid=\d+/, // whoami output
      /total \d+\n.*?rwx/, // ls -la output
      /Microsoft Windows.*?Copyright/i, // Windows cmd output
    ],

    // Path traversal success indicators
    pathTraversal: [
      /root:x:0:0/, // Unix password file
      /daemon:x:\d+:\d+/,
      /\[boot loader\]/i, // Windows boot.ini
      /\[operating systems\]/i,
    ],

    // XXE success indicators
    xxe: [
      /root:.*?:\/root/, // Unix passwd via XXE
      /ENTITY.*?SYSTEM/i,
      /<!DOCTYPE.*?ENTITY/i,
    ],

    // SSRF indicators
    ssrf: [
      /ami-id/, // AWS metadata
      /instance-id/,
      /placement\/availability-zone/,
      /<html.*?<\/html>/s, // HTML from internal service
    ],

    // NoSQL injection indicators
    nosql: [/MongoError/i, /CastError/, /\$where.*?function/i],

    // Generic error indicators (might reveal sensitive info)
    genericErrors: [
      /Internal Server Error/i,
      /500.*?Error/i,
      /Fatal error/i,
      /Exception.*?:\s*.*?at/i,
    ],
  };

  /**
   * Timing thresholds (milliseconds)
   */
  private timingThresholds = {
    normal: 1000, // Normal response time
    suspiciousSlow: 3000, // Might indicate time-based injection
    definitelySlow: 5000, // Very likely time-based injection
  };

  /**
   * Baseline response time (set during calibration)
   */
  private baselineResponseTime: number = 0;

  /**
   * Analyze a response for vulnerabilities
   */
  analyze(
    payload: AttackPayload,
    response: unknown,
    responseTime: number,
    statusCode?: number,
  ): AnalysisResult {
    const findings: VulnerabilityFinding[] = [];

    // Convert response to string for analysis
    const responseStr = JSON.stringify(response);

    // 1. Error message analysis
    findings.push(...this.analyzeErrors(payload, responseStr));

    // 2. Stack trace detection
    findings.push(...this.analyzeStackTraces(responseStr));

    // 3. Content reflection (XSS)
    if (payload.type === "xss") {
      findings.push(...this.analyzeXssReflection(payload, responseStr));
    }

    // 4. Timing analysis (blind injection)
    if (payload.type === "sqli" || payload.type === "cmdInjection") {
      findings.push(...this.analyzeTimingAnomalies(payload, responseTime));
    }

    // 5. Status code analysis
    findings.push(...this.analyzeStatusCode(statusCode, payload));

    // 6. Specific payload type analysis
    switch (payload.type) {
      case "sqli":
        findings.push(...this.analyzeSqlInjection(responseStr));
        break;
      case "cmdInjection":
        findings.push(...this.analyzeCommandInjection(responseStr));
        break;
      case "pathTraversal":
        findings.push(...this.analyzePathTraversal(responseStr));
        break;
      case "xxe":
        findings.push(...this.analyzeXxe(responseStr));
        break;
      case "ssrf":
        findings.push(...this.analyzeSsrf(responseStr));
        break;
      case "nosql":
        findings.push(...this.analyzeNoSql(responseStr));
        break;
    }

    // Calculate confidence
    const confidence = this.calculateConfidence(findings);

    // Calculate baseline deviation
    const baselineDeviation =
      this.baselineResponseTime > 0
        ? responseTime - this.baselineResponseTime
        : undefined;

    return {
      vulnerable: findings.length > 0,
      confidence,
      findings,
      baselineDeviation,
    };
  }

  /**
   * Set baseline response time for timing attack detection
   */
  setBaselineResponseTime(time: number) {
    this.baselineResponseTime = time;
  }

  /**
   * Analyze for error messages
   */
  private analyzeErrors(
    payload: AttackPayload,
    response: string,
  ): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.genericErrors) {
      if (pattern.test(response)) {
        findings.push({
          type: "information_disclosure",
          severity: "medium",
          description: t("fuzz_info_disclosure_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_info_disclosure_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze for stack traces
   */
  private analyzeStackTraces(response: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.stackTraces) {
      if (pattern.test(response)) {
        findings.push({
          type: "information_disclosure",
          severity: "high",
          description: t("fuzz_stack_trace_desc"),
          evidence: response.substring(0, 300),
          remediation: t("fuzz_stack_trace_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze for XSS reflection
   */
  private analyzeXssReflection(
    payload: AttackPayload,
    response: string,
  ): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    // Check if payload is reflected unencoded
    if (response.includes(payload.value)) {
      findings.push({
        type: "xss",
        severity: "high",
        description: t("fuzz_xss_reflected_desc"),
        evidence: `Payload "${payload.value}" found in response`,
        remediation: t("fuzz_xss_reflected_rem"),
      });
    }

    // Check for XSS indicators
    for (const pattern of this.patterns.xssReflection) {
      if (pattern.test(response)) {
        findings.push({
          type: "xss",
          severity: "high",
          description: t("fuzz_xss_detected_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_xss_detected_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze timing anomalies
   */
  private analyzeTimingAnomalies(
    payload: AttackPayload,
    responseTime: number,
  ): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    // Time-based blind injection detection
    if (payload.value.includes("SLEEP") || payload.value.includes("WAITFOR")) {
      if (responseTime >= this.timingThresholds.definitelySlow) {
        findings.push({
          type: "time_based_injection",
          severity: "critical",
          description: t("fuzz_time_sqli_desc"),
          evidence: `Response time: ${responseTime}ms (expected: < ${this.timingThresholds.normal}ms)`,
          remediation: t("fuzz_time_sqli_rem"),
        });
      } else if (responseTime >= this.timingThresholds.suspiciousSlow) {
        findings.push({
          type: "time_based_injection",
          severity: "high",
          description: t("fuzz_time_suspicious_desc"),
          evidence: `Response time: ${responseTime}ms`,
          remediation: t("fuzz_time_suspicious_rem"),
        });
      }
    }

    return findings;
  }

  /**
   * Analyze status code
   */
  private analyzeStatusCode(
    statusCode: number | undefined,
    payload: AttackPayload,
  ): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    if (statusCode === 500) {
      findings.push({
        type: "server_error",
        severity: "medium",
        description: t("fuzz_server_error_desc"),
        evidence: `Status code: ${statusCode}`,
        remediation: t("fuzz_server_error_rem"),
      });
    }

    return findings;
  }

  /**
   * Analyze SQL injection indicators
   */
  private analyzeSqlInjection(response: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.sqlErrors) {
      if (pattern.test(response)) {
        findings.push({
          type: "sqli",
          severity: "critical",
          description: t("fuzz_sqli_detected_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_sqli_detected_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze command injection indicators
   */
  private analyzeCommandInjection(response: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.commandInjection) {
      if (pattern.test(response)) {
        findings.push({
          type: "cmdInjection",
          severity: "critical",
          description: t("fuzz_cmd_detected_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_cmd_detected_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze path traversal indicators
   */
  private analyzePathTraversal(response: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.pathTraversal) {
      if (pattern.test(response)) {
        findings.push({
          type: "pathTraversal",
          severity: "critical",
          description: t("fuzz_path_detected_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_path_detected_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze XXE indicators
   */
  private analyzeXxe(response: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.xxe) {
      if (pattern.test(response)) {
        findings.push({
          type: "xxe",
          severity: "critical",
          description: t("fuzz_xxe_detected_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_xxe_detected_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze SSRF indicators
   */
  private analyzeSsrf(response: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.ssrf) {
      if (pattern.test(response)) {
        findings.push({
          type: "ssrf",
          severity: "critical",
          description: t("fuzz_ssrf_detected_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_ssrf_detected_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Analyze NoSQL injection indicators
   */
  private analyzeNoSql(response: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns.nosql) {
      if (pattern.test(response)) {
        findings.push({
          type: "nosql",
          severity: "high",
          description: t("fuzz_nosql_detected_desc"),
          evidence: response.substring(0, 200),
          remediation: t("fuzz_nosql_detected_rem"),
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Calculate confidence level based on findings
   */
  private calculateConfidence(
    findings: VulnerabilityFinding[],
  ): "high" | "medium" | "low" {
    if (findings.length === 0) return "low";

    const hasCritical = findings.some((f) => f.severity === "critical");
    const hasMultiple = findings.length >= 2;

    if (hasCritical && hasMultiple) return "high";
    if (hasCritical || hasMultiple) return "medium";
    return "low";
  }
}
