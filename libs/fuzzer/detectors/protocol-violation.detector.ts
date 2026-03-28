/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Protocol Violation Detector
 *
 * Detects JSON-RPC and MCP protocol violations in responses.
 * Identifies improper error handling, missing fields, and spec violations.
 */

import {
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
  DetectionSeverity,
  DetectionConfidence
} from './detector.interface';

export interface ProtocolViolationConfig {
  /** Strict mode - flag all spec deviations */
  strictMode?: boolean;
  /** Expected JSON-RPC version */
  jsonRpcVersion?: string;
  /** Check for information disclosure in errors */
  checkInfoDisclosure?: boolean;
}

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: unknown;
  result?: unknown;
  error?: {
    code?: number;
    message?: string;
    data?: unknown;
  };
}

/**
 * Detects protocol-level vulnerabilities in MCP/JSON-RPC responses
 */
export class ProtocolViolationDetector implements IVulnerabilityDetector {
  readonly id = 'protocol-violation';
  readonly name = 'Protocol Violation Detector';
  readonly description = 'Detects JSON-RPC and MCP protocol violations';

  private config: ProtocolViolationConfig;

  // Sensitive patterns that shouldn't appear in error messages
  private readonly sensitivePatterns: RegExp[] = [
    /stack trace/i,
    /at \w+\.\w+\s*\(/i, // Stack frame pattern
    /\/home\/\w+/i,       // Unix paths
    /[A-Z]:\\Users\\/i,   // Windows paths
    /password/i,
    /secret/i,
    /api[_-]?key/i,
    /token/i,
    /\.env/i,
    /database/i,
    /connection string/i,
    /mongodb:\/\//i,
    /postgres:\/\//i,
    /mysql:\/\//i,
  ];

  // Standard JSON-RPC error codes
  private readonly standardErrorCodes: Set<number> = new Set([
    -32700, // Parse error
    -32600, // Invalid Request
    -32601, // Method not found
    -32602, // Invalid params
    -32603, // Internal error
  ]);

  constructor(config: ProtocolViolationConfig = {}) {
    this.config = {
      strictMode: false,
      jsonRpcVersion: '2.0',
      checkInfoDisclosure: true,
      ...config
    };
  }

  isApplicable(category: string): boolean {
    return category === 'json-rpc' ||
           category === 'protocol' ||
           category === 'mcp-protocol';
  }

  detect(context: DetectorContext): DetectionResult {
    const violations: Array<{
      type: string;
      description: string;
      severity: DetectionSeverity;
    }> = [];

    // Parse response
    const response = this.parseResponse(context.response);

    if (!response) {
      // If we expected a response but got nothing/unparseable
      if (!context.isError) {
        violations.push({
          type: 'malformed-response',
          description: 'Response is not valid JSON-RPC',
          severity: 'medium'
        });
      }
    } else {
      // Check JSON-RPC version
      if (response.jsonrpc !== this.config.jsonRpcVersion) {
        violations.push({
          type: 'invalid-version',
          description: `Expected jsonrpc: "${this.config.jsonRpcVersion}", got: "${response.jsonrpc}"`,
          severity: this.config.strictMode ? 'medium' : 'low'
        });
      }

      // Check for both result and error (violation)
      if (response.result !== undefined && response.error !== undefined) {
        violations.push({
          type: 'result-and-error',
          description: 'Response contains both result and error (spec violation)',
          severity: 'high'
        });
      }

      // Check error object structure
      if (response.error) {
        this.checkErrorObject(response.error, violations);
      }

      // Check for missing id in response
      if (response.id === undefined && !context.isError) {
        violations.push({
          type: 'missing-id',
          description: 'Response missing required "id" field',
          severity: 'medium'
        });
      }

      // Check for null id (should only be for parse errors)
      if (response.id === null && response.error?.code !== -32700) {
        violations.push({
          type: 'null-id-misuse',
          description: 'Null id should only be used for parse errors',
          severity: 'low'
        });
      }
    }

    // Check raw response for info disclosure
    if (this.config.checkInfoDisclosure) {
      this.checkInfoDisclosure(context, violations);
    }

    // Check for crash indicators
    this.checkCrashIndicators(context, violations);

    if (violations.length === 0) {
      return this.noDetection();
    }

    // Calculate overall severity (highest violation wins)
    const severity = this.getHighestSeverity(violations);
    const confidence = this.calculateConfidence(violations);

    return {
      detected: true,
      detectorId: this.id,
      vulnerabilityType: 'protocol-violation',
      severity,
      confidence,
      description: `${violations.length} protocol violation(s) detected`,
      evidence: {
        payload: this.truncate(String(context.payload), 200),
        response: this.truncate(JSON.stringify(context.response), 500),
        matchedPatterns: violations.map(v => v.description),
      },
      remediation: this.buildRecommendation(violations),
      cweId: this.getCwe(violations),
      owaspCategory: 'API8:2023' // Security Misconfiguration
    };
  }

  private parseResponse(response: unknown): JsonRpcResponse | null {
    if (!response) return null;

    if (typeof response === 'object') {
      return response as JsonRpcResponse;
    }

    if (typeof response === 'string') {
      try {
        return JSON.parse(response) as JsonRpcResponse;
      } catch {
        return null;
      }
    }

    return null;
  }

  private checkErrorObject(
    error: JsonRpcResponse['error'],
    violations: Array<{ type: string; description: string; severity: DetectionSeverity }>
  ): void {
    if (!error) return;

    // Check for missing code
    if (error.code === undefined) {
      violations.push({
        type: 'error-missing-code',
        description: 'Error object missing required "code" field',
        severity: 'medium'
      });
    } else if (typeof error.code !== 'number') {
      violations.push({
        type: 'error-invalid-code',
        description: `Error code must be integer, got: ${typeof error.code}`,
        severity: 'medium'
      });
    }

    // Check for missing message
    if (error.message === undefined) {
      violations.push({
        type: 'error-missing-message',
        description: 'Error object missing required "message" field',
        severity: 'low'
      });
    } else if (typeof error.message !== 'string') {
      violations.push({
        type: 'error-invalid-message',
        description: `Error message must be string, got: ${typeof error.message}`,
        severity: 'low'
      });
    }

    // Check for non-standard error codes in reserved range
    if (typeof error.code === 'number') {
      if (error.code >= -32099 && error.code <= -32000) {
        if (!this.standardErrorCodes.has(error.code)) {
          violations.push({
            type: 'reserved-error-code',
            description: `Using reserved error code range: ${error.code}`,
            severity: 'low'
          });
        }
      }
    }
  }

  private checkInfoDisclosure(
    context: DetectorContext,
    violations: Array<{ type: string; description: string; severity: DetectionSeverity }>
  ): void {
    const responseStr = JSON.stringify(context.response || '');
    const errorStr = context.error ? JSON.stringify(context.error) : '';
    const combined = responseStr + errorStr;

    for (const pattern of this.sensitivePatterns) {
      if (pattern.test(combined)) {
        violations.push({
          type: 'info-disclosure',
          description: `Sensitive information pattern detected: ${pattern.source}`,
          severity: 'high'
        });
        break; // One is enough
      }
    }
  }

  private checkCrashIndicators(
    context: DetectorContext,
    violations: Array<{ type: string; description: string; severity: DetectionSeverity }>
  ): void {
    // Very slow response might indicate resource exhaustion
    if (context.responseTimeMs > 30000) {
      violations.push({
        type: 'potential-dos',
        description: `Extremely slow response: ${context.responseTimeMs}ms`,
        severity: 'medium'
      });
    }

    // Check for unexpected error patterns
    if (context.error?.message) {
      const msg = context.error.message.toLowerCase();
      if (msg.includes('timeout') || msg.includes('timed out')) {
        violations.push({
          type: 'timeout-triggered',
          description: 'Request caused server timeout',
          severity: 'medium'
        });
      }
      if (msg.includes('out of memory') || msg.includes('heap')) {
        violations.push({
          type: 'memory-exhaustion',
          description: 'Request may have caused memory exhaustion',
          severity: 'critical'
        });
      }
    }
  }

  private getHighestSeverity(
    violations: Array<{ severity: DetectionSeverity }>
  ): DetectionSeverity {
    const order: DetectionSeverity[] = ['critical', 'high', 'medium', 'low'];
    for (const sev of order) {
      if (violations.some(v => v.severity === sev)) {
        return sev;
      }
    }
    return 'low';
  }

  private calculateConfidence(
    violations: Array<{ type: string }>
  ): DetectionConfidence {
    // Multiple violations = higher confidence
    if (violations.length >= 3) return 'high';
    if (violations.length >= 2) return 'medium';
    return 'low';
  }

  private buildRecommendation(
    violations: Array<{ type: string }>
  ): string {
    const types = new Set(violations.map(v => v.type));

    const recommendations: string[] = [];

    if (types.has('info-disclosure')) {
      recommendations.push('Sanitize error messages to remove sensitive information');
    }
    if (types.has('result-and-error')) {
      recommendations.push('Fix response handler to return either result OR error, never both');
    }
    if (types.has('memory-exhaustion') || types.has('timeout-triggered')) {
      recommendations.push('Implement input validation and resource limits');
    }
    if (types.has('error-missing-code') || types.has('error-missing-message')) {
      recommendations.push('Ensure error objects contain required code and message fields');
    }

    if (recommendations.length === 0) {
      recommendations.push('Review JSON-RPC implementation for spec compliance');
    }

    return recommendations.join('. ');
  }

  private getCwe(violations: Array<{ type: string }>): string {
    if (violations.some(v => v.type === 'info-disclosure')) {
      return 'CWE-209'; // Error Message Information Disclosure
    }
    if (violations.some(v => v.type === 'memory-exhaustion')) {
      return 'CWE-400'; // Uncontrolled Resource Consumption
    }
    return 'CWE-703'; // Improper Check or Handling of Exceptional Conditions
  }

  private truncate(str: string, maxLen: number): string {
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen) + '...';
  }

  private noDetection(): DetectionResult {
    return {
      detected: false,
      detectorId: this.id,
      vulnerabilityType: 'none',
      severity: 'low',
      confidence: 'low',
      description: 'No protocol violations detected'
    };
  }
}
