/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * XSS Detector — v1.0
 *
 * Detects reflected Cross-Site Scripting (XSS) by identifying when
 * fuzzer payloads (HTML tags, JavaScript) are returned unmodified
 * in the server response or error message.
 *
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 */

import type {
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
} from "./detector.interface";

export class XssDetector implements IVulnerabilityDetector {
  readonly id = "xss";
  readonly name = "Reflected XSS Detector";
  readonly description =
    "Detects reflected HTML and script tags in responses (CWE-79)";
  readonly categories = ["xss", "security"];
  readonly enabledByDefault = true;

  isApplicable(category: string): boolean {
    return category === "xss" || category === "all";
  }

  detect(context: DetectorContext): DetectionResult {
    const payloadStr =
      typeof context.payload === "string"
        ? context.payload
        : JSON.stringify(context.payload);

    // Only scan if the payload looks like HTML/Script
    if (
      !payloadStr.includes("<") &&
      !payloadStr.includes(">") &&
      !payloadStr.includes("javascript:")
    ) {
      return this.notDetected();
    }

    const responseStr = this.serialiseResponse(context.response);
    const errorStr =
      context.isError && context.error ? context.error.message : "";
    const combinedBody = `${responseStr}
${errorStr}`;

    // Simple reflection check: is the exact payload in the response?
    if (combinedBody.includes(payloadStr)) {
      return {
        detectorId: this.id,
        detected: true,
        vulnerabilityType: "Reflected Cross-Site Scripting (XSS)",
        severity: "high",
        confidence: "high",
        description:
          "Server reflects unsanitized input directly in response/error, potentially allowing script execution.",
        evidence: {
          payload: context.payload,
          response: context.response,
          matchedPatterns: [payloadStr.substring(0, 50)],
        },
        remediation:
          "Sanitize all user-supplied data before reflecting it in HTML/responses. Use context-aware output encoding (e.g., escape < to &lt;).",
        cweId: "CWE-79",
        owaspCategory: "A03:2021-Injection",
      };
    }

    return this.notDetected();
  }

  private serialiseResponse(response: unknown): string {
    if (response === null || response === undefined) return "";
    if (typeof response === "string") return response;
    try {
      return JSON.stringify(response);
    } catch {
      return String(response);
    }
  }

  private notDetected(): DetectionResult {
    return {
      detectorId: this.id,
      detected: false,
      vulnerabilityType: "XSS",
      severity: "low",
      confidence: "low",
      description: "No reflected XSS detected",
      evidence: { payload: "", response: null },
    };
  }
}
