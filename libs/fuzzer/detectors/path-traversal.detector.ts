/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Path Traversal Detector
 *
 * Detects if a tool call successfully accessed files outside the intended directory
 * by looking for known OS file signatures in the response.
 */

import {
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
} from "./detector.interface";

export class PathTraversalDetector implements IVulnerabilityDetector {
  readonly id = "path-traversal";
  readonly name = "Path Traversal Detector";
  readonly description =
    "Detects unauthorized access to system files via path traversal";

  /**
   * Known sensitive file signatures to look for in responses
   */
  private readonly signatures = [
    // Unix/Linux
    { pattern: /root:x:0:0/i, file: "/etc/passwd", platform: "unix" },
    { pattern: /daemon:x:1:1/i, file: "/etc/passwd", platform: "unix" },
    {
      pattern: /node_modules/i,
      file: "package.json or directory listing",
      platform: "any",
    },

    // Windows
    { pattern: /\[boot loader\]/i, file: "boot.ini", platform: "windows" },
    {
      pattern: /\[Operating Systems\]/i,
      file: "boot.ini",
      platform: "windows",
    },
    {
      pattern: /WINDOWS\\system32/i,
      file: "Windows System File",
      platform: "windows",
    },
    {
      pattern: /Registry\\Machine\\System/i,
      file: "Windows Registry",
      platform: "windows",
    },

    // General
    {
      pattern: /"name":\s*".*",\s*"version":\s*".*"/i,
      file: "package.json",
      platform: "any",
    },
    {
      pattern: /DB_PASSWORD|AWS_SECRET_ACCESS_KEY|API_KEY/i,
      file: ".env file",
      platform: "any",
    },

    // Server-specific Oracle (Confirmation of bypass)
    {
      pattern: /outside base directory/i,
      file: "Bypass confirmed: Path reached the startsWith check",
      platform: "any",
    },
    {
      pattern: /ENOENT: no such file or directory/i,
      file: "Potential bypass: Server attempted to access a file that does not exist in the injected path",
      platform: "any",
    },
  ];

  isApplicable(category: string): boolean {
    // Debug: Always run to rule out category mapping issues
    return true;
  }

  detect(context: DetectorContext): DetectionResult {
    // Analyze both the successful response and any error messages
    const responseStr = JSON.stringify(context.response || {});
    const errorStr = context.error ? context.error.message : "";
    const combinedContent = `${responseStr} ${errorStr}`;

    const findings: string[] = [];

    // Check against signatures
    for (const sig of this.signatures) {
      if (sig.pattern.test(combinedContent)) {
        findings.push(
          `Found signature of sensitive file: ${sig.file} (${sig.platform})`,
        );
      }
    }

    // Heuristic: If response is very large and looks like binary data or raw file content
    if (
      context.response &&
      typeof context.response === "string" &&
      context.response.length > 5000
    ) {
      if (context.response.includes("\n") && !context.response.includes("{")) {
        findings.push(
          "Response contains large amount of non-JSON text, possibly a raw file content",
        );
      }
    }

    const detected = findings.length > 0;

    return {
      detectorId: this.id,
      detected,
      vulnerabilityType: "path-traversal",
      severity: "critical",
      confidence: "definite", // Cambiado de 'certain' a 'definite'
      description: detected
        ? `Potential Path Traversal successful: ${findings.join(", ")}`
        : "No path traversal detected",
      evidence: {
        payload: context.payload,
        response: context.response,
        matchedPatterns: findings, // 'findings' ahora es 'matchedPatterns'
      },
      remediation:
        "Implement strict path sanitization using path.resolve() and verify the result starts with the intended base directory. Avoid manual string replacements for path cleaning.",
      cweId: "CWE-22",
      owaspCategory: "A01:2021-Broken Access Control",
    };
  }
}
