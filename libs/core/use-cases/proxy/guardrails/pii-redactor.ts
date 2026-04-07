/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * PII Redaction Guardrail
 *
 * Automatically detects and redacts Personally Identifiable Information (PII)
 * in requests and responses to prevent sensitive data leakage.
 *
 * Detects:
 * - Social Security Numbers (SSN)
 * - Credit Card Numbers
 * - Email addresses
 * - Phone numbers
 * - IP addresses
 * - API keys and tokens
 *
 * @module libs/core/use-cases/proxy/guardrails/pii-redactor
 */

import { t } from "@mcp-verify/shared";
import type { IGuardrail, InterceptResult } from "../proxy.types";
import type {
  JsonValue,
  JsonObject,
} from "../../../domain/shared/common.types";

export class PIIRedactor implements IGuardrail {
  name = t("guardrail_pii_redaction");

  /**
   * Regex patterns for detecting PII.
   * Ordered by sensitivity (most sensitive first).
   */
  private patterns = {
    // API Keys: sk_live_1234567890abcdef (Stripe-like)
    apiKey: {
      pattern: /\b[a-z]{2,}_[a-z]{4,}_[A-Za-z0-9]{16,}\b/g,
      replacement: (match: string) => {
        const parts = match.split("_");
        return `${parts[0]}_${parts[1]}_${"*".repeat(16)}`;
      },
      description: t("guardrail_pii_api_key"),
    },

    // JWT Tokens: eyJ... (simplified)
    jwt: {
      pattern:
        /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      replacement: "eyJ***REDACTED_JWT***",
      description: "JWT Token",
    },

    // SSN: 123-45-6789
    ssn: {
      pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
      replacement: "***-**-****",
      description: t("guardrail_pii_ssn"),
    },

    // Credit Card: 4532-1234-5678-9010 or 4532123456789010
    creditCard: {
      pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      replacement: "****-****-****-****",
      description: t("guardrail_pii_cc"),
    },

    // Email: user@example.com
    email: {
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      replacement: (match: string) => {
        const parts = match.split("@");
        const username = parts[0];
        const domain = parts[1];
        const redactedUsername =
          username.length > 2
            ? username[0] +
              "*".repeat(username.length - 2) +
              username[username.length - 1]
            : "***";
        return `${redactedUsername}@${domain}`;
      },
      description: t("guardrail_pii_email"),
    },

    // Phone: +1-555-123-4567, (555) 123-4567, 555.123.4567
    phone: {
      pattern:
        /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
      replacement: "***-***-****",
      description: t("guardrail_pii_phone"),
    },

    // IPv4: 192.168.1.1
    ipAddress: {
      pattern: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
      replacement: "***.***.***.***",
      description: t("guardrail_pii_address"),
    },

    // Generic tokens/secrets: token=abc123def456 or secret=xyz789
    genericToken: {
      pattern:
        /(token|secret|password|passwd|pwd)\s*[=:]\s*([A-Za-z0-9+/=\-_]{8,})/gi,
      replacement: (match: string, label: string, value: string) => {
        return `${label}=***REDACTED***`;
      },
      description: t("guardrail_pii_api_key"),
    },

    // Passport numbers: A12345678 (simplified)
    passport: {
      pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g,
      replacement: "***REDACTED_PASSPORT***",
      description: t("md_executive_security_report"),
    },

    // Driver's License: varies by state, this is simplified
    driversLicense: {
      pattern: /\b[A-Z]{1,2}[0-9]{5,8}\b/g,
      replacement: "***REDACTED_DL***",
      description: t("guardrail_pii_api_key"),
    },
  };

  /**
   * Additional configuration
   */
  private config = {
    logRedactions: true,
    strictMode: true, // If true, block instead of redact for critical PII
    criticalPatterns: ["ssn", "creditCard", "passport"], // Patterns that trigger blocking in strict mode
  };

  inspectRequest(message: JsonValue): InterceptResult {
    const result = this.redactMessage(message, "request");

    // In strict mode, block requests containing critical PII
    if (this.config.strictMode && result.hadCriticalPII) {
      return {
        action: "block",
        reason: `Blocked request containing sensitive PII: ${result.detectedTypes.join(", ")}`,
      };
    }

    if (result.wasRedacted) {
      return {
        action: "modify",
        modifiedMessage: result.message,
        reason: `Redacted PII in request: ${result.detectedTypes.join(", ")}`,
      };
    }

    return { action: "allow" };
  }

  inspectResponse(message: JsonValue): InterceptResult {
    const result = this.redactMessage(message, "response");

    if (result.wasRedacted) {
      return {
        action: "modify",
        modifiedMessage: result.message,
        reason: `Redacted PII in response: ${result.detectedTypes.join(", ")}`,
      };
    }

    return { action: "allow" };
  }

  /**
   * Redact PII from a message (request or response)
   */
  private redactMessage(
    message: JsonValue,
    type: "request" | "response",
  ): {
    message: JsonValue;
    wasRedacted: boolean;
    hadCriticalPII: boolean;
    detectedTypes: string[];
  } {
    const detectedTypes: string[] = [];
    let hadCriticalPII = false;

    // Deep clone to avoid mutating original
    let redactedMessage: JsonObject;
    try {
      redactedMessage = JSON.parse(JSON.stringify(message));
    } catch (error) {
      // If cloning fails, return original message (unlikely but safe)
      return {
        message,
        wasRedacted: false,
        hadCriticalPII: false,
        detectedTypes: [],
      };
    }

    // Convert to string for pattern matching
    const messageStr = JSON.stringify(message);
    let redactedStr = messageStr;
    let wasRedacted = false;

    // Apply each pattern
    for (const [patternName, patternConfig] of Object.entries(this.patterns)) {
      const { pattern, replacement, description } = patternConfig;

      // Test if pattern matches
      if (pattern.test(redactedStr)) {
        detectedTypes.push(description);

        // Check if this is a critical pattern
        if (this.config.criticalPatterns.includes(patternName)) {
          hadCriticalPII = true;
        }

        // CRITICAL: Reset lastIndex BEFORE replace (test() consumed the match)
        pattern.lastIndex = 0;

        // Apply redaction
        if (typeof replacement === "function") {
          redactedStr = redactedStr.replace(pattern, replacement);
        } else {
          redactedStr = redactedStr.replace(pattern, replacement as string);
        }

        wasRedacted = true;

        // Reset pattern lastIndex again for next iteration
        pattern.lastIndex = 0;
      }
    }

    // Parse back to object if redacted
    if (wasRedacted) {
      try {
        const parsed = JSON.parse(redactedStr);
        Object.assign(redactedMessage, parsed);
      } catch (e) {
        // If parsing fails, use original message
        // This shouldn't happen with our patterns
      }
    }

    return {
      message: redactedMessage,
      wasRedacted,
      hadCriticalPII,
      detectedTypes,
    };
  }

  /**
   * Configure the PII Redactor
   */
  configure(options: {
    logRedactions?: boolean;
    strictMode?: boolean;
    criticalPatterns?: string[];
  }) {
    Object.assign(this.config, options);
  }
}
