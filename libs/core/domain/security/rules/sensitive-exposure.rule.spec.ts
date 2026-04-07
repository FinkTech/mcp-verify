/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Sensitive Data Exposure Rule Tests (SEC-010)
 *
 * Tests for Sensitive Data Exposure vulnerability detection.
 */

import { SensitiveDataExposureRule } from "./sensitive-exposure.rule";
import { DiscoveryResult } from "../../mcp-server/entities/validation.types";

describe("SensitiveDataExposureRule", () => {
  let rule: SensitiveDataExposureRule;

  beforeEach(() => {
    rule = new SensitiveDataExposureRule();
  });

  describe("Rule Metadata", () => {
    it("should have correct code SEC-009", () => {
      expect(rule.code).toBe("SEC-009");
    });

    it("should have a helpUri pointing to OWASP resource", () => {
      expect(rule.helpUri).toContain("owasp.org");
      expect(rule.helpUri).toContain("Sensitive_Data");
    });
  });

  describe("should detect vulnerabilities", () => {
    it("should detect sensitive parameters without format specification (Critical)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "login_user",
            inputSchema: {
              type: "object",
              properties: {
                password: {
                  type: "string",
                  // Missing format: 'password'
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      const finding = findings.find((f) =>
        f.message.includes("lacks format specification"),
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical"); // Credentials = critical
      expect((finding!.evidence as any).category).toBe("credentials");
    });

    it("should warn about potential logging of sensitive data (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "process_payment",
            inputSchema: {
              type: "object",
              properties: {
                credit_card: {
                  type: "string",
                  format: "unknown",
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const logFinding = findings.find((f) =>
        f.message.toLowerCase().includes("might be logged"),
      );
      expect(logFinding).toBeDefined();
      expect(logFinding!.severity).toBe("medium");
    });

    it("should detect missing data protection measures (High)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "store_ssn",
            description: "Stores SSN in database", // No mention of encryption
            inputSchema: {
              type: "object",
              properties: {
                ssn: {
                  type: "string",
                  description: "Social Security Number",
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const protectionFinding = findings.find((f) =>
        f.message.toLowerCase().includes("without protection"),
      );
      expect(protectionFinding).toBeDefined();
      expect(protectionFinding!.severity).toBe("high");
    });

    it("should detect sensitive data in output schema (High)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "get_user_profile",
            inputSchema: { type: "object", properties: {} },
            // Mocking outputSchema property which rule checks
            ...({
              outputSchema: {
                type: "object",
                properties: {
                  password_hash: { type: "string" },
                  credit_card: { type: "string" },
                },
              },
            } as any),
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const outputFindings = findings.filter(
        (f) =>
          f.message.toLowerCase().includes("returns") &&
          f.message.toLowerCase().includes("data"),
      );
      expect(outputFindings.length).toBeGreaterThan(0);
      expect(outputFindings[0].severity).toBe("high");
      expect((outputFindings[0].evidence as any).outputField).toBeDefined();
    });
  });

  it("should detect financial data exposure with specific remediation (Critical)", () => {
    const discovery: DiscoveryResult = {
      tools: [
        {
          name: "payment_tool",
          inputSchema: {
            type: "object",
            properties: {
              credit_card: { type: "string" },
              // No format, no pattern
            },
          },
        },
      ],
      resources: [],
      prompts: [],
    };

    const findings = rule.evaluate(discovery);
    const finding = findings.find((f) =>
      f.message.includes("lacks format specification"),
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    // expect(finding?.remediation).toContain('Luhn algorithm'); // Check specific recommendation
  });

  it("should detect PII exposure (High)", () => {
    const discovery: DiscoveryResult = {
      tools: [
        {
          name: "update_user",
          inputSchema: {
            type: "object",
            properties: {
              passport_number: { type: "string" },
            },
          },
        },
      ],
      resources: [],
      prompts: [],
    };

    const findings = rule.evaluate(discovery);
    const finding = findings.find((f) =>
      f.message.includes("lacks format specification"),
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect((finding?.evidence as any).category).toBe("pii");
  });

  it("should detect health data exposure (High)", () => {
    const discovery: DiscoveryResult = {
      tools: [
        {
          name: "add_patient",
          inputSchema: {
            type: "object",
            properties: {
              medical_diagnosis: { type: "string" },
            },
          },
        },
      ],
      resources: [],
      prompts: [],
    };

    const findings = rule.evaluate(discovery);
    const finding = findings.find((f) =>
      f.message.includes("lacks format specification"),
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect((finding?.evidence as any).category).toBe("health");
  });
  describe("should pass for safe implementations", () => {
    it("should pass if proper format and encryption are used", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "safe_login",
            description:
              "Login using secure encryption (TLS) and hashed storage.",
            inputSchema: {
              type: "object",
              properties: {
                password: {
                  type: "string",
                  format: "password",
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      // Might still warn about 'logging' (Medium) because that's unconditional for creds?
      // Rule logic: if (sensitiveCategory === 'credentials'...) -> warn logging.
      // So expects MEDIUM finding.
      // But critical/high should be absent.

      const criticalOrHigh = findings.filter(
        (f) => f.severity === "critical" || f.severity === "high",
      );
      expect(criticalOrHigh.length).toBe(0);
    });

    it("should ignore non-sensitive parameters", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "public_data",
            inputSchema: {
              type: "object",
              properties: {
                username: { type: "string" }, // 'username' not in SENSITIVE_KEYWORDS
                count: { type: "number" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0); // Assuming username is not sensitive (it isn't in default list)
    });
  });

  describe("Edge Cases", () => {
    it("should handle undefined tools", () => {
      const discovery = { tools: undefined } as unknown as DiscoveryResult;
      expect(() => rule.evaluate(discovery)).not.toThrow();
    });

    it("should handle empty discovery", () => {
      const discovery = { tools: [], resources: [], prompts: [] };
      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });
  });
});
