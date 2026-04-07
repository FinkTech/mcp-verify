/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Insecure Deserialization Rule Tests (SEC-006)
 *
 * Tests for Insecure Deserialization vulnerability detection.
 */

import { InsecureDeserializationRule } from "./insecure-deserialization.rule";
import { DiscoveryResult } from "../../mcp-server/entities/validation.types";

describe("InsecureDeserializationRule", () => {
  let rule: InsecureDeserializationRule;

  beforeEach(() => {
    rule = new InsecureDeserializationRule();
  });

  describe("Rule Metadata", () => {
    it("should have correct code SEC-006", () => {
      expect(rule.code).toBe("SEC-006");
    });

    it("should have valid tags for CWE and OWASP mapping", () => {
      expect(rule.tags).toContain("CWE-502");
      expect(rule.tags).toContain("OWASP-A08:2021");
    });

    it("should have a helpUri pointing to OWASP resource", () => {
      expect(rule.helpUri).toContain("owasp.org");
      expect(rule.helpUri).toContain("Deserialization");
    });
  });

  describe("should detect vulnerabilities", () => {
    it("should detect dangerous formats (Critical)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "restore_state",
            description: "Restores object state from a Python pickle file",
            inputSchema: {
              type: "object",
              properties: {
                data: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      const critical = findings.find((f) => f.severity === "critical");
      expect(critical).toBeDefined();
      expect(critical!.message).toContain(
        "appears to deserialize dangerous format:",
      );
      expect((critical!.evidence as any).dangerousFormat).toBe("pickle");
    });

    it("should detect unsafe YAML loading (Critical)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "config_loader",
            description: "Loads configuration using yaml.load()",
            inputSchema: {
              type: "object",
              properties: {
                config: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      const yamlFinding = findings.find((f) =>
        f.message.includes("unsafe YAML"),
      );
      expect(yamlFinding).toBeDefined();
      expect(yamlFinding!.severity).toBe("critical");
    });

    it("should detect untyped parameters (Critical)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "deserialize_object",
            description: "Deserialize arbitrary object",
            inputSchema: {
              type: "object",
              properties: {
                // No type defined!
                payload: { description: "The payload" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const paramFinding = findings.find(
        (f) => f.location?.parameter === "payload",
      );
      expect(paramFinding).toBeDefined();
      expect(paramFinding!.severity).toBe("critical");
      expect(paramFinding!.message).toContain(
        "is an object without explicit type, allowing arbitrary object injection",
      );
    });

    it("should detect arbitrary object parameters (High)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "parse_blob",
            description: "Parse data blob",
            inputSchema: {
              type: "object",
              properties: {
                data: {
                  type: "object",
                  // No properties defined = arbitrary object
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const paramFinding = findings.find(
        (f) => f.location?.parameter === "data",
      );
      expect(paramFinding).toBeDefined();
      expect(paramFinding!.severity).toBe("high");
      expect(paramFinding!.message).toContain(
        "allows arbitrary object properties, which can lead to injection attacks",
      );
    });

    it("should warn about encoded data (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "decode_token",
            description: "Decodes a token",
            inputSchema: {
              type: "object",
              properties: {
                encoded_token: {
                  type: "string",
                  format: "base64",
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const finding = findings.find((f) => f.severity === "medium");
      expect(finding).toBeDefined();
      expect(finding!.message).toContain("accepts encoded data");
    });
  });

  describe("should pass for safe implementations", () => {
    it("should pass for safe formats like JSON", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "parse_json",
            description: "Parses secure JSON data with schema validation",
            inputSchema: {
              type: "object",
              properties: {
                json_string: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      // Might trigger 'warn if no safe practices' if description doesn't explicitly match SAFE_INDICATORS
      // description has 'schema validation' -> SAFE_INDICATOR.
      // So no findings.
      expect(findings.length).toBe(0);
    });

    it("should ignore non-deserialization tools", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "calculate_sum",
            description: "Adds two numbers",
            inputSchema: {
              type: "object",
              properties: {
                a: { type: "number" },
                b: { type: "number" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
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
