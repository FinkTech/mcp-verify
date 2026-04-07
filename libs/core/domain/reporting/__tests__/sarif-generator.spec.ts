/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SARIF Generator Tests
 *
 * Validates that generated SARIF reports conform to SARIF 2.1.0 schema
 */

import { SarifGenerator } from "../sarif-generator";
import {
  Report,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";

describe("SarifGenerator", () => {
  const mockReport: Report = {
    server_name: "test-server",
    url: "http://localhost:3000",
    protocol_version: "2024-11-05",
    status: "invalid",
    timestamp: "2026-02-03T00:00:00Z",
    duration_ms: 100,
    tools: {
      count: 2,
      valid: 2,
      invalid: 0,
      items: [],
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
    quality: {
      score: 85,
      issues: [],
    },
    security: {
      score: 45,
      level: "Critical Risk",
      findings: [
        {
          severity: "critical",
          message: "SQL injection pattern detected",
          component: "tool:execute_query",
          ruleCode: "SEC-002",
          evidence: { description: "Parameter accepts raw SQL" },
          remediation: "Use parameterized queries",
        },
        {
          severity: "high",
          message: "Command injection detected",
          component: "tool:run_command",
          ruleCode: "SEC-002",
          evidence: { description: "Executes shell commands" },
          remediation: "Sanitize input or use safe alternatives",
        },
        {
          severity: "medium",
          message: "Path traversal risk",
          component: "tool:read_file",
          ruleCode: "SEC-001",
          evidence: { description: "File path parameter accepts ../" },
          remediation: "Validate and sanitize file paths",
        },
      ],
      criticalCount: 1,
      highCount: 1,
      mediumCount: 1,
      lowCount: 0,
    },
  };

  describe("generate()", () => {
    it("should generate valid SARIF 2.1.0 structure", () => {
      const sarifJson = SarifGenerator.generate(mockReport);
      const sarif = JSON.parse(sarifJson);

      // Validate top-level structure
      expect(sarif).toHaveProperty(
        "$schema",
        "https://json.schemastore.org/sarif-2.1.0.json",
      );
      expect(sarif).toHaveProperty("version", "2.1.0");
      expect(sarif).toHaveProperty("runs");
      expect(Array.isArray(sarif.runs)).toBe(true);
      expect(sarif.runs.length).toBe(1);
    });

    it("should include tool driver metadata", () => {
      const sarifJson = SarifGenerator.generate(mockReport);
      const sarif = JSON.parse(sarifJson);

      const driver = sarif.runs[0].tool.driver;
      expect(driver).toHaveProperty("name", "mcp-verify");
      expect(driver).toHaveProperty(
        "informationUri",
        "https://github.com/FinkTech/mcp-verify",
      );
      expect(driver).toHaveProperty("version", "1.0.0");
      expect(driver).toHaveProperty("rules");
      expect(Array.isArray(driver.rules)).toBe(true);
    });

    it("should map security findings to SARIF results", () => {
      const sarifJson = SarifGenerator.generate(mockReport);
      const sarif = JSON.parse(sarifJson);

      const results = sarif.runs[0].results;
      expect(results).toHaveLength(3);

      // Check first result (critical finding)
      const criticalResult = results[0];
      expect(criticalResult.ruleId).toBe("SEC-002");
      expect(criticalResult.level).toBe("error"); // critical/high -> error
      expect(criticalResult.message).toHaveProperty(
        "text",
        "SQL injection pattern detected",
      );
      expect(criticalResult.properties).toHaveProperty("evidence");
      expect(criticalResult.properties.evidence).toEqual({
        description: "Parameter accepts raw SQL",
      });
      expect(criticalResult.properties).toHaveProperty(
        "remediation",
        "Use parameterized queries",
      );
    });

    it("should map severity levels correctly", () => {
      const sarifJson = SarifGenerator.generate(mockReport);
      const sarif = JSON.parse(sarifJson);

      const results = sarif.runs[0].results;

      // Critical -> error
      expect(results[0].level).toBe("error");
      // High -> error
      expect(results[1].level).toBe("error");
      // Medium -> warning
      expect(results[2].level).toBe("warning");
    });

    it("should include physical locations for findings", () => {
      const sarifJson = SarifGenerator.generate(mockReport);
      const sarif = JSON.parse(sarifJson);

      const results = sarif.runs[0].results;

      results.forEach((result: any) => {
        expect(result).toHaveProperty("locations");
        expect(Array.isArray(result.locations)).toBe(true);
        expect(result.locations.length).toBeGreaterThan(0);

        const location = result.locations[0];
        expect(location).toHaveProperty("physicalLocation");
        expect(location.physicalLocation).toHaveProperty("artifactLocation");
        expect(location.physicalLocation).toHaveProperty("region");
        expect(location.physicalLocation.region).toHaveProperty("startLine");
      });
    });

    it("should extract unique rules from findings", () => {
      const sarifJson = SarifGenerator.generate(mockReport);
      const sarif = JSON.parse(sarifJson);

      const rules = sarif.runs[0].tool.driver.rules;

      // Should have 2 unique rules (SEC-001 and SEC-002)
      expect(rules.length).toBe(2);

      // Check rule structure
      rules.forEach((rule: any) => {
        expect(rule).toHaveProperty("id");
        expect(rule).toHaveProperty("name");
        expect(rule).toHaveProperty("shortDescription");
        expect(rule.shortDescription).toHaveProperty("text");
        expect(rule).toHaveProperty("helpUri");
        expect(rule).toHaveProperty("properties");
        expect(rule.properties).toHaveProperty("tags");
      });
    });

    it("should handle empty findings gracefully", () => {
      const emptyReport: Report = {
        ...mockReport,
        security: {
          score: 100,
          level: "Low Risk",
          findings: [],
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
        },
      };

      const sarifJson = SarifGenerator.generate(emptyReport);
      const sarif = JSON.parse(sarifJson);

      expect(sarif.runs[0].results).toHaveLength(0);
      expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
    });

    it("should produce parseable JSON", () => {
      const sarifJson = SarifGenerator.generate(mockReport);

      // Should not throw
      expect(() => JSON.parse(sarifJson)).not.toThrow();

      const sarif = JSON.parse(sarifJson);
      expect(typeof sarif).toBe("object");
    });

    it("should include all required SARIF properties", () => {
      const sarifJson = SarifGenerator.generate(mockReport);
      const sarif = JSON.parse(sarifJson);

      // Top-level required properties
      expect(sarif).toHaveProperty("$schema");
      expect(sarif).toHaveProperty("version");
      expect(sarif).toHaveProperty("runs");

      // Run required properties
      const run = sarif.runs[0];
      expect(run).toHaveProperty("tool");
      expect(run).toHaveProperty("results");

      // Tool driver required properties
      expect(run.tool.driver).toHaveProperty("name");
    });

    it("should format output with proper indentation", () => {
      const sarifJson = SarifGenerator.generate(mockReport);

      // Should be pretty-printed (contains newlines and spaces)
      expect(sarifJson).toContain("\n");
      expect(sarifJson).toContain("  "); // 2-space indentation
    });
  });
});
