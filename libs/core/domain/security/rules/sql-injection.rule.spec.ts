/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SQL Injection Rule Tests (SEC-003)
 *
 * Tests for SQL injection vulnerability detection in MCP server tools.
 */

import { SQLInjectionRule } from "./sql-injection.rule";
import { DiscoveryResult } from "../../mcp-server/entities/validation.types";

describe("SQLInjectionRule", () => {
  let rule: SQLInjectionRule;

  beforeEach(() => {
    rule = new SQLInjectionRule();
  });

  describe("Rule Metadata", () => {
    it("should have correct code SEC-003", () => {
      expect(rule.code).toBe("SEC-003");
    });

    it("should have a helpUri pointing to OWASP resource", () => {
      expect(rule.helpUri).toContain("owasp.org");
      expect(rule.helpUri).toContain("SQL_Injection");
    });
  });

  describe("should detect vulnerabilities", () => {
    it("should detect SQL tool with unvalidated query parameter", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "execute_query",
            description: "Executes a SQL query against the database",
            inputSchema: {
              type: "object",
              properties: {
                query: { type: "string" }, // No pattern - vulnerable
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe("critical");
      expect(findings[0].ruleCode).toBe("SEC-003");
    });

    it("should detect database tool with weak pattern", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "db_select",
            description: "Runs SELECT queries",
            inputSchema: {
              type: "object",
              properties: {
                sql: {
                  type: "string",
                  pattern: ".*", // Allows everything
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
      expect(findings.some((f) => f.severity === "critical")).toBe(true);
    });

    it("should detect sensitive parameter names without validation", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "search_database",
            description: "Searches records in database",
            inputSchema: {
              type: "object",
              properties: {
                where_clause: { type: "string" }, // Suspicious name
                filter: { type: "string" }, // Also suspicious
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("should detect SQL tool without input schema", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "run_mysql",
            description: "Runs MySQL commands",
            // No inputSchema - suspicious for SQL tool
          } as any, // Intentionally testing edge case
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe("medium");
    });
  });

  describe("should pass for safe implementations", () => {
    it("should pass for strict alphanumeric patterns", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "get_user_by_id",
            description: "Retrieves user from database",
            inputSchema: {
              type: "object",
              properties: {
                id: {
                  type: "string",
                  pattern: "^[0-9]+$", // Strict numeric only
                },
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

    it("should pass for tools mentioning parameterized queries", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "db_query",
            description:
              "Executes parameterized/prepared statements only. Uses prepared statements for all queries.",
            inputSchema: {
              type: "object",
              properties: {
                table: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      // Should pass or have reduced severity due to safe practice indicators
      const criticalFindings = findings.filter(
        (f) => f.severity === "critical",
      );
      expect(criticalFindings.length).toBe(0);
    });

    it("should pass for non-SQL tools", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "send_email",
            description: "Sends an email notification",
            inputSchema: {
              type: "object",
              properties: {
                to: { type: "string" },
                subject: { type: "string" },
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

    it("should handle ORM-based tools with reduced severity", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "prisma_query",
            description: "Uses Prisma ORM for database access",
            inputSchema: {
              type: "object",
              properties: {
                model: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      // ORMs typically have safer patterns
      const criticalFindings = findings.filter(
        (f) => f.severity === "critical",
      );
      expect(criticalFindings.length).toBe(0);
    });
  });

  describe("edge cases", () => {
    it("should handle empty discovery result", () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it("should handle discovery with undefined tools", () => {
      const discovery: DiscoveryResult = {
        tools: undefined as any,
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it("should handle tool with empty properties", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "db_status",
            description: "Checks database connection status",
            inputSchema: {
              type: "object",
              properties: {},
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      // No findings expected for tool with no parameters
      expect(findings.length).toBe(0);
    });
  });
});
