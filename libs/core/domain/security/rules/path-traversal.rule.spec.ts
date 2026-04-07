/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Path Traversal Rule Tests (SEC-001)
 *
 * Tests for path traversal vulnerability detection in MCP server tools and resources.
 */

import { PathTraversalRule } from "./path-traversal.rule";
import { DiscoveryResult } from "../../mcp-server/entities/validation.types";

describe("PathTraversalRule", () => {
  let rule: PathTraversalRule;

  beforeEach(() => {
    rule = new PathTraversalRule();
  });

  describe("Rule Metadata", () => {
    it("should have correct code SEC-007", () => {
      expect(rule.code).toBe("SEC-007");
    });

    it("should have valid tags for CWE and OWASP mapping", () => {
      expect(rule.tags).toContain("CWE-22");
      expect(rule.tags).toContain("OWASP-A01:2021");
    });

    it("should have a helpUri pointing to OWASP resource", () => {
      expect(rule.helpUri).toContain("owasp.org");
      expect(rule.helpUri).toContain("Path_Traversal");
    });
  });

  describe("should detect vulnerabilities in tools", () => {
    it("should detect path parameters without validation pattern", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "read_file",
            description: "Reads a file from disk",
            inputSchema: {
              type: "object",
              properties: {
                filename: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe("high");
      expect(findings[0].message.toLowerCase()).toContain(
        "no path validation pattern detected",
      );
    });

    it("should detect path parameters with weak validation pattern", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "write_file",
            description: "Writes data to a file",
            inputSchema: {
              type: "object",
              properties: {
                filepath: {
                  type: "string",
                  pattern: ".*", // Allows anything, including traversal
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
      expect(findings[0].severity).toBe("critical");
      // Using lowercase to be safe against casing changes in translation strings
      expect(findings[0].message.toLowerCase()).toContain(
        "uses weak path validation",
      );
    });

    it("should detect path traversal in directory listing tools", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "list_directory",
            description: "Lists contents of a folder",
            inputSchema: {
              type: "object",
              properties: {
                dir_path: {
                  type: "string",
                  pattern: ".*", // Allows anything including traversal
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
      expect(findings[0].severity).toBe("critical");
    });
  });

  describe("should detect vulnerabilities in resources", () => {
    it("should detect dynamic URIs without restrictions (High)", () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            uri: "https://api.example.com/data/{id}",
            name: "Dynamic Data",
            mimeType: "application/json",
          },
        ],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe("high");
      expect(findings[0].message.toLowerCase()).toContain(
        "uses dynamic uri without restrictions",
      );
    });

    it("should detect file:// URIs with dynamic segments (Critical)", () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            uri: "file:///{path}",
            name: "Local File",
            mimeType: "text/plain",
          },
        ],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      const criticalFinding = findings.find((f) => f.severity === "critical");
      expect(criticalFinding).toBeDefined();
      expect(criticalFinding?.message).toContain(
        "uses file:// scheme with dynamic segments",
      );
    });
  });

  describe("should pass for safe implementations", () => {
    it("should pass for tools with strict patterns", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "get_log",
            description: "Get log file",
            inputSchema: {
              type: "object",
              properties: {
                logfile: {
                  type: "string",
                  pattern: "^[a-z0-9]+\\.log$", // Only allows simple filenames, no slashes or dots
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

    it("should ignore non-path parameters", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "calculate",
            description: "Calculator",
            inputSchema: {
              type: "object",
              properties: {
                expression: { type: "string" },
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

    it("should pass for static URIs", () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            uri: "file:///etc/hosts", // Static, no dynamic parts
            name: "Hosts File",
            mimeType: "text/plain",
          },
        ],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });
  });

  describe("edge cases", () => {
    it('should ignore non-string parameters even if named "path"', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "draw_path",
            description: "Draws a path",
            inputSchema: {
              type: "object",
              properties: {
                path_coordinates: {
                  type: "array", // Array type
                  items: { type: "number" },
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
