/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Authentication Bypass Rule Tests (SEC-009)
 *
 * Tests for authentication vulnerability detection in MCP server tools.
 */

import { AuthenticationBypassRule } from "./auth-bypass.rule";
import { DiscoveryResult } from "../../mcp-server/entities/validation.types";

describe("AuthenticationBypassRule", () => {
  let rule: AuthenticationBypassRule;

  beforeEach(() => {
    rule = new AuthenticationBypassRule();
  });

  describe("Rule Metadata", () => {
    it("should have correct code SEC-001", () => {
      expect(rule.code).toBe("SEC-001");
    });

    it("should have a helpUri pointing to OWASP resource", () => {
      expect(rule.helpUri).toContain("owasp.org");
      expect(rule.helpUri).toContain("Authentication");
    });
  });

  describe("should detect vulnerabilities", () => {
    it("should detect tools using weak hashing algorithms", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "create_user",
            description: "Creates a user and stores password using MD5 hashing",
            inputSchema: {
              type: "object",
              properties: {
                username: { type: "string" },
                password: { type: "string" },
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
      expect(findings[0].message.toLowerCase()).toContain(
        "uses weak hashing algorithms",
      );
    });

    it("should detect password parameters without minimum length", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "register",
            description: "User registration with bcrypt",
            inputSchema: {
              type: "object",
              properties: {
                username: { type: "string" },
                password: {
                  type: "string",
                  // No minLength
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
      const lengthFinding = findings.find((f) =>
        f.message.includes("minimum length"),
      );
      expect(lengthFinding).toBeDefined();
      expect(lengthFinding?.severity).toBe("high");
    });

    it("should detect password parameters with insufficient length", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "update_password",
            description: "Updates user password (bcrypt)",
            inputSchema: {
              type: "object",
              properties: {
                new_password: {
                  type: "string",
                  minLength: 4, // Too short
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
      const lengthFinding = findings.find((f) =>
        f.message.includes("minimum length"),
      );
      expect(lengthFinding).toBeDefined();
    });

    it("should detect password parameters without complexity pattern", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "set_credentials",
            description: "Sets user credentials securely",
            inputSchema: {
              type: "object",
              properties: {
                password: {
                  type: "string",
                  minLength: 12,
                  // No pattern for complexity
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const complexityFinding = findings.find((f) =>
        f.message.includes("complexity"),
      );
      expect(complexityFinding).toBeDefined();
      expect(complexityFinding?.severity).toBe("medium");
    });

    it("should detect authentication tools that do not mention hashing", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "store_password",
            description: "Stores user password in the database",
            inputSchema: {
              type: "object",
              properties: {
                password: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const hashFinding = findings.find(
        (f) =>
          f.message.toLowerCase().includes("does not") &&
          f.message.toLowerCase().includes("hashing"),
      );
      expect(hashFinding).toBeDefined();
      expect(hashFinding?.severity).toBe("high");
    });

    it("should detect potential username enumeration (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "login_check_username", // renamed to trigger auth keywords
            description: "Checks if a username is taken",
            inputSchema: {
              type: "object",
              properties: {
                username: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const enumFinding = findings.find((f) =>
        f.message.includes("user enumeration"),
      );
      expect(enumFinding).toBeDefined();
      expect(enumFinding?.severity).toBe("medium");
    });

    it("should detect credential parameters transmitted as plain strings (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "auth_connect_service", // renamed to trigger auth keywords
            description: "Connects to external API",
            inputSchema: {
              type: "object",
              properties: {
                api_key: {
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
      const plainFinding = findings.find((f) =>
        f.message.toLowerCase().includes("plain text credentials"),
      );
      expect(plainFinding).toBeDefined();
      expect(plainFinding?.severity).toBe("medium");
    });

    it("should detect missing brute-force protection (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "simple_login",
            description: "Simple login function",
            inputSchema: {
              type: "object",
              properties: {
                username: { type: "string" },
                password: { type: "string" },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      const bruteForceFinding = findings.find((f) =>
        f.message.toLowerCase().includes("lacks brute force protection"),
      );
      expect(bruteForceFinding).toBeDefined();
      expect(bruteForceFinding?.severity).toBe("medium");
    });
  });

  describe("should pass for safe implementations", () => {
    it("should pass for tools using strong hashing and strong password policies", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "create_admin",
            description:
              "Creates admin. Passwords hashed with Argon2id. Implements rate limiting and brute force protection.",
            inputSchema: {
              type: "object",
              properties: {
                username: { type: "string" },
                password: {
                  type: "string",
                  minLength: 12,
                  pattern:
                    "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$",
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

    it("should pass for non-authentication tools", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "get_weather",
            description: "Gets weather information based on zip code",
            inputSchema: {
              type: "object",
              properties: {
                zip: { type: "string" },
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

  describe("edge cases", () => {
    it("should handle tools with no schema", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "login",
            description: "Login tool",
            // Missing inputSchema
          } as any,
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      // It might return findings about missing hashing info, but shouldn't crash
      expect(Array.isArray(findings)).toBe(true);
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
