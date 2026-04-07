/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SSRF Detection Rule Tests (SEC-004)
 *
 * Tests for Server-Side Request Forgery vulnerability detection.
 */

import { SSRFDetectionRule } from "./ssrf.rule";
import { DiscoveryResult } from "../../mcp-server/entities/validation.types";

describe("SSRFDetectionRule", () => {
  let rule: SSRFDetectionRule;

  beforeEach(() => {
    rule = new SSRFDetectionRule();
  });

  describe("Rule Metadata", () => {
    it("should have correct code SEC-004", () => {
      expect(rule.code).toBe("SEC-004");
    });

    it("should have valid tags for CWE and OWASP mapping", () => {
      expect(rule.tags).toContain("CWE-918");
      expect(rule.tags).toContain("OWASP-A10:2021");
    });

    it("should have a helpUri pointing to OWASP resource", () => {
      expect(rule.helpUri).toContain("owasp.org");
      expect(rule.helpUri).toContain("Request_Forgery");
    });
  });

  describe("should detect vulnerabilities", () => {
    it("should detect URL parameters without validation pattern (High)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "fetch_data",
            description: "Fetches data from a URL",
            inputSchema: {
              type: "object",
              properties: {
                target_url: {
                  type: "string",
                  description: "The URL to fetch",
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
      expect(findings[0].severity).toBe("high");
      expect(findings[0].message).toContain(
        "appears to be a URL input without validation",
      );
    });

    it("should detect unanchored patterns (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "webhook_register",
            description: "Register a webhook",
            inputSchema: {
              type: "object",
              properties: {
                callback_link: {
                  type: "string",
                  pattern: "https://api.example.com", // Unanchored, allows 'https://api.example.com.evil.com'
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
      expect(findings[0].severity).toBe("medium");
      expect(
        ((findings[0].evidence as any).issue as string).toLowerCase(),
      ).toContain("not anchored");
    });

    it("should detect patterns allowing insecure HTTP (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "proxy",
            description: "Simple proxy",
            inputSchema: {
              type: "object",
              properties: {
                endpoint: {
                  type: "string",
                  pattern: "^http://.*$", // Allows http
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
      expect(findings[0].severity).toBe("medium");
      expect(
        ((findings[0].evidence as any).issue as string).toLowerCase(),
      ).toContain("allows insecure http");
    });

    it("should detect permissive wildcard patterns (Medium)", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "verify_link",
            inputSchema: {
              type: "object",
              properties: {
                link: {
                  type: "string",
                  pattern: "^.*$", // Matches everything
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
      expect(findings[0].severity).toBe("medium");
      expect(
        ((findings[0].evidence as any).issue as string).toLowerCase(),
      ).toContain("starts with wildcard");
    });
  });

  describe("edge cases & behavior checks", () => {
    it("should behavior check: format: uri without pattern silences High warning (current implementation)", () => {
      // NOTE: This test documents current behavior. If verifying strict security,
      // this arguably SHOULD produce a finding. But we test "what is", then we can strictify.
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "download",
            inputSchema: {
              type: "object",
              properties: {
                source: {
                  type: "string",
                  format: "uri",
                  // No pattern
                },
              },
            },
          },
        ],
        resources: [],
        prompts: [],
      };

      const findings = rule.evaluate(discovery);
      // As analyzed, the code skips if format is present.
      // So we expect 0 findings currently.
      expect(findings.length).toBe(0);
    });
  });

  describe("should pass for safe implementations", () => {
    it("should pass for strict, anchored HTTPS patterns", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "safe_webhook",
            inputSchema: {
              type: "object",
              properties: {
                url: {
                  type: "string",
                  pattern: "^https://trusted\\.domain\\.com/api/.*$",
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

    it("should ignore non-string parameters", () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: "set_url_count",
            inputSchema: {
              type: "object",
              properties: {
                url_count: { type: "number" },
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
