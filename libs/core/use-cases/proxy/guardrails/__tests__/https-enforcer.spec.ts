/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Comprehensive tests for HttpsEnforcer Guardrail
 *
 * Tests cover:
 * - HTTP URL detection and blocking
 * - Auto-upgrade functionality
 * - Localhost whitelisting
 * - Custom host whitelisting
 * - Mixed content detection
 * - Edge cases
 */

import { HttpsEnforcer } from "../https-enforcer";

describe("HttpsEnforcer", () => {
  let enforcer: HttpsEnforcer;

  beforeEach(() => {
    enforcer = new HttpsEnforcer();
    enforcer.configure({ logViolations: false }); // Disable logging for tests
  });

  describe("HTTP URL Detection", () => {
    test("should block HTTP URLs by default", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://example.com/data" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("block");
      expect(result.reason).toContain("Detected insecure URLs:");
      expect(result.reason).toContain("http://example.com/data");
    });

    test("should allow HTTPS URLs", () => {
      const message = {
        method: "tools/call",
        params: { url: "https://example.com/data" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });

    test("should detect multiple HTTP URLs", () => {
      const message = {
        method: "tools/call",
        params: {
          urls: ["http://site1.com", "http://site2.com", "http://site3.com"],
        },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("block");
      expect(result.reason).toContain("http://site1.com");
      expect(result.reason).toContain("http://site2.com");
      expect(result.reason).toContain("http://site3.com");
    });

    test("should detect HTTP URLs in nested objects", () => {
      const message = {
        method: "tools/call",
        params: {
          config: {
            api: {
              endpoint: "http://api.example.com",
            },
          },
        },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("block");
      expect(result.reason).toContain("http://api.example.com");
    });

    test("should detect HTTP URLs in strings", () => {
      const message = {
        method: "tools/call",
        params: {
          text: "Please visit http://unsafe.com for more info",
        },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("block");
      expect(result.reason).toContain("http://unsafe.com");
    });
  });

  describe("Auto-Upgrade Functionality", () => {
    beforeEach(() => {
      enforcer.configure({ autoUpgrade: true });
    });

    test("should upgrade HTTP to HTTPS when enabled", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://example.com/data" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("modify");
      expect(result.reason).toContain("Auto-upgraded");

      const modifiedUrl = (result.modifiedMessage as any).params.url;
      expect(modifiedUrl).toBe("https://example.com/data");
    });

    test("should upgrade multiple HTTP URLs", () => {
      const message = {
        method: "tools/call",
        params: {
          urls: ["http://site1.com", "http://site2.com"],
        },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("modify");

      const modifiedUrls = (result.modifiedMessage as any).params.urls;
      expect(modifiedUrls[0]).toBe("https://site1.com");
      expect(modifiedUrls[1]).toBe("https://site2.com");
    });

    test("should not modify HTTPS URLs", () => {
      const message = {
        method: "tools/call",
        params: { url: "https://example.com/data" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });

    test("should preserve URL query parameters during upgrade", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://example.com/api?key=value&foo=bar" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("modify");

      const modifiedUrl = (result.modifiedMessage as any).params.url;
      expect(modifiedUrl).toBe("https://example.com/api?key=value&foo=bar");
    });
  });

  describe("Localhost Whitelisting", () => {
    test("should allow http://localhost by default", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://localhost:3000/api" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });

    test("should allow http://127.0.0.1 by default", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://127.0.0.1:8080/test" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });

    test("should allow http://0.0.0.0 by default", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://0.0.0.0:5000" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });

    test("should block localhost when disabled", () => {
      enforcer.configure({ allowLocalhost: false });

      const message = {
        method: "tools/call",
        params: { url: "http://localhost:3000" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("block");
    });
  });

  describe("Custom Host Whitelisting", () => {
    test("should allow whitelisted HTTP hosts", () => {
      enforcer.allowHttpHost("internal.corp.com");

      const message = {
        method: "tools/call",
        params: { url: "http://internal.corp.com/api" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });

    test("should block non-whitelisted HTTP hosts", () => {
      enforcer.allowHttpHost("trusted.com");

      const message = {
        method: "tools/call",
        params: { url: "http://untrusted.com/api" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("block");
    });

    test("should allow multiple whitelisted hosts", () => {
      enforcer.allowHttpHost("internal1.com");
      enforcer.allowHttpHost("internal2.com");

      const message1 = {
        method: "tools/call",
        params: { url: "http://internal1.com/api" },
      };
      const message2 = {
        method: "tools/call",
        params: { url: "http://internal2.com/api" },
      };

      expect(enforcer.inspectRequest(message1).action).toBe("allow");
      expect(enforcer.inspectRequest(message2).action).toBe("allow");
    });

    test("should remove hosts from whitelist", () => {
      enforcer.allowHttpHost("temp.com");

      const message = {
        method: "tools/call",
        params: { url: "http://temp.com/api" },
      };

      // Should be allowed initially
      expect(enforcer.inspectRequest(message).action).toBe("allow");

      // Remove from whitelist
      enforcer.disallowHttpHost("temp.com");

      // Should now be blocked
      expect(enforcer.inspectRequest(message).action).toBe("block");
    });
  });

  describe("Mixed Content Detection", () => {
    test("should detect mixed HTTP and HTTPS content", () => {
      const message = {
        method: "tools/call",
        params: {
          urls: ["https://secure.com/api", "http://insecure.com/data"],
        },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("block");
      expect(result.reason).toContain("Mixed content detected");
    });

    test("should allow pure HTTPS content", () => {
      const message = {
        method: "tools/call",
        params: {
          urls: ["https://site1.com", "https://site2.com"],
        },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });

    test("should allow mixed content when disabled", () => {
      enforcer.configure({ blockMixedContent: false });

      const message = {
        method: "tools/call",
        params: {
          urls: ["https://secure.com", "http://insecure.com"],
        },
      };
      const result = enforcer.inspectRequest(message);

      // Should block HTTP URL, but not because of mixed content
      expect(result.action).toBe("block");
      expect(result.reason).not.toContain("Mixed content");
    });
  });

  describe("Edge Cases", () => {
    test("should handle empty messages", () => {
      const result = enforcer.inspectRequest({});
      expect(result.action).toBe("allow");
    });

    test("should handle null values", () => {
      const message = { params: { url: null } };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("allow");
    });

    test("should handle messages without URLs", () => {
      const message = {
        method: "tools/call",
        params: { text: "This is just text without URLs" },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("allow");
    });

    test("should handle malformed URLs", () => {
      const message = {
        method: "tools/call",
        params: { url: "not-a-url" },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("allow"); // Malformed URLs not detected
    });

    test("should handle URLs in arrays", () => {
      const message = {
        method: "tools/call",
        params: {
          urls: ["https://safe1.com", "http://unsafe.com", "https://safe2.com"],
        },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("block");
    });

    test("should handle deeply nested URLs", () => {
      const message = {
        method: "tools/call",
        params: {
          level1: {
            level2: {
              level3: {
                url: "http://deep.com",
              },
            },
          },
        },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("block");
    });

    test("should handle disabled enforcer", () => {
      enforcer.configure({ enabled: false });

      const message = {
        method: "tools/call",
        params: { url: "http://insecure.com" },
      };
      const result = enforcer.inspectRequest(message);

      expect(result.action).toBe("allow");
    });
  });

  describe("Response Inspection", () => {
    test("should allow all responses", () => {
      const response = {
        result: {
          data: "http://example.com",
        },
      };
      const result = enforcer.inspectResponse(response);
      expect(result.action).toBe("allow");
    });
  });

  describe("Configuration Management", () => {
    test("should allow getting current configuration", () => {
      const config = enforcer.getConfig();

      expect(config).toHaveProperty("enabled");
      expect(config).toHaveProperty("autoUpgrade");
      expect(config).toHaveProperty("allowLocalhost");
      expect(config).toHaveProperty("blockMixedContent");
    });

    test("should allow partial configuration updates", () => {
      enforcer.configure({ autoUpgrade: true, allowLocalhost: false });

      const config = enforcer.getConfig();
      expect(config.autoUpgrade).toBe(true);
      expect(config.allowLocalhost).toBe(false);
      expect(config.enabled).toBe(true); // Unchanged
    });
  });

  describe("URL Pattern Edge Cases", () => {
    test("should handle URLs with special characters", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://example.com/path?key=value&foo=bar#anchor" },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("block");
    });

    test("should handle URLs with ports", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://example.com:8080/api" },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("block");
    });

    test("should handle URLs with authentication", () => {
      const message = {
        method: "tools/call",
        params: { url: "http://user:pass@example.com/api" },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("block");
    });

    test("should handle URLs in text surrounded by quotes", () => {
      const message = {
        method: "tools/call",
        params: { text: 'Visit "http://example.com" for details' },
      };
      const result = enforcer.inspectRequest(message);
      expect(result.action).toBe("block");
    });
  });
});
