/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { SensitiveCommandBlocker } from "../sensitive-command-blocker";
import { PIIRedactor } from "../pii-redactor";
import { InputSanitizer } from "../input-sanitizer";

describe("Security Guardrails", () => {
  describe("SensitiveCommandBlocker", () => {
    const blocker = new SensitiveCommandBlocker();

    it("should block dangerous commands", () => {
      const result = blocker.inspectRequest({
        method: "tools/call",
        params: { arguments: { cmd: "rm -rf /" } },
      });
      expect(result.action).toBe("block");
      // @ts-ignore
      expect(result.reason).toContain("rm -rf");
    });

    it("should allow safe commands", () => {
      const result = blocker.inspectRequest({
        method: "tools/call",
        params: { arguments: { cmd: "echo hello" } },
      });
      expect(result.action).toBe("allow");
    });
  });

  describe("PIIRedactor", () => {
    const redactor = new PIIRedactor();

    it("should redact email addresses", () => {
      const result = redactor.inspectResponse({
        content: "Contact me at user@example.com",
      });
      // PIIRedactor returns 'modify' when PII is detected and redacted
      expect(result.action).toBe("modify");
      // @ts-ignore
      const str = JSON.stringify(result.modifiedMessage);
      expect(str).not.toContain("user@example.com");
      // Verify redaction happened (contains asterisks and domain)
      expect(str).toContain("example.com");
      expect(str).toContain("*");
    });
  });

  describe("InputSanitizer", () => {
    const sanitizer = new InputSanitizer();

    it("should sanitize basic injection attempts", () => {
      const result = sanitizer.inspectRequest({
        method: "tools/call",
        params: { arguments: { input: "; DROP TABLE users;" } },
      });
      // InputSanitizer defaults to 'modify' (sanitizing) unless strictMode is on
      expect(result.action).toBe("modify");

      // Verify items removed (semicolons are removed by SQL filter)
      // @ts-ignore
      const modifiedArgs = result.modifiedMessage.params.arguments;
      expect(modifiedArgs.input).not.toContain(";");
    });
  });
});
