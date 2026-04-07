/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { t } from "@mcp-verify/shared";
import type { IGuardrail, InterceptResult } from "../proxy.types";
import type { JsonValue } from "../../../domain/shared/common.types";

export class SensitiveCommandBlocker implements IGuardrail {
  name = t("guardrail_sensitive_blocker");

  private blockedPatterns = [
    "rm -rf",
    "mkfs",
    "dd if=",
    ":(){ :|:& };:",
    "wget",
    "curl",
  ];

  inspectRequest(message: JsonValue): InterceptResult {
    // Type guard: ensure message is an object
    if (!message || typeof message !== "object" || Array.isArray(message)) {
      return { action: "allow" };
    }

    const msgObj = message as Record<string, unknown>;
    if (msgObj.method === "tools/call") {
      const params = msgObj.params as Record<string, unknown> | undefined;
      const argsStr = JSON.stringify(params?.arguments || {});
      for (const pattern of this.blockedPatterns) {
        if (argsStr.includes(pattern)) {
          return {
            action: "block",
            reason: t("guardrail_sensitive_cmd", { pattern }),
          };
        }
      }
    }
    return { action: "allow" };
  }

  inspectResponse(message: JsonValue): InterceptResult {
    return { action: "allow" };
  }
}
