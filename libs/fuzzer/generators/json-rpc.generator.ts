/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * JSON-RPC Generator
 *
 * Generates payloads to test MCP protocol compliance and robustness.
 * Targets the JSON-RPC layer with malformed requests, edge cases, and protocol violations.
 */

import {
  IPayloadGenerator,
  GeneratorConfig,
  GeneratedPayload,
} from "./generator.interface";

export class JsonRpcGenerator implements IPayloadGenerator {
  readonly id = "json-rpc";
  readonly name = "JSON-RPC Protocol Generator";
  readonly category = "protocol";
  readonly description =
    "Generates malformed JSON-RPC requests to test protocol robustness";

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // Malformed Structure
    payloads.push(...this.generateMalformedStructure());

    // Invalid IDs
    payloads.push(...this.generateInvalidIds());

    // Method Attacks
    payloads.push(...this.generateMethodAttacks());

    // Params Attacks
    payloads.push(...this.generateParamsAttacks());

    return payloads;
  }

  private generateMalformedStructure(): GeneratedPayload[] {
    return [
      {
        value: { jsonrpc: "1.0", method: "test", id: 1 },
        category: "protocol",
        type: "malformed-version",
        severity: "medium",
        description: "Invalid JSON-RPC version",
        expectedVulnerableBehavior: "Server accepts non-2.0 version",
        tags: ["version", "protocol"],
      },
      {
        value: { method: "test", id: 1 },
        category: "protocol",
        type: "missing-version",
        severity: "low",
        description: "Missing jsonrpc field",
        expectedVulnerableBehavior: "Server processes without version check",
        tags: ["missing-field", "protocol"],
      },
      {
        value: { jsonrpc: "2.0", id: 1 },
        category: "protocol",
        type: "missing-method",
        severity: "medium",
        description: "Missing method field",
        expectedVulnerableBehavior: "Server crashes or hangs",
        tags: ["missing-field", "crash"],
      },
      {
        value: "not a json object",
        category: "protocol",
        type: "invalid-json",
        severity: "low",
        description: "Non-JSON payload",
        expectedVulnerableBehavior: "Server crashes on parse",
        tags: ["parse-error", "crash"],
      },
      {
        value: {
          jsonrpc: "2.0",
          method: "test",
          id: 1,
          extra: "field",
          another: "one",
        },
        category: "protocol",
        type: "extra-fields",
        severity: "low",
        description: "Extra unknown fields",
        expectedVulnerableBehavior: "Server processes extra fields unsafely",
        tags: ["extra-fields", "protocol"],
      },
    ];
  }

  private generateInvalidIds(): GeneratedPayload[] {
    return [
      {
        value: { jsonrpc: "2.0", method: "test", id: -1 },
        category: "protocol",
        type: "negative-id",
        severity: "low",
        description: "Negative request ID",
        expectedVulnerableBehavior: "Server mishandles negative ID",
        tags: ["id", "edge-case"],
      },
      {
        value: {
          jsonrpc: "2.0",
          method: "test",
          id: Number.MAX_SAFE_INTEGER + 1,
        },
        category: "protocol",
        type: "overflow-id",
        severity: "medium",
        description: "Integer overflow in ID",
        expectedVulnerableBehavior: "Server has integer overflow",
        tags: ["id", "overflow"],
      },
      {
        value: { jsonrpc: "2.0", method: "test", id: null },
        category: "protocol",
        type: "null-id",
        severity: "low",
        description: "Null request ID (valid for notification)",
        expectedVulnerableBehavior: "Server confuses notification with request",
        tags: ["id", "null"],
      },
      {
        value: { jsonrpc: "2.0", method: "test", id: { nested: "object" } },
        category: "protocol",
        type: "object-id",
        severity: "medium",
        description: "Object as request ID",
        expectedVulnerableBehavior: "Server accepts invalid ID type",
        tags: ["id", "type-confusion"],
      },
      {
        value: { jsonrpc: "2.0", method: "test", id: "a".repeat(10000) },
        category: "protocol",
        type: "large-id",
        severity: "medium",
        description: "Extremely large string ID",
        expectedVulnerableBehavior: "Server has memory issues with large ID",
        tags: ["id", "dos", "memory"],
      },
    ];
  }

  private generateMethodAttacks(): GeneratedPayload[] {
    return [
      {
        value: { jsonrpc: "2.0", method: "", id: 1 },
        category: "protocol",
        type: "empty-method",
        severity: "low",
        description: "Empty method name",
        expectedVulnerableBehavior: "Server crashes on empty method",
        tags: ["method", "empty"],
      },
      {
        value: { jsonrpc: "2.0", method: "../../../etc/passwd", id: 1 },
        category: "protocol",
        type: "path-traversal-method",
        severity: "high",
        description: "Path traversal in method name",
        expectedVulnerableBehavior: "Server uses method name in file path",
        tags: ["method", "path-traversal"],
      },
      {
        value: { jsonrpc: "2.0", method: "rpc.internal.secret", id: 1 },
        category: "protocol",
        type: "reserved-method",
        severity: "medium",
        description: "Reserved rpc.* method",
        expectedVulnerableBehavior: "Server exposes internal methods",
        tags: ["method", "internal"],
      },
      {
        value: { jsonrpc: "2.0", method: "__proto__", id: 1 },
        category: "protocol",
        type: "prototype-pollution-method",
        severity: "critical",
        description: "Prototype pollution via method name",
        expectedVulnerableBehavior: "Server has prototype pollution",
        tags: ["method", "prototype-pollution"],
      },
    ];
  }

  private generateParamsAttacks(): GeneratedPayload[] {
    return [
      {
        value: { jsonrpc: "2.0", method: "tools/call", id: 1, params: null },
        category: "protocol",
        type: "null-params",
        severity: "low",
        description: "Null params object",
        expectedVulnerableBehavior: "Server crashes on null params",
        tags: ["params", "null"],
      },
      {
        value: {
          jsonrpc: "2.0",
          method: "tools/call",
          id: 1,
          params: "string instead of object",
        },
        category: "protocol",
        type: "string-params",
        severity: "medium",
        description: "String instead of object params",
        expectedVulnerableBehavior: "Server accepts wrong params type",
        tags: ["params", "type-confusion"],
      },
      {
        value: {
          jsonrpc: "2.0",
          method: "tools/call",
          id: 1,
          params: { __proto__: { admin: true } },
        },
        category: "protocol",
        type: "prototype-pollution-params",
        severity: "critical",
        description: "Prototype pollution in params",
        expectedVulnerableBehavior: "Server prototype is polluted",
        tags: ["params", "prototype-pollution"],
      },
      {
        value: {
          jsonrpc: "2.0",
          method: "tools/call",
          id: 1,
          params: { constructor: { prototype: { admin: true } } },
        },
        category: "protocol",
        type: "constructor-pollution",
        severity: "critical",
        description: "Constructor pollution attempt",
        expectedVulnerableBehavior: "Server object prototype modified",
        tags: ["params", "prototype-pollution"],
      },
    ];
  }
}
