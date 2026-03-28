/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Raw Protocol Generator
 *
 * Generates malformed JSON, JSON-RPC violations, and batch attacks
 * to test the robustness of MCP server transport/parsing layers.
 *
 * Unlike other generators that test tool logic, this generator tests
 * the server's ability to handle malformed input at the protocol level.
 *
 * Attack categories:
 * - Malformed JSON (syntax errors, truncation, encoding)
 * - JSON-RPC 2.0 Violations (missing fields, wrong types, invalid IDs)
 * - Batch Attacks (oversized batches, nested batches, mixed validity)
 * - DoS Payloads (JSON bombs, deep nesting, huge strings)
 * - Null byte injection and encoding attacks
 *
 * CWE-20: Improper Input Validation
 * CWE-400: Uncontrolled Resource Consumption
 * CWE-754: Improper Check for Unusual Conditions
 *
 * @module libs/fuzzer/generators/raw-protocol.generator
 */

import {
  IPayloadGenerator,
  GeneratorConfig,
  GeneratedPayload
} from './generator.interface';

export interface RawProtocolConfig extends GeneratorConfig {
  /** Include JSON bomb payloads (large memory consumption) */
  includeJsonBombs?: boolean;
  /** Maximum depth for nested structures */
  maxNestingDepth?: number;
  /** Maximum batch size for batch attacks */
  maxBatchSize?: number;
  /** Include null byte injection */
  includeNullBytes?: boolean;
}

export class RawProtocolGenerator implements IPayloadGenerator {
  readonly id = 'raw-protocol';
  readonly name = 'Raw Protocol Generator';
  readonly category = 'raw-protocol';
  readonly description = 'Tests transport layer with malformed JSON, JSON-RPC violations, and batch attacks';

  private config: Required<RawProtocolConfig>;

  constructor(config: RawProtocolConfig = {}) {
    this.config = {
      maxPayloads: config.maxPayloads ?? 100,
      minSeverity: config.minSeverity ?? 'low',
      enableMutations: config.enableMutations ?? false,
      seed: config.seed ?? '',
      includeJsonBombs: config.includeJsonBombs ?? true,
      maxNestingDepth: config.maxNestingDepth ?? 50,
      maxBatchSize: config.maxBatchSize ?? 100,
      includeNullBytes: config.includeNullBytes ?? true
    };
  }

  generate(_config?: GeneratorConfig): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // 1. Malformed JSON payloads
    payloads.push(...this.generateMalformedJson());

    // 2. JSON-RPC 2.0 violations
    payloads.push(...this.generateJsonRpcViolations());

    // 3. Batch attacks
    payloads.push(...this.generateBatchAttacks());

    // 4. DoS payloads (JSON bombs, deep nesting)
    if (this.config.includeJsonBombs) {
      payloads.push(...this.generateDoSPayloads());
    }

    // 5. Encoding attacks
    payloads.push(...this.generateEncodingAttacks());

    // 6. Null byte and special character injection
    if (this.config.includeNullBytes) {
      payloads.push(...this.generateNullByteAttacks());
    }

    return payloads.slice(0, this.config.maxPayloads);
  }

  // ==================== MALFORMED JSON ====================

  private generateMalformedJson(): GeneratedPayload[] {
    return [
      // Truncated JSON
      {
        value: '{"jsonrpc": "2.0", "method": "tools/list"',
        category: 'raw-protocol',
        type: 'truncated-json',
        severity: 'medium',
        description: 'Truncated JSON - missing closing brace',
        expectedVulnerableBehavior: 'Server hangs waiting for more data or crashes',
        tags: ['parser', 'dos'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '{"jsonrpc": "2.0", "method": "tools/list", "params": {"name":',
        category: 'raw-protocol',
        type: 'truncated-json',
        severity: 'medium',
        description: 'Truncated JSON - mid-value truncation',
        expectedVulnerableBehavior: 'Parser error or hang',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      },

      // Invalid JSON syntax
      {
        value: '{jsonrpc: "2.0", method: "tools/list"}',
        category: 'raw-protocol',
        type: 'unquoted-keys',
        severity: 'low',
        description: 'JSON with unquoted keys (JavaScript object notation)',
        expectedVulnerableBehavior: 'Server accepts non-standard JSON',
        tags: ['parser', 'relaxed-parsing'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: "{'jsonrpc': '2.0', 'method': 'tools/list'}",
        category: 'raw-protocol',
        type: 'single-quotes',
        severity: 'low',
        description: 'JSON with single quotes instead of double',
        expectedVulnerableBehavior: 'Server accepts Python-style dict notation',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '{"jsonrpc": "2.0", "method": "tools/list",}',
        category: 'raw-protocol',
        type: 'trailing-comma',
        severity: 'low',
        description: 'JSON with trailing comma',
        expectedVulnerableBehavior: 'Server accepts non-standard JSON',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '{"jsonrpc": "2.0", "method": "tools/list"} extra garbage',
        category: 'raw-protocol',
        type: 'trailing-garbage',
        severity: 'medium',
        description: 'Valid JSON followed by garbage data',
        expectedVulnerableBehavior: 'Server ignores trailing data (could hide attacks)',
        tags: ['parser', 'injection'],
        metadata: { isRaw: true, sendAsString: true }
      },

      // Multiple JSON objects (not valid JSON, but common mistake)
      {
        value: '{"jsonrpc": "2.0", "method": "a"}{"jsonrpc": "2.0", "method": "b"}',
        category: 'raw-protocol',
        type: 'concatenated-json',
        severity: 'medium',
        description: 'Two JSON objects concatenated without separator',
        expectedVulnerableBehavior: 'Request smuggling via concatenation',
        tags: ['parser', 'smuggling'],
        metadata: { isRaw: true, sendAsString: true }
      },

      // Comments in JSON
      {
        value: '{"jsonrpc": "2.0", /* comment */ "method": "tools/list"}',
        category: 'raw-protocol',
        type: 'json-with-comments',
        severity: 'low',
        description: 'JSON with C-style comments',
        expectedVulnerableBehavior: 'Server accepts JSONC format',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '{"jsonrpc": "2.0", // comment\n"method": "tools/list"}',
        category: 'raw-protocol',
        type: 'json-with-line-comments',
        severity: 'low',
        description: 'JSON with line comments',
        expectedVulnerableBehavior: 'Server accepts JSONC format',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      },

      // Not JSON at all
      {
        value: 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
        category: 'raw-protocol',
        type: 'http-injection',
        severity: 'high',
        description: 'HTTP request instead of JSON-RPC',
        expectedVulnerableBehavior: 'Protocol confusion or crash',
        tags: ['parser', 'protocol-confusion'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '<?xml version="1.0"?><request method="tools/list"/>',
        category: 'raw-protocol',
        type: 'xml-injection',
        severity: 'medium',
        description: 'XML instead of JSON',
        expectedVulnerableBehavior: 'Protocol confusion',
        tags: ['parser', 'protocol-confusion'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '',
        category: 'raw-protocol',
        type: 'empty-input',
        severity: 'low',
        description: 'Empty string input',
        expectedVulnerableBehavior: 'Server should gracefully reject',
        tags: ['parser', 'edge-case'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '\n\n\n',
        category: 'raw-protocol',
        type: 'whitespace-only',
        severity: 'low',
        description: 'Whitespace-only input',
        expectedVulnerableBehavior: 'Server should gracefully reject',
        tags: ['parser', 'edge-case'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: 'null',
        category: 'raw-protocol',
        type: 'json-null',
        severity: 'low',
        description: 'JSON null literal',
        expectedVulnerableBehavior: 'Should reject with proper error',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '[]',
        category: 'raw-protocol',
        type: 'empty-array',
        severity: 'low',
        description: 'Empty JSON array (empty batch)',
        expectedVulnerableBehavior: 'Should reject or return empty response',
        tags: ['parser', 'batch'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '"just a string"',
        category: 'raw-protocol',
        type: 'json-string',
        severity: 'low',
        description: 'Plain JSON string instead of object',
        expectedVulnerableBehavior: 'Should reject with proper error',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '12345',
        category: 'raw-protocol',
        type: 'json-number',
        severity: 'low',
        description: 'Plain JSON number instead of object',
        expectedVulnerableBehavior: 'Should reject with proper error',
        tags: ['parser'],
        metadata: { isRaw: true, sendAsString: true }
      }
    ];
  }

  // ==================== JSON-RPC 2.0 VIOLATIONS ====================

  private generateJsonRpcViolations(): GeneratedPayload[] {
    return [
      // Missing required fields
      {
        value: { method: 'tools/list', id: 1 },
        category: 'raw-protocol',
        type: 'missing-jsonrpc-field',
        severity: 'medium',
        description: 'JSON-RPC request missing "jsonrpc" field',
        expectedVulnerableBehavior: 'Server accepts non-compliant request',
        tags: ['jsonrpc', 'spec-violation'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', id: 1 },
        category: 'raw-protocol',
        type: 'missing-method-field',
        severity: 'medium',
        description: 'JSON-RPC request missing "method" field',
        expectedVulnerableBehavior: 'Server crashes or executes undefined behavior',
        tags: ['jsonrpc', 'spec-violation'],
        metadata: { isRaw: true }
      },

      // Wrong jsonrpc version
      {
        value: { jsonrpc: '1.0', method: 'tools/list', id: 1 },
        category: 'raw-protocol',
        type: 'wrong-jsonrpc-version',
        severity: 'low',
        description: 'JSON-RPC 1.0 version string',
        expectedVulnerableBehavior: 'Server accepts old protocol version',
        tags: ['jsonrpc', 'version'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '3.0', method: 'tools/list', id: 1 },
        category: 'raw-protocol',
        type: 'future-jsonrpc-version',
        severity: 'low',
        description: 'Future JSON-RPC version',
        expectedVulnerableBehavior: 'Should reject unknown version',
        tags: ['jsonrpc', 'version'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: 2.0, method: 'tools/list', id: 1 },
        category: 'raw-protocol',
        type: 'jsonrpc-as-number',
        severity: 'medium',
        description: 'jsonrpc field as number instead of string',
        expectedVulnerableBehavior: 'Type coercion vulnerability',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: null, method: 'tools/list', id: 1 },
        category: 'raw-protocol',
        type: 'jsonrpc-null',
        severity: 'medium',
        description: 'jsonrpc field as null',
        expectedVulnerableBehavior: 'Null pointer dereference or bypass',
        tags: ['jsonrpc', 'null'],
        metadata: { isRaw: true }
      },

      // Invalid method field
      {
        value: { jsonrpc: '2.0', method: 123, id: 1 },
        category: 'raw-protocol',
        type: 'method-as-number',
        severity: 'medium',
        description: 'method field as number instead of string',
        expectedVulnerableBehavior: 'Type confusion in method routing',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: null, id: 1 },
        category: 'raw-protocol',
        type: 'method-null',
        severity: 'medium',
        description: 'method field as null',
        expectedVulnerableBehavior: 'Null method handling',
        tags: ['jsonrpc', 'null'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: '', id: 1 },
        category: 'raw-protocol',
        type: 'empty-method',
        severity: 'low',
        description: 'Empty string method',
        expectedVulnerableBehavior: 'Edge case in method routing',
        tags: ['jsonrpc', 'edge-case'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: ['tools/list'], id: 1 },
        category: 'raw-protocol',
        type: 'method-as-array',
        severity: 'medium',
        description: 'method field as array',
        expectedVulnerableBehavior: 'Type confusion',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: { name: 'tools/list' }, id: 1 },
        category: 'raw-protocol',
        type: 'method-as-object',
        severity: 'medium',
        description: 'method field as object',
        expectedVulnerableBehavior: 'Type confusion or toString exploitation',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },

      // Invalid ID field
      {
        value: { jsonrpc: '2.0', method: 'tools/list', id: null },
        category: 'raw-protocol',
        type: 'null-id',
        severity: 'low',
        description: 'Null ID (valid for notifications, but odd for requests)',
        expectedVulnerableBehavior: 'Notification vs request confusion',
        tags: ['jsonrpc', 'id'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: 'tools/list', id: -1 },
        category: 'raw-protocol',
        type: 'negative-id',
        severity: 'low',
        description: 'Negative ID value',
        expectedVulnerableBehavior: 'Edge case in ID handling',
        tags: ['jsonrpc', 'id'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: 'tools/list', id: 999999999999999999999n },
        category: 'raw-protocol',
        type: 'huge-id',
        severity: 'medium',
        description: 'Extremely large ID (BigInt overflow)',
        expectedVulnerableBehavior: 'Integer overflow in ID handling',
        tags: ['jsonrpc', 'overflow'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: 'tools/list', id: 1.5 },
        category: 'raw-protocol',
        type: 'float-id',
        severity: 'low',
        description: 'Floating point ID',
        expectedVulnerableBehavior: 'Non-integer ID handling',
        tags: ['jsonrpc', 'id'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: 'tools/list', id: { nested: true } },
        category: 'raw-protocol',
        type: 'object-id',
        severity: 'medium',
        description: 'Object as ID',
        expectedVulnerableBehavior: 'Type confusion in ID matching',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: 'tools/list', id: [1, 2, 3] },
        category: 'raw-protocol',
        type: 'array-id',
        severity: 'medium',
        description: 'Array as ID',
        expectedVulnerableBehavior: 'Type confusion in ID matching',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },

      // Params field violations
      {
        value: { jsonrpc: '2.0', method: 'tools/call', params: 'not-an-object', id: 1 },
        category: 'raw-protocol',
        type: 'params-as-string',
        severity: 'medium',
        description: 'params as string instead of object/array',
        expectedVulnerableBehavior: 'Type confusion in parameter parsing',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: 'tools/call', params: 12345, id: 1 },
        category: 'raw-protocol',
        type: 'params-as-number',
        severity: 'medium',
        description: 'params as number',
        expectedVulnerableBehavior: 'Type confusion in parameter parsing',
        tags: ['jsonrpc', 'type-confusion'],
        metadata: { isRaw: true }
      },

      // Reserved internal methods
      {
        value: { jsonrpc: '2.0', method: 'rpc.discover', id: 1 },
        category: 'raw-protocol',
        type: 'rpc-reserved-method',
        severity: 'medium',
        description: 'Attempt to call reserved rpc.* method',
        expectedVulnerableBehavior: 'Access to internal RPC methods',
        tags: ['jsonrpc', 'reserved'],
        metadata: { isRaw: true }
      },
      {
        value: { jsonrpc: '2.0', method: 'rpc.listMethods', id: 1 },
        category: 'raw-protocol',
        type: 'rpc-introspection',
        severity: 'medium',
        description: 'RPC introspection method',
        expectedVulnerableBehavior: 'Information disclosure via introspection',
        tags: ['jsonrpc', 'introspection'],
        metadata: { isRaw: true }
      },

      // Extra fields
      {
        value: {
          jsonrpc: '2.0',
          method: 'tools/list',
          id: 1,
          __proto__: { admin: true }
        },
        category: 'raw-protocol',
        type: 'proto-pollution-attempt',
        severity: 'critical',
        description: 'Prototype pollution via __proto__ field',
        expectedVulnerableBehavior: 'Prototype pollution vulnerability',
        tags: ['jsonrpc', 'prototype-pollution'],
        metadata: { isRaw: true }
      },
      {
        value: {
          jsonrpc: '2.0',
          method: 'tools/list',
          id: 1,
          constructor: { prototype: { admin: true } }
        },
        category: 'raw-protocol',
        type: 'constructor-pollution',
        severity: 'critical',
        description: 'Prototype pollution via constructor field',
        expectedVulnerableBehavior: 'Prototype pollution via constructor',
        tags: ['jsonrpc', 'prototype-pollution'],
        metadata: { isRaw: true }
      }
    ];
  }

  // ==================== BATCH ATTACKS ====================

  private generateBatchAttacks(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // Valid batch with mixed valid/invalid requests
    payloads.push({
      value: { payload: [
        { jsonrpc: '2.0', method: 'tools/list', id: 1 },
        { invalid: 'request' },
        { jsonrpc: '2.0', method: 'tools/list', id: 2 }
      ]},
      category: 'raw-protocol',
      type: 'mixed-validity-batch',
      severity: 'medium',
      description: 'Batch with mix of valid and invalid requests',
      expectedVulnerableBehavior: 'Server crashes on partial batch failure',
      tags: ['batch', 'error-handling'],
      metadata: { isRaw: true }
    });

    // Batch with duplicate IDs
    payloads.push({
      value: { payload: [
        { jsonrpc: '2.0', method: 'tools/list', id: 1 },
        { jsonrpc: '2.0', method: 'resources/list', id: 1 },
        { jsonrpc: '2.0', method: 'prompts/list', id: 1 }
      ]},
      category: 'raw-protocol',
      type: 'duplicate-id-batch',
      severity: 'medium',
      description: 'Batch with duplicate request IDs',
      expectedVulnerableBehavior: 'Response correlation confusion',
      tags: ['batch', 'id-collision'],
      metadata: { isRaw: true }
    });

    // Nested batch (batch within batch)
    payloads.push({
      value: { payload: [
        { jsonrpc: '2.0', method: 'tools/list', id: 1 },
        [
          { jsonrpc: '2.0', method: 'tools/list', id: 2 }
        ]
      ]},
      category: 'raw-protocol',
      type: 'nested-batch',
      severity: 'high',
      description: 'Nested batch request (array within array)',
      expectedVulnerableBehavior: 'Recursive processing or crash',
      tags: ['batch', 'nesting'],
      metadata: { isRaw: true }
    });

    // Large batch (DoS potential)
    const largeBatch = [];
    for (let i = 0; i < this.config.maxBatchSize; i++) {
      largeBatch.push({ jsonrpc: '2.0', method: 'tools/list', id: i });
    }
    payloads.push({
      value: { payload: largeBatch },
      category: 'raw-protocol',
      type: 'large-batch',
      severity: 'high',
      description: `Large batch with ${this.config.maxBatchSize} requests`,
      expectedVulnerableBehavior: 'Resource exhaustion or timeout',
      tags: ['batch', 'dos'],
      metadata: { isRaw: true, size: this.config.maxBatchSize }
    });

    // Batch with all notifications (no IDs)
    payloads.push({
      value: { payload: [
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', method: 'notifications/progress' },
        { jsonrpc: '2.0', method: 'notifications/message' }
      ]},
      category: 'raw-protocol',
      type: 'notification-only-batch',
      severity: 'low',
      description: 'Batch containing only notifications',
      expectedVulnerableBehavior: 'Should return no response',
      tags: ['batch', 'notification'],
      metadata: { isRaw: true }
    });

    // Batch with single element (edge case)
    payloads.push({
      value: { payload: [{ jsonrpc: '2.0', method: 'tools/list', id: 1 }] },
      category: 'raw-protocol',
      type: 'single-element-batch',
      severity: 'low',
      description: 'Batch with single request',
      expectedVulnerableBehavior: 'Should work but return array response',
      tags: ['batch', 'edge-case'],
      metadata: { isRaw: true }
    });

    return payloads;
  }

  // ==================== DOS PAYLOADS ====================

  private generateDoSPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // JSON Bomb (exponential expansion via nested objects)
    const createNestedObject = (depth: number): object => {
      if (depth === 0) return { value: 'x'.repeat(100) };
      return {
        a: createNestedObject(depth - 1),
        b: createNestedObject(depth - 1)
      };
    };

    // Deeply nested structure (stack overflow potential)
    type NestedObject = { value: string } | { nested: NestedObject };
    let deepNested: NestedObject = { value: 'end' };
    for (let i = 0; i < this.config.maxNestingDepth; i++) {
      deepNested = { nested: deepNested };
    }
    payloads.push({
      value: {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: deepNested,
        id: 1
      },
      category: 'raw-protocol',
      type: 'deep-nesting',
      severity: 'high',
      description: `Deeply nested JSON (${this.config.maxNestingDepth} levels)`,
      expectedVulnerableBehavior: 'Stack overflow or excessive recursion',
      tags: ['dos', 'nesting'],
      metadata: { isRaw: true, depth: this.config.maxNestingDepth }
    });

    // Wide object (many keys)
    const wideObject: Record<string, string> = {};
    for (let i = 0; i < 10000; i++) {
      wideObject[`key_${i}`] = `value_${i}`;
    }
    payloads.push({
      value: {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { arguments: wideObject },
        id: 1
      },
      category: 'raw-protocol',
      type: 'wide-object',
      severity: 'medium',
      description: 'Object with 10,000 keys',
      expectedVulnerableBehavior: 'Memory exhaustion or slow parsing',
      tags: ['dos', 'memory'],
      metadata: { isRaw: true, keyCount: 10000 }
    });

    // Long string value
    payloads.push({
      value: {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: 'test', arguments: { data: 'A'.repeat(1000000) } },
        id: 1
      },
      category: 'raw-protocol',
      type: 'long-string',
      severity: 'high',
      description: '1MB string payload',
      expectedVulnerableBehavior: 'Memory exhaustion or buffer overflow',
      tags: ['dos', 'memory'],
      metadata: { isRaw: true, size: 1000000 }
    });

    // Long method name
    payloads.push({
      value: {
        jsonrpc: '2.0',
        method: 'x'.repeat(100000),
        id: 1
      },
      category: 'raw-protocol',
      type: 'long-method-name',
      severity: 'medium',
      description: 'Very long method name (100KB)',
      expectedVulnerableBehavior: 'Buffer overflow in method routing',
      tags: ['dos', 'overflow'],
      metadata: { isRaw: true, methodLength: 100000 }
    });

    // Recursive reference (if server uses unsafe JSON parse)
    payloads.push({
      value: '{"jsonrpc":"2.0","method":"test","id":1,"self":{"$ref":"$"}}',
      category: 'raw-protocol',
      type: 'circular-reference',
      severity: 'high',
      description: 'JSON with $ref circular reference',
      expectedVulnerableBehavior: 'Infinite loop if using JSON schema dereferencing',
      tags: ['dos', 'circular'],
      metadata: { isRaw: true, sendAsString: true }
    });

    return payloads;
  }

  // ==================== ENCODING ATTACKS ====================

  private generateEncodingAttacks(): GeneratedPayload[] {
    return [
      // Unicode variations
      {
        value: '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}\uFEFF',
        category: 'raw-protocol',
        type: 'bom-suffix',
        severity: 'low',
        description: 'JSON with BOM at end',
        expectedVulnerableBehavior: 'Parser accepts invalid trailing bytes',
        tags: ['encoding', 'unicode'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '\uFEFF{"jsonrpc": "2.0", "method": "tools/list", "id": 1}',
        category: 'raw-protocol',
        type: 'bom-prefix',
        severity: 'low',
        description: 'JSON with BOM at start',
        expectedVulnerableBehavior: 'Parser handles BOM correctly',
        tags: ['encoding', 'unicode'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '{"jsonrpc": "2.0", "method": "tools\\u002flist", "id": 1}',
        category: 'raw-protocol',
        type: 'unicode-escape-method',
        severity: 'medium',
        description: 'Method name with unicode escape',
        expectedVulnerableBehavior: 'Bypass method filtering via encoding',
        tags: ['encoding', 'bypass'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '{"jsonrpc": "2.0", "method": "to\u006fls/list", "id": 1}',
        category: 'raw-protocol',
        type: 'unicode-normalized-method',
        severity: 'medium',
        description: 'Method with Unicode normalization edge case',
        expectedVulnerableBehavior: 'Normalization confusion in routing',
        tags: ['encoding', 'normalization'],
        metadata: { isRaw: true, sendAsString: true }
      },

      // Overlong UTF-8 encodings (security bypass)
      {
        value: Buffer.from([0x7B, 0x22, 0x6A, 0x73, 0x6F, 0x6E, 0x72, 0x70, 0x63, 0x22, 0x3A, 0x22, 0x32, 0x2E, 0x30, 0x22, 0x7D]).toString(),
        category: 'raw-protocol',
        type: 'raw-bytes',
        severity: 'low',
        description: 'Raw byte sequence',
        expectedVulnerableBehavior: 'Proper UTF-8 handling',
        tags: ['encoding', 'binary'],
        metadata: { isRaw: true, sendAsString: true }
      }
    ];
  }

  // ==================== NULL BYTE ATTACKS ====================

  private generateNullByteAttacks(): GeneratedPayload[] {
    return [
      {
        value: '{"jsonrpc": "2.0", "method": "tools/list\x00injected", "id": 1}',
        category: 'raw-protocol',
        type: 'null-byte-method',
        severity: 'high',
        description: 'Null byte in method name',
        expectedVulnerableBehavior: 'Null byte truncation in method routing',
        tags: ['null-byte', 'injection'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '{"jsonrpc": "2.0", "method": "tools/list", "id": 1, "extra": "before\x00after"}',
        category: 'raw-protocol',
        type: 'null-byte-value',
        severity: 'medium',
        description: 'Null byte in JSON value',
        expectedVulnerableBehavior: 'Truncation or logging bypass',
        tags: ['null-byte'],
        metadata: { isRaw: true, sendAsString: true }
      },
      {
        value: '\x00{"jsonrpc": "2.0", "method": "tools/list", "id": 1}',
        category: 'raw-protocol',
        type: 'null-byte-prefix',
        severity: 'medium',
        description: 'Null byte before JSON',
        expectedVulnerableBehavior: 'Parser bypass or confusion',
        tags: ['null-byte'],
        metadata: { isRaw: true, sendAsString: true }
      }
    ];
  }
}
