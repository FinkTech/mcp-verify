/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * DoS Protection Tests - Security Fix for HIGH-1
 *
 * Tests resource limits and timeouts to prevent Denial of Service attacks.
 *
 * @module libs/core/use-cases/validator/__tests__/dos-protection.spec
 */

import { MCPValidator } from '../validator';
import type { ITransport, TransportOptions } from '../../../domain/transport';
import type { McpTool, McpResource, McpPrompt, JsonRpcRequest, JsonRpcNotification, JsonValue } from '../../../domain/shared/common.types';

// Mock transport for testing
class MockTransport implements ITransport {
  private responses: Map<string, unknown> = new Map();
  private delay: number = 0;
  private activeTimers: Set<NodeJS.Timeout> = new Set();

  setResponse(method: string, response: unknown) {
    this.responses.set(method, response);
  }

  setDelay(ms: number) {
    this.delay = ms;
  }

  async connect(): Promise<void> {
    return Promise.resolve();
  }

  async send(message: JsonRpcRequest | JsonRpcNotification, _options?: TransportOptions): Promise<JsonValue> {
    if (this.delay > 0) {
      await new Promise<void>((resolve) => {
        const timerId = setTimeout(() => {
          this.activeTimers.delete(timerId);
          resolve();
        }, this.delay);
        this.activeTimers.add(timerId);
      });
    }

    const method = (message as JsonRpcRequest).method;
    const response = this.responses.get(method);

    if (!response) {
      throw new Error(`Method not found: ${method}`);
    }

    return response as JsonValue;
  }

  close(): void {
    // Clear all active timers to prevent Jest open handles
    this.activeTimers.forEach((timerId) => {
      clearTimeout(timerId);
    });
    this.activeTimers.clear();
  }
}

describe('MCPValidator - DoS Protection', () => {
  let transport: MockTransport;

  jest.setTimeout(60000);

  beforeEach(() => {
    transport = new MockTransport();

    // Setup default responses for initialization
    transport.setResponse('initialize', {
      protocolVersion: '1.0.0',
      capabilities: {},
      serverInfo: {
        name: 'test-server',
        version: '1.0.0'
      }
    });
  });

  afterEach(() => {
    // Clean up all active timers to prevent Jest open handles warning
    transport.close();
  });

  describe('Tool count limits', () => {
    it('should accept servers with reasonable number of tools', async () => {
      // Create 100 tools (well within limit of 1000)
      const tools: McpTool[] = Array.from({ length: 100 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Test tool ${i}`,
        inputSchema: {
          type: 'object',
          properties: {
            input: { type: 'string' }
          }
        }
      }));

      transport.setResponse('tools/list', { tools });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);
      const result = await validator.discoverCapabilities();

      expect(result.tools).toHaveLength(100);
    });

    it('should reject servers with excessive tools (DoS protection)', async () => {
      // Create 1001 tools (exceeds limit of 1000)
      const tools: McpTool[] = Array.from({ length: 1001 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Test tool ${i}`,
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }));

      transport.setResponse('tools/list', { tools });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);

      await expect(validator.discoverCapabilities()).rejects.toThrow(/too many tools/);
      await expect(validator.discoverCapabilities()).rejects.toThrow(/1001/);
      await expect(validator.discoverCapabilities()).rejects.toThrow(/max: 1000/);
    });
  });

  describe('Resource count limits', () => {
    it('should reject servers with excessive resources', async () => {
      // Create 1001 resources (exceeds limit of 1000)
      const resources: McpResource[] = Array.from({ length: 1001 }, (_, i) => ({
        name: `resource_${i}`,
        uri: `file:///test/${i}`,
        description: `Test resource ${i}`,
        mimeType: 'text/plain'
      }));

      transport.setResponse('tools/list', { tools: [] });
      transport.setResponse('resources/list', { resources });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);

      await expect(validator.discoverCapabilities()).rejects.toThrow(/too many resources/);
      await expect(validator.discoverCapabilities()).rejects.toThrow(/1001/);
    });
  });

  describe('Prompt count limits', () => {
    it('should reject servers with excessive prompts', async () => {
      // Create 1001 prompts (exceeds limit of 1000)
      const prompts: McpPrompt[] = Array.from({ length: 1001 }, (_, i) => ({
        name: `prompt_${i}`,
        description: `Test prompt ${i}`,
        arguments: []
      }));

      transport.setResponse('tools/list', { tools: [] });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts });

      const validator = new MCPValidator(transport);

      await expect(validator.discoverCapabilities()).rejects.toThrow(/too many prompts/);
      await expect(validator.discoverCapabilities()).rejects.toThrow(/1001/);
    });
  });

  describe('Response size limits', () => {
    it('should accept servers with reasonable response size', async () => {
      // Create tools with moderate schemas (< 10MB total)
      const tools: McpTool[] = Array.from({ length: 10 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Test tool ${i}`,
        inputSchema: {
          type: 'object',
          properties: {
            data: {
              type: 'string',
              description: 'A'.repeat(1000) // 1KB per tool = 10KB total
            }
          }
        }
      }));

      transport.setResponse('tools/list', { tools });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);
      const result = await validator.discoverCapabilities();

      expect(result.tools).toHaveLength(10);
    });

    it('should reject servers with oversized responses (DoS protection)', async () => {
      // Create a tool with massive schema (> 10MB)
      const largeString = 'A'.repeat(11 * 1024 * 1024); // 11MB

      const tools: McpTool[] = [{
        name: 'huge_tool',
        description: 'Tool with massive schema',
        inputSchema: {
          type: 'object',
          properties: {
            data: {
              type: 'string',
              description: largeString
            }
          }
        }
      }];

      transport.setResponse('tools/list', { tools });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);

      await expect(validator.discoverCapabilities()).rejects.toThrow(/response too large/);
      await expect(validator.discoverCapabilities()).rejects.toThrow(/MB/);
    });
  });

  describe('Timeout protection', () => {
    it('should timeout slow discovery (DoS protection)', async () => {
      // Set delay > 30 seconds (DISCOVERY_TIMEOUT)
      transport.setDelay(35000);

      transport.setResponse('tools/list', { tools: [] });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);

      await expect(validator.discoverCapabilities()).rejects.toThrow(/timeout/);
      await expect(validator.discoverCapabilities()).rejects.toThrow(/30000ms/);
    }, 90000); // Test timeout > delay

    it('should complete fast discovery within timeout', async () => {
      // Set delay < 30 seconds
      transport.setDelay(1000); // 1 second

      transport.setResponse('tools/list', { tools: [{ name: 'test', description: 'test', inputSchema: {} }] });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);
      const result = await validator.discoverCapabilities();

      expect(result.tools).toHaveLength(1);
    }, 5000);
  });

  describe('Error messages', () => {
    it('should provide clear error messages for DoS violations', async () => {
      const tools: McpTool[] = Array.from({ length: 1001 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Tool ${i}`,
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }));

      transport.setResponse('tools/list', { tools });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);

      try {
        await validator.discoverCapabilities();
        fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).toContain('[Security]');
        expect(error.message).toContain('too many tools');
        expect(error.message).toContain('1001');
        expect(error.message).toContain('max: 1000');
        expect(error.message).toContain('misconfigured or malicious');
      }
    });

    it('should provide clear timeout error messages', async () => {
      transport.setDelay(35000);
      transport.setResponse('tools/list', { tools: [] });

      const validator = new MCPValidator(transport);

      try {
        await validator.discoverCapabilities();
        fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).toContain('Discovery');
        expect(error.message).toContain('timeout');
        expect(error.message).toContain('30000ms');
        expect(error.message).toContain('misconfigured or malicious');
      }
    }, 40000);
  });

  describe('Combined limits', () => {
    it('should enforce multiple limits simultaneously', async () => {
      // Create scenario with many tools AND large response
      const tools: McpTool[] = Array.from({ length: 500 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Tool ${i}`,
        inputSchema: {
          type: 'object',
          properties: {
            data: {
              type: 'string',
              description: 'X'.repeat(25000) // 25KB per tool * 500 = 12.5MB > 10MB limit
            }
          }
        }
      }));

      transport.setResponse('tools/list', { tools });
      transport.setResponse('resources/list', { resources: [] });
      transport.setResponse('prompts/list', { prompts: [] });

      const validator = new MCPValidator(transport);

      // Should fail on size limit (not count limit, since 500 < 1000)
      await expect(validator.discoverCapabilities()).rejects.toThrow(/response too large/);
    });
  });
});
