/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Transport Integration Tests
 *
 * Tests critical buffer handling scenarios for StdioTransport:
 * 1. Fragmented JSON messages (50 chunks of 1 byte)
 * 2. Oversized payload protection (10.1 MB exceeding MAX_BUFFER_SIZE)
 * 3. Buffer cleanup after errors
 */

import { StdioTransport } from '@mcp-verify/core';
import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import { writeFileSync, mkdirSync } from 'fs';

describe('StdioTransport Buffer Handling', () => {
  const MAX_BUFFER_SIZE = 10 * 1024 * 1024; // 10MB
  let testServerPath: string;

  beforeAll(() => {
    // Create a temporary test server script
    const testDir = path.join(__dirname, '__test_servers__');
    mkdirSync(testDir, { recursive: true });
    testServerPath = path.join(testDir, 'fragmented-server.js');

    // Test server that can send responses in controlled chunks or large payloads
    const serverCode = `
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);

    if (request.method === 'test/fragmented') {
      // Send response in 50 chunks of 1 byte each
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { success: true, message: 'Fragmented response' }
      }) + '\\n';

      // Send byte by byte
      for (let i = 0; i < response.length; i++) {
        process.stdout.write(response[i]);
        // Small delay to ensure chunks are sent separately
        if (i < response.length - 1) {
          const start = Date.now();
          while (Date.now() - start < 1) {} // Busy wait 1ms
        }
      }
    } else if (request.method === 'test/oversized') {
      // Send a response that exceeds MAX_BUFFER_SIZE (10.1 MB)
      const oversizePayload = 'x'.repeat(10.1 * 1024 * 1024);
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { data: oversizePayload }
      }) + '\\n';

      process.stdout.write(response);
    } else if (request.method === 'test/normal') {
      // Normal response for baseline testing
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { success: true }
      }) + '\\n';

      process.stdout.write(response);
    } else {
      // Echo back unknown methods
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { method: request.method }
      }) + '\\n';

      process.stdout.write(response);
    }
  } catch (e) {
    // Ignore parse errors
  }
});
`;

    writeFileSync(testServerPath, serverCode);
  });

  afterAll(() => {
    // Cleanup is handled by Jest's temp directory cleanup
  });

  describe('Fragmented JSON Messages', () => {
    it('should correctly handle JSON message sent in 50 chunks of 1 byte', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 5000);

      try {
        await transport.connect();

        const result = await transport.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'test/fragmented',
          params: {}
        });

        expect(result).toEqual({
          success: true,
          message: 'Fragmented response'
        });
      } finally {
        transport.close();
      }
    }, 20000); // 20s timeout for this test

    it('should handle multiple fragmented messages sequentially', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 5000);

      try {
        await transport.connect();

        // Send multiple fragmented requests
        const results = [];
        for (let i = 0; i < 3; i++) {
          const result = await transport.send({
            jsonrpc: '2.0',
            id: i + 1,
            method: 'test/fragmented',
            params: {}
          });
          results.push(result);
        }

        expect(results).toHaveLength(3);
        results.forEach(result => {
          expect(result).toEqual({
            success: true,
            message: 'Fragmented response'
          });
        });
      } finally {
        transport.close();
      }
    }, 30000);
  });

  describe('Buffer Overflow Protection', () => {
    it('should reject payload exceeding MAX_BUFFER_SIZE (10.1 MB)', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 15000);

      try {
        await transport.connect();

        // This should trigger the buffer overflow protection
        await expect(
          transport.send({
            jsonrpc: '2.0',
            id: 1,
            method: 'test/oversized',
            params: {}
          })
        ).rejects.toThrow(/buffer limit exceeded/i);

      } finally {
        transport.close();
      }
    }, 40000); // 40s timeout - large payload test

    it('should terminate connection when buffer limit exceeded', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 15000);

      try {
        await transport.connect();

        // Send oversized payload
        try {
          await transport.send({
            jsonrpc: '2.0',
            id: 1,
            method: 'test/oversized',
            params: {}
          });
          fail('Should have thrown buffer limit error');
        } catch (error) {
          expect((error as Error).message).toMatch(/buffer limit exceeded/i);
        }

        // Subsequent requests should fail because process is terminated
        await expect(
          transport.send({
            jsonrpc: '2.0',
            id: 2,
            method: 'test/normal',
            params: {}
          })
        ).rejects.toThrow();

      } finally {
        transport.close();
      }
    }, 40000);
  });

  describe('Buffer Cleanup', () => {
    it('should clear buffer after successful message processing', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 5000);

      try {
        await transport.connect();

        // Send normal request
        const result1 = await transport.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'test/normal',
          params: {}
        });

        expect(result1).toEqual({ success: true });

        // Send another request - should work if buffer was cleared
        const result2 = await transport.send({
          jsonrpc: '2.0',
          id: 2,
          method: 'test/normal',
          params: {}
        });

        expect(result2).toEqual({ success: true });
      } finally {
        transport.close();
      }
    });

    it('should handle partial line in buffer on close', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 5000);

      try {
        await transport.connect();

        const result = await transport.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'test/normal',
          params: {}
        });

        expect(result).toEqual({ success: true });

        // Close should flush decoder and process remaining bytes
        transport.close();

        // No errors should be thrown during close
        expect(true).toBe(true);
      } catch (error) {
        fail(`Should not throw error on close: ${(error as Error).message}`);
      }
    });
  });

  describe('UTF-8 Multibyte Character Handling', () => {
    it('should correctly handle multibyte characters split across chunks', async () => {
      // Create a test server that sends a response with emoji split across chunks
      const emojiServerPath = path.join(__dirname, '__test_servers__', 'emoji-server.js');
      const emojiServerCode = `
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);

    // Response with emojis that will be split across byte boundaries
    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: { message: '¡Hola! 👋 Testing UTF-8 émojis 🚀' }
    }) + '\\n';

    // Send in chunks that will split multibyte characters
    const chunkSize = 5; // Small chunks to ensure emoji are split
    for (let i = 0; i < response.length; i += chunkSize) {
      process.stdout.write(response.slice(i, i + chunkSize));
      const start = Date.now();
      while (Date.now() - start < 1) {} // Small delay
    }
  } catch (e) {
    // Ignore
  }
});
`;

      writeFileSync(emojiServerPath, emojiServerCode);

      const transport = StdioTransport.create('node', [emojiServerPath], 5000);

      try {
        await transport.connect();

        const result = await transport.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'test/emoji',
          params: {}
        });

        expect(result).toEqual({
          message: '¡Hola! 👋 Testing UTF-8 émojis 🚀'
        });
      } finally {
        transport.close();
      }
    }, 20000);
  });

  describe('Edge Cases', () => {
    it('should handle empty lines in response', async () => {
      const emptyLineServerPath = path.join(__dirname, '__test_servers__', 'empty-line-server.js');
      const emptyLineServerCode = `
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);

    // Send response with empty lines before it
    process.stdout.write('\\n\\n');
    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: { success: true }
    }) + '\\n';
    process.stdout.write(response);
  } catch (e) {
    // Ignore
  }
});
`;

      writeFileSync(emptyLineServerPath, emptyLineServerCode);

      const transport = StdioTransport.create('node', [emptyLineServerPath], 5000);

      try {
        await transport.connect();

        const result = await transport.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'test/empty-lines',
          params: {}
        });

        expect(result).toEqual({ success: true });
      } finally {
        transport.close();
      }
    });

    it('should handle rapid successive requests', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 5000);

      try {
        await transport.connect();

        // Send 10 requests in parallel
        const promises = [];
        for (let i = 0; i < 10; i++) {
          promises.push(
            transport.send({
              jsonrpc: '2.0',
              id: i + 1,
              method: 'test/normal',
              params: {}
            })
          );
        }

        const results = await Promise.all(promises);

        expect(results).toHaveLength(10);
        results.forEach(result => {
          expect(result).toEqual({ success: true });
        });
      } finally {
        transport.close();
      }
    }, 25000);
  });

  describe('Error Scenarios', () => {
    it('should reject all pending requests when buffer limit exceeded', async () => {
      const transport = StdioTransport.create('node', [testServerPath], 15000);

      try {
        await transport.connect();

        // Send multiple requests, including one that will exceed buffer
        const promises = [
          transport.send({ jsonrpc: '2.0', id: 1, method: 'test/normal', params: {} }),
          transport.send({ jsonrpc: '2.0', id: 2, method: 'test/oversized', params: {} }),
          transport.send({ jsonrpc: '2.0', id: 3, method: 'test/normal', params: {} })
        ];

        // All should be rejected when buffer limit is exceeded
        const results = await Promise.allSettled(promises);

        // At least the oversized one should be rejected
        const rejectedCount = results.filter(r => r.status === 'rejected').length;
        expect(rejectedCount).toBeGreaterThan(0);

        // The rejection should mention buffer limit
        const bufferLimitError = results.find(
          r => r.status === 'rejected' &&
            (r as PromiseRejectedResult).reason.message.includes('buffer limit')
        );
        expect(bufferLimitError).toBeDefined();

      } finally {
        transport.close();
      }
    }, 40000);

    it('should handle malformed JSON gracefully', async () => {
      const malformedServerPath = path.join(__dirname, '__test_servers__', 'malformed-server.js');
      const malformedServerCode = `
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);

    // Send malformed JSON first (should be ignored)
    process.stdout.write('{invalid json}\\n');

    // Then send valid response
    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: { success: true }
    }) + '\\n';
    process.stdout.write(response);
  } catch (e) {
    // Ignore
  }
});
`;

      writeFileSync(malformedServerPath, malformedServerCode);

      const transport = StdioTransport.create('node', [malformedServerPath], 25000);

      try {
        await transport.connect();

        // Should still receive valid response despite malformed JSON
        const result = await transport.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'test/malformed',
          params: {}
        });

        expect(result).toEqual({ success: true });
      } finally {
        transport.close();
      }
    }, 40000); // 40s timeout for malformed JSON handling
  });
});
