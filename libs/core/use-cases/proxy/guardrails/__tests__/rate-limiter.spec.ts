/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Comprehensive tests for RateLimiter Guardrail
 *
 * Tests cover:
 * - Burst limit enforcement
 * - Per-minute limit enforcement
 * - Per-hour limit enforcement
 * - Custom tool limits
 * - Reset functionality
 * - Statistics reporting
 * - Edge cases
 */

import { RateLimiter } from '../rate-limiter';

describe('RateLimiter', () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter({
      perMinute: 10,
      perHour: 100,
      burstSize: 3,
      enabled: true
    });
  });

  afterEach(() => {
    rateLimiter.reset();
    rateLimiter.destroy(); // Clean up interval timer to prevent Jest open handles
  });

  describe('Burst Limit Enforcement', () => {
    test('should allow requests within burst limit', () => {
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // First 3 requests should pass (burst size = 3)
      expect(rateLimiter.inspectRequest(message).action).toBe('allow');
      expect(rateLimiter.inspectRequest(message).action).toBe('allow');
      expect(rateLimiter.inspectRequest(message).action).toBe('allow');
    });

    test('should block requests exceeding burst limit', () => {
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Send burst size + 1 requests immediately
      for (let i = 0; i < 3; i++) {
        rateLimiter.inspectRequest(message);
      }

      // 4th request should be blocked (exceeds burst size of 3)
      const result = rateLimiter.inspectRequest(message);
      expect(result.action).toBe('block');
      expect(result.reason).toContain('Burst limit exceeded');
    });

    test('should reset burst limit after time window', async () => {
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Fill burst limit
      for (let i = 0; i < 3; i++) {
        rateLimiter.inspectRequest(message);
      }

      // Wait for burst window to expire (1 second)
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Should allow new burst
      expect(rateLimiter.inspectRequest(message).action).toBe('allow');
    });
  });

  describe('Per-Minute Limit Enforcement', () => {
    test('should allow requests within per-minute limit', () => {
      rateLimiter.setToolLimits('test_tool', { burstSize: 20 }); // Increase burst for this test
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Send requests spaced out to avoid burst limit
      for (let i = 0; i < 10; i++) {
        const result = rateLimiter.inspectRequest(message);
        expect(result.action).toBe('allow');
      }
    });

    test('should block requests exceeding per-minute limit', () => {
      rateLimiter.setToolLimits('test_tool', { burstSize: 20 });
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Send 11 requests (limit is 10 per minute)
      // First 10 should pass
      for (let i = 0; i < 10; i++) {
        rateLimiter.inspectRequest(message);
      }

      // 11th should be blocked
      const result = rateLimiter.inspectRequest(message);
      expect(result.action).toBe('block');
      expect(result.reason).toContain('Rate limit exceeded');
      expect(result.reason).toContain('per minute');
    });

    test('should track different tools separately', () => {
      const message1 = { method: 'tools/call', params: { name: 'tool1' } };
      const message2 = { method: 'tools/call', params: { name: 'tool2' } };

      // Fill limit for tool1
      for (let i = 0; i < 10; i++) {
        rateLimiter.inspectRequest(message1);
      }

      // tool1 should be blocked
      expect(rateLimiter.inspectRequest(message1).action).toBe('block');

      // tool2 should still be allowed (separate tracking)
      expect(rateLimiter.inspectRequest(message2).action).toBe('allow');
    });
  });

  describe('Per-Hour Limit Enforcement', () => {
    test('should block requests exceeding per-hour limit', () => {
      rateLimiter.setToolLimits('test_tool', { burstSize: 200, perHour: 100, perMinute: 200 });
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Send 101 requests (limit is 100 per hour)
      for (let i = 0; i < 100; i++) {
        rateLimiter.inspectRequest(message);
      }

      // 101st should be blocked
      const result = rateLimiter.inspectRequest(message);
      expect(result.action).toBe('block');
      expect(result.reason).toContain('Rate limit exceeded');
    });
  });

  describe('Custom Tool Limits', () => {
    test('should apply custom limits to specific tools', () => {
      rateLimiter.setToolLimits('expensive_tool', {
        perMinute: 2, // Stricter than default
        burstSize: 1
      });

      const message = { method: 'tools/call', params: { name: 'expensive_tool' } };

      // First request should pass
      expect(rateLimiter.inspectRequest(message).action).toBe('allow');

      // Second request should be blocked (burst size = 1)
      const result = rateLimiter.inspectRequest(message);
      expect(result.action).toBe('block');
    });

    test('should use default limits for tools without custom limits', () => {
      rateLimiter.setToolLimits('tool1', { perMinute: 2 });
      rateLimiter.setToolLimits('tool2', { burstSize: 15 }); // Avoid burst blocking

      const message1 = { method: 'tools/call', params: { name: 'tool1' } };
      const message2 = { method: 'tools/call', params: { name: 'tool2' } };

      // tool1 uses custom limit (2 per minute)
      rateLimiter.inspectRequest(message1);
      rateLimiter.inspectRequest(message1);
      expect(rateLimiter.inspectRequest(message1).action).toBe('block');

      // tool2 uses default limit (10 per minute)
      for (let i = 0; i < 10; i++) {
        expect(rateLimiter.inspectRequest(message2).action).toBe('allow');
      }
    });

    test('should allow disabling rate limiting per tool', () => {
      rateLimiter.setToolLimits('unlimited_tool', { enabled: false, burstSize: 1500 });

      const message = { method: 'tools/call', params: { name: 'unlimited_tool' } };

      // Should allow unlimited requests
      for (let i = 0; i < 1000; i++) {
        expect(rateLimiter.inspectRequest(message).action).toBe('allow');
      }
    });
  });

  describe('Reset Functionality', () => {
    test('should reset all rate limits', () => {
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Fill limit
      for (let i = 0; i < 10; i++) {
        rateLimiter.inspectRequest(message);
      }

      // Should be blocked
      expect(rateLimiter.inspectRequest(message).action).toBe('block');

      // Reset
      rateLimiter.reset();

      // Should allow again
      expect(rateLimiter.inspectRequest(message).action).toBe('allow');
    });

    test('should reset specific tool rate limits', () => {
      const message1 = { method: 'tools/call', params: { name: 'tool1' } };
      const message2 = { method: 'tools/call', params: { name: 'tool2' } };

      // Fill limits for both tools
      for (let i = 0; i < 10; i++) {
        rateLimiter.inspectRequest(message1);
        rateLimiter.inspectRequest(message2);
      }

      // Both should be blocked
      expect(rateLimiter.inspectRequest(message1).action).toBe('block');
      expect(rateLimiter.inspectRequest(message2).action).toBe('block');

      // Reset only tool1
      rateLimiter.resetTool('tool1');

      // tool1 should be allowed, tool2 still blocked
      expect(rateLimiter.inspectRequest(message1).action).toBe('allow');
      expect(rateLimiter.inspectRequest(message2).action).toBe('block');
    });
  });

  describe('Statistics Reporting', () => {
    test('should report accurate statistics', () => {
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Send 5 requests
      for (let i = 0; i < 5; i++) {
        rateLimiter.inspectRequest(message);
      }

      const stats = rateLimiter.getStats();

      expect(stats.totalKeys).toBeGreaterThan(0);
      expect(stats.totalRequests).toBe(5);
      expect(stats.perToolStats.length).toBeGreaterThan(0);
    });

    test('should report per-tool statistics', () => {
      const message1 = { method: 'tools/call', params: { name: 'tool1' } };
      const message2 = { method: 'tools/call', params: { name: 'tool2' } };

      // Send requests to different tools
      for (let i = 0; i < 3; i++) {
        rateLimiter.inspectRequest(message1);
      }
      for (let i = 0; i < 7; i++) {
        rateLimiter.inspectRequest(message2);
      }

      const stats = rateLimiter.getStats();

      expect(stats.perToolStats).toHaveLength(2);
      expect(stats.totalRequests).toBe(10);
    });

    test('should report requests in time windows', () => {
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Send requests
      for (let i = 0; i < 5; i++) {
        rateLimiter.inspectRequest(message);
      }

      const stats = rateLimiter.getStats();
      const toolStats = stats.perToolStats[0];

      expect(toolStats.requestsLastMinute).toBe(5);
      expect(toolStats.requestsLastHour).toBe(5);
    });
  });

  describe('Edge Cases', () => {
    test('should handle null/undefined messages', () => {
      expect(rateLimiter.inspectRequest(null).action).toBe('allow');
      // @ts-ignore
      expect(rateLimiter.inspectRequest(undefined).action).toBe('allow');
    });

    test('should handle messages without method', () => {
      const message = { params: { name: 'tool1' } };
      const result = rateLimiter.inspectRequest(message);
      expect(result.action).toBe('allow');
    });

    test('should handle messages without params', () => {
      const message = { method: 'tools/call' };
      const result = rateLimiter.inspectRequest(message);
      expect(result.action).toBe('allow');
    });

    test('should handle empty messages', () => {
      const result = rateLimiter.inspectRequest({});
      expect(result.action).toBe('allow');
    });

    test('should handle array messages', () => {
      const result = rateLimiter.inspectRequest([]);
      expect(result.action).toBe('allow');
    });

    test('should handle disabled rate limiter', () => {
      const disabledLimiter = new RateLimiter({ enabled: false });
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      try {
        // Should allow unlimited requests when disabled
        for (let i = 0; i < 1000; i++) {
          expect(disabledLimiter.inspectRequest(message).action).toBe('allow');
        }
      } finally {
        // Clean up interval timer
        disabledLimiter.destroy();
      }
    });
  });

  describe('Response Inspection', () => {
    test('should always allow responses', () => {
      const response = { result: { success: true } };
      expect(rateLimiter.inspectResponse(response).action).toBe('allow');
    });
  });

  describe('Concurrent Requests', () => {
    test('should handle concurrent requests from same tool', () => {
      rateLimiter.setToolLimits('test_tool', { burstSize: 20 });
      const message = { method: 'tools/call', params: { name: 'test_tool' } };

      // Simulate concurrent requests
      const results = [];
      for (let i = 0; i < 15; i++) {
        results.push(rateLimiter.inspectRequest(message));
      }

      // First 10 should be allowed
      expect(results.slice(0, 10).every(r => r.action === 'allow')).toBe(true);

      // Remaining should be blocked
      expect(results.slice(10).every(r => r.action === 'block')).toBe(true);
    });
  });

  describe('Different Request Methods', () => {
    test('should track different methods separately', () => {
      const message1 = { method: 'tools/call', params: { name: 'tool1' } };
      const message2 = { method: 'tools/list', params: { name: 'tool1' } };

      // Fill limit for tools/call
      for (let i = 0; i < 10; i++) {
        rateLimiter.inspectRequest(message1);
      }

      // tools/call should be blocked
      expect(rateLimiter.inspectRequest(message1).action).toBe('block');

      // tools/list should still be allowed (different method)
      expect(rateLimiter.inspectRequest(message2).action).toBe('allow');
    });
  });
});
