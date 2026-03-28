/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Rate Limiter Guardrail
 *
 * Implements token bucket algorithm to prevent abuse and DoS attacks.
 * Tracks requests per tool/method with configurable limits.
 *
 * Features:
 * - Per-tool rate limiting
 * - Sliding window tracking
 * - Burst allowance
 * - Automatic cleanup of old entries
 *
 * @module libs/core/use-cases/proxy/guardrails/rate-limiter
 */

import { t } from '@mcp-verify/shared';
import type { IGuardrail, InterceptResult } from '../proxy.types';
import type { JsonValue } from '../../../domain/shared/common.types';

interface RateLimitConfig {
  perMinute: number;
  perHour: number;
  burstSize: number;
  enabled: boolean;
}

interface RequestLog {
  timestamps: number[];
  lastCleanup: number;
}

export class RateLimiter implements IGuardrail {
  name = t('guardrail_rate_limiting');

  /**
   * Default limits
   */
  private defaultLimits: RateLimitConfig = {
    perMinute: 60,    // 60 requests per minute
    perHour: 1000,    // 1000 requests per hour
    burstSize: 10,    // Allow burst of 10 requests
    enabled: true
  };

  /**
   * Per-tool custom limits
   */
  private toolLimits: Map<string, RateLimitConfig> = new Map();

  /**
   * Request tracking: tool/method -> request logs
   */
  private requestLogs: Map<string, RequestLog> = new Map();

  /**
   * Cleanup interval (ms)
   */
  private cleanupInterval = 5 * 60 * 1000; // 5 minutes

  /**
   * Cleanup timer reference for cleanup
   */
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(defaultLimits?: Partial<RateLimitConfig>) {
    if (defaultLimits) {
      Object.assign(this.defaultLimits, defaultLimits);
    }

    // Start cleanup timer
    this.startCleanupTimer();
  }

  inspectRequest(message: JsonValue): InterceptResult {
    // console.log('InspectRequest:', JSON.stringify(message));
    if (!this.defaultLimits.enabled) {
      return { action: 'allow' };
    }

    // Type guard: ensure message is an object with expected properties
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      return { action: 'allow' };
    }

    const msgObj = message as Record<string, unknown>;
    const method = (typeof msgObj.method === 'string' ? msgObj.method : 'unknown');
    const params = msgObj.params as Record<string, unknown> | undefined;
    const toolName = (params && typeof params.name === 'string' ? params.name : method);
    const key = this.getKey(method, toolName);

    // Get applicable limits
    const limits = this.getLimitsForTool(toolName);

    // If rate limiting is disabled for this tool, allow
    if (!limits.enabled) {
      return { action: 'allow' };
    }

    // Check rate limits
    const now = Date.now();
    const log = this.getOrCreateLog(key);

    // Add current request timestamp
    log.timestamps.push(now);

    // Check burst limit
    const recentRequests = this.countRequestsInWindow(log, 1000); // Last 1 second
    if (recentRequests > limits.burstSize) {
      return {
        action: 'block',
        reason: t('guardrail_rate_burst', { current: recentRequests, limit: limits.burstSize })
      };
    }

    // Check per-minute limit
    const requestsPerMinute = this.countRequestsInWindow(log, 60 * 1000);
    if (requestsPerMinute > limits.perMinute) {
      return {
        action: 'block',
        reason: t('guardrail_rate_minute', { current: requestsPerMinute, limit: limits.perMinute })
      };
    }

    // Check per-hour limit
    const requestsPerHour = this.countRequestsInWindow(log, 60 * 60 * 1000);
    if (requestsPerHour > limits.perHour) {
      return {
        action: 'block',
        reason: t('guardrail_rate_hour', { current: requestsPerHour, limit: limits.perHour })
      };
    }

    return { action: 'allow' };
  }

  inspectResponse(message: JsonValue): InterceptResult {
    return { action: 'allow' };
  }

  /**
   * Set custom limits for a specific tool
   */
  setToolLimits(toolName: string, limits: Partial<RateLimitConfig>) {
    const existingLimits = this.toolLimits.get(toolName) || { ...this.defaultLimits };
    this.toolLimits.set(toolName, { ...existingLimits, ...limits });
  }

  /**
   * Get limits for a tool (custom or default)
   */
  private getLimitsForTool(toolName: string): RateLimitConfig {
    return this.toolLimits.get(toolName) || this.defaultLimits;
  }

  /**
   * Generate unique key for tracking
   */
  private getKey(method: string, toolName: string): string {
    return `${method}:${toolName}`;
  }

  /**
   * Get or create request log for a key
   */
  private getOrCreateLog(key: string): RequestLog {
    let log = this.requestLogs.get(key);

    if (!log) {
      log = {
        timestamps: [],
        lastCleanup: Date.now()
      };
      this.requestLogs.set(key, log);
    }

    return log;
  }

  /**
   * Count requests within a time window
   */
  private countRequestsInWindow(log: RequestLog, windowMs: number): number {
    const now = Date.now();
    const cutoff = now - windowMs;

    // Filter timestamps within window
    return log.timestamps.filter(ts => ts >= cutoff).length;
  }

  /**
   * Clean up old request logs
   */
  private cleanup() {
    const now = Date.now();
    const maxAge = 60 * 60 * 1000; // 1 hour

    for (const [key, log] of this.requestLogs.entries()) {
      // Remove timestamps older than maxAge
      log.timestamps = log.timestamps.filter(ts => now - ts < maxAge);

      // Remove empty logs
      if (log.timestamps.length === 0) {
        this.requestLogs.delete(key);
      } else {
        log.lastCleanup = now;
      }
    }
  }

  /**
   * Start automatic cleanup timer
   */
  private startCleanupTimer() {
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, this.cleanupInterval);
  }

  /**
   * Stop the cleanup timer and release resources
   * Call this method when the RateLimiter is no longer needed to prevent memory leaks
   */
  destroy() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Get current statistics
   */
  getStats(): {
    totalKeys: number;
    totalRequests: number;
    perToolStats: Array<{
      key: string;
      requestsLastMinute: number;
      requestsLastHour: number;
      limits: RateLimitConfig;
    }>;
  } {
    const perToolStats = [];

    for (const [key, log] of this.requestLogs.entries()) {
      const toolName = key.split(':')[1];
      const limits = this.getLimitsForTool(toolName);

      perToolStats.push({
        key,
        requestsLastMinute: this.countRequestsInWindow(log, 60 * 1000),
        requestsLastHour: this.countRequestsInWindow(log, 60 * 60 * 1000),
        limits
      });
    }

    return {
      totalKeys: this.requestLogs.size,
      totalRequests: Array.from(this.requestLogs.values())
        .reduce((sum, log) => sum + log.timestamps.length, 0),
      perToolStats
    };
  }

  /**
   * Reset all rate limits (useful for testing)
   */
  reset() {
    this.requestLogs.clear();
  }

  /**
   * Reset rate limits for a specific tool
   */
  resetTool(toolName: string) {
    for (const key of this.requestLogs.keys()) {
      if (key.includes(toolName)) {
        this.requestLogs.delete(key);
      }
    }
  }
}
