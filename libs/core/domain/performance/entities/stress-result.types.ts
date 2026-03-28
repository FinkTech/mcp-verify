/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export interface RequestMetric {
  endpoint: string;
  durationMs: number;
  success: boolean;
  timestamp: number;
}

export interface StressTestConfig {
  concurrentClients: number;
  durationSeconds: number; // or number of requests
  endpoints: string[]; // e.g., ['initialize', 'tools/list']
}

export interface StressTestReport {
  serverUrl: string;
  timestamp: string;
  config: StressTestConfig;
  summary: {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    requestsPerSecond: number;
    avgLatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    maxLatencyMs: number;
  };
  metrics: RequestMetric[];
  errors: Array<{ code: string; message: string; count: number }>;
  resourceWarnings?: string[]; // Added for resource monitoring warnings
}
