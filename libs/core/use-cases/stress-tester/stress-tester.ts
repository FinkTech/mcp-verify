/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { t } from "@mcp-verify/shared";
import {
  ITransport,
  HttpTransport,
  StdioTransport,
} from "../../domain/transport";
import type {
  StressTestConfig,
  StressTestReport,
  RequestMetric,
} from "../../domain/performance/entities/stress-result.types";
import type { JsonValue } from "../../domain/shared/common.types";
import * as os from "os";

// Constants for stress testing configuration
const PROTOCOL_VERSION = "2024-11-05";
const WORKER_YIELD_MS = 10;
const RANDOM_ID_MAX = 10000;
const MS_PER_SECOND = 1000;
const PERCENTILE_95 = 0.95;
const PERCENTILE_99 = 0.99;

// Resource monitoring thresholds
const CPU_WARNING_THRESHOLD = 80; // %
const MEMORY_WARNING_THRESHOLD = 85; // %

interface ResourceSnapshot {
  timestamp: number;
  cpuUsagePercent: number;
  memoryUsagePercent: number;
  availableMemoryMB: number;
}

export class StressTester {
  private targetUrl: string;
  private transportType: "http" | "stdio";
  private lang: string | undefined;
  private metrics: RequestMetric[] = [];
  private errors: Map<string, number> = new Map();
  private resourceSnapshots: ResourceSnapshot[] = [];
  private resourceMonitorInterval: NodeJS.Timeout | null = null;

  constructor(
    targetUrl: string,
    transportType: "http" | "stdio",
    lang?: string,
  ) {
    this.targetUrl = targetUrl;
    this.transportType = transportType;
    this.lang = lang;
  }

  private createTransport(): ITransport {
    if (this.transportType === "http") {
      return HttpTransport.create(this.targetUrl);
    } else {
      // Split command string into command and args to avoid SDK deprecation warning
      // Simple split by space (handles basic cases like "node server.js")
      // For complex quoted arguments, users should use proper array configuration,
      // but this covers the CLI use case.
      const parts = this.targetUrl.trim().split(/\s+/);
      const command = parts[0];
      const args = parts.slice(1);

      if (this.lang) {
        args.push("--lang", this.lang);
      }

      return StdioTransport.create(command, args);
    }
  }

  async run(config: StressTestConfig): Promise<StressTestReport> {
    const startTime = Date.now();
    const endTime = startTime + config.durationSeconds * MS_PER_SECOND;

    // Start resource monitoring
    this.startResourceMonitoring();

    // We execute in batches to simulate concurrency
    const activePromises: Promise<void>[] = [];

    // Simple loop strategy for now: maintain N active workers
    for (let i = 0; i < config.concurrentClients; i++) {
      activePromises.push(this.runWorker(i, endTime, config.endpoints));
    }

    await Promise.all(activePromises);

    // Stop resource monitoring
    this.stopResourceMonitoring();

    return this.generateReport(config, startTime);
  }

  private async runWorker(
    workerId: number,
    endTime: number,
    endpoints: string[],
  ) {
    // Each worker needs its own transport connection usually,
    // especially for stateful connections.
    const transport = this.createTransport();

    try {
      await transport.connect();

      // Initial Handshake for this worker
      await this.measureRequest(transport, "initialize", {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "mcp-stress", version: "0.1.0" },
      });

      while (Date.now() < endTime) {
        for (const method of endpoints) {
          if (Date.now() >= endTime) break;

          // Do not re-run initialize in loop
          if (method === "initialize") continue;

          await this.measureRequest(transport, method, {});

          // Small yield to prevent event loop starvation in single-threaded verify tool
          await new Promise((r) => setTimeout(r, WORKER_YIELD_MS));
        }
      }
    } catch (error) {
      this.recordError(error);
    } finally {
      transport.close();
    }
  }

  private async measureRequest(
    transport: ITransport,
    method: string,
    params: JsonValue,
  ) {
    const start = Date.now();
    let success = false;
    try {
      await transport.send({
        jsonrpc: "2.0",
        id: Math.floor(Math.random() * RANDOM_ID_MAX),
        method,
        params,
      });
      success = true;
    } catch (e) {
      success = false;
      this.recordError(e);
    } finally {
      const duration = Date.now() - start;
      this.metrics.push({
        endpoint: method,
        durationMs: duration,
        success,
        timestamp: Date.now(),
      });
    }
  }

  private recordError(error: Error | unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    const count = this.errors.get(msg) || 0;
    this.errors.set(msg, count + 1);
  }

  private generateReport(
    config: StressTestConfig,
    startTime: number,
  ): StressTestReport {
    const totalDurationMs = Date.now() - startTime;
    const totalDurationSec = totalDurationMs / MS_PER_SECOND;

    const successful = this.metrics.filter((m) => m.success);
    const latencies = successful.map((m) => m.durationMs).sort((a, b) => a - b);

    const avg = this.calculateAverage(latencies);
    const p95 = this.calculatePercentile(latencies, PERCENTILE_95);
    const p99 = this.calculatePercentile(latencies, PERCENTILE_99);
    const max = latencies[latencies.length - 1] || 0;

    // Analyze resource usage
    const resourceWarnings = this.analyzeResourceUsage();

    return {
      serverUrl: this.targetUrl,
      timestamp: new Date().toISOString(),
      config,
      summary: {
        totalRequests: this.metrics.length,
        successfulRequests: successful.length,
        failedRequests: this.metrics.length - successful.length,
        requestsPerSecond: Math.round(this.metrics.length / totalDurationSec),
        avgLatencyMs: Math.round(avg),
        p95LatencyMs: p95,
        p99LatencyMs: p99,
        maxLatencyMs: max,
      },
      metrics: this.metrics,
      errors: Array.from(this.errors.entries()).map(([message, count]) => ({
        code: "ERR",
        message,
        count,
      })),
      resourceWarnings,
    };
  }

  /**
   * Calculate average of an array of numbers
   */
  private calculateAverage(values: number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  /**
   * Calculate percentile value from sorted array
   */
  private calculatePercentile(
    sortedValues: number[],
    percentile: number,
  ): number {
    if (sortedValues.length === 0) return 0;
    const index = Math.floor(sortedValues.length * percentile);
    return sortedValues[index] || 0;
  }

  /**
   * Start monitoring system resources during stress test
   */
  private startResourceMonitoring() {
    // Capture initial snapshot
    this.captureResourceSnapshot();

    // Capture snapshot every 500ms
    this.resourceMonitorInterval = setInterval(() => {
      this.captureResourceSnapshot();
    }, 500);
  }

  /**
   * Stop monitoring system resources
   */
  private stopResourceMonitoring() {
    if (this.resourceMonitorInterval) {
      clearInterval(this.resourceMonitorInterval);
      this.resourceMonitorInterval = null;
    }

    // Capture final snapshot
    this.captureResourceSnapshot();
  }

  /**
   * Capture a snapshot of current resource usage
   */
  private captureResourceSnapshot() {
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const usedMemory = totalMemory - freeMemory;
    const memoryUsagePercent = (usedMemory / totalMemory) * 100;

    // Simple CPU usage estimation based on load average
    const loadAvg = os.loadavg()[0]; // 1-minute load average
    const cpuCount = os.cpus().length;
    const cpuUsagePercent = Math.min((loadAvg / cpuCount) * 100, 100);

    this.resourceSnapshots.push({
      timestamp: Date.now(),
      cpuUsagePercent: Math.round(cpuUsagePercent),
      memoryUsagePercent: Math.round(memoryUsagePercent),
      availableMemoryMB: Math.round(freeMemory / (1024 * 1024)),
    });
  }

  /**
   * Analyze resource usage and generate warnings
   */
  private analyzeResourceUsage(): string[] {
    if (this.resourceSnapshots.length === 0) {
      return [];
    }

    const warnings: string[] = [];

    // Calculate average and peak resource usage
    const avgCpu = this.calculateAverage(
      this.resourceSnapshots.map((s) => s.cpuUsagePercent),
    );
    const avgMemory = this.calculateAverage(
      this.resourceSnapshots.map((s) => s.memoryUsagePercent),
    );
    const peakCpu = Math.max(
      ...this.resourceSnapshots.map((s) => s.cpuUsagePercent),
    );
    const peakMemory = Math.max(
      ...this.resourceSnapshots.map((s) => s.memoryUsagePercent),
    );
    const minAvailableMemoryMB = Math.min(
      ...this.resourceSnapshots.map((s) => s.availableMemoryMB),
    );

    // CPU warnings
    if (peakCpu >= CPU_WARNING_THRESHOLD) {
      warnings.push(
        t("stress_high_cpu", { peak: peakCpu, avg: Math.round(avgCpu) }),
      );
    }

    // Memory warnings
    if (peakMemory >= MEMORY_WARNING_THRESHOLD) {
      warnings.push(
        t("stress_high_memory", {
          peak: peakMemory,
          avg: Math.round(avgMemory),
          avail: minAvailableMemoryMB,
        }),
      );
    }

    // Low memory warning
    if (minAvailableMemoryMB < 512) {
      warnings.push(t("stress_low_memory", { avail: minAvailableMemoryMB }));
    }

    return warnings;
  }
}
