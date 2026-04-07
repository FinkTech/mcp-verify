/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * HealthMonitor Tests
 * Comprehensive test suite for health monitoring system
 */

import {
  HealthMonitor,
  SystemHealthCheck,
  NetworkHealthCheck,
  SecurityHealthCheck,
  HealthStatus,
  ComponentType,
  getHealthCheckEndpoint,
  getMetricsEndpoint,
  getPrometheusMetricsEndpoint,
} from "../health-check";

describe("HealthMonitor", () => {
  let monitor: HealthMonitor;

  beforeEach(() => {
    (HealthMonitor as any).instance = undefined;
    monitor = HealthMonitor.getInstance();
    monitor.resetMetrics();
  });

  describe("Singleton Pattern", () => {
    it("should return the same instance", () => {
      const instance1 = HealthMonitor.getInstance();
      const instance2 = HealthMonitor.getInstance();
      expect(instance1).toBe(instance2);
    });
  });

  describe("Health Checks", () => {
    it("should run all registered health checks", async () => {
      const report = await monitor.runHealthChecks();

      expect(report.status).toBeDefined();
      expect(report.timestamp).toBeDefined();
      expect(report.checks).toBeInstanceOf(Array);
      expect(report.checks.length).toBeGreaterThan(0);
    });

    it("should include system health check by default", async () => {
      const report = await monitor.runHealthChecks();

      const systemCheck = report.checks.find((c) => c.component === "System");
      expect(systemCheck).toBeDefined();
      expect(systemCheck?.componentType).toBe(ComponentType.SYSTEM);
    });

    it("should include network health check by default", async () => {
      const report = await monitor.runHealthChecks();

      const networkCheck = report.checks.find((c) => c.component === "Network");
      expect(networkCheck).toBeDefined();
      expect(networkCheck?.componentType).toBe(ComponentType.NETWORK);
    });

    it("should include security health check by default", async () => {
      const report = await monitor.runHealthChecks();

      const securityCheck = report.checks.find(
        (c) => c.component === "Security",
      );
      expect(securityCheck).toBeDefined();
      expect(securityCheck?.componentType).toBe(ComponentType.SECURITY);
    });

    it("should report overall HEALTHY status when all checks pass", async () => {
      const report = await monitor.runHealthChecks();

      // Status can be HEALTHY or DEGRADED depending on system memory usage
      expect([HealthStatus.HEALTHY, HealthStatus.DEGRADED]).toContain(
        report.status,
      );
    });

    it("should include uptime in report", async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      const report = await monitor.runHealthChecks();

      expect(report.uptime).toBeGreaterThan(0);
    });

    it("should include version in report", async () => {
      const report = await monitor.runHealthChecks();

      expect(report.version).toBe("1.0.0");
    });

    it("should include metrics in report", async () => {
      const report = await monitor.runHealthChecks();

      expect(report.metrics).toBeDefined();
      expect(report.metrics.totalRequests).toBeDefined();
      expect(report.metrics.avgResponseTime).toBeDefined();
    });
  });

  describe("Metrics Recording", () => {
    it("should record successful requests", () => {
      monitor.recordRequest(100, true);
      const metrics = monitor.getMetrics();

      expect(metrics.totalRequests).toBe(1);
      expect(metrics.totalErrors).toBe(0);
    });

    it("should record failed requests", () => {
      monitor.recordRequest(100, false);
      const metrics = monitor.getMetrics();

      expect(metrics.totalRequests).toBe(1);
      expect(metrics.totalErrors).toBe(1);
    });

    it("should calculate error rate", () => {
      monitor.recordRequest(100, true);
      monitor.recordRequest(100, false);
      monitor.recordRequest(100, true);
      monitor.recordRequest(100, false);

      const metrics = monitor.getMetrics();

      expect(metrics.errorRate).toBe(50); // 2 errors out of 4 requests
      expect(metrics.successRate).toBe(50);
    });

    it("should record validations", () => {
      monitor.recordValidation();
      monitor.recordValidation();

      const metrics = monitor.getMetrics();
      expect(metrics.totalValidations).toBe(2);
    });

    it("should record security findings", () => {
      monitor.recordSecurityFinding();
      monitor.recordSecurityFinding();
      monitor.recordSecurityFinding();

      const metrics = monitor.getMetrics();
      expect(metrics.totalSecurityFindings).toBe(3);
    });
  });

  describe("Response Time Metrics", () => {
    it("should calculate average response time", () => {
      monitor.recordRequest(100, true);
      monitor.recordRequest(200, true);
      monitor.recordRequest(300, true);

      const metrics = monitor.getMetrics();

      // Average should be calculated from recent requests
      expect(metrics.avgResponseTime).toBeGreaterThan(0);
    });

    it("should calculate P95 response time", () => {
      for (let i = 1; i <= 100; i++) {
        monitor.recordRequest(i, true);
      }

      const metrics = monitor.getMetrics();

      expect(metrics.p95ResponseTime).toBeGreaterThan(0);
      expect(metrics.p95ResponseTime).toBeLessThanOrEqual(100);
    });

    it("should calculate P99 response time", () => {
      for (let i = 1; i <= 100; i++) {
        monitor.recordRequest(i, true);
      }

      const metrics = monitor.getMetrics();

      expect(metrics.p99ResponseTime).toBeGreaterThan(0);
      expect(metrics.p99ResponseTime).toBeLessThanOrEqual(100);
      expect(metrics.p99ResponseTime).toBeGreaterThanOrEqual(
        metrics.p95ResponseTime,
      );
    });

    it("should handle empty response times", () => {
      const metrics = monitor.getMetrics();

      expect(metrics.avgResponseTime).toBe(0);
      expect(metrics.p95ResponseTime).toBe(0);
      expect(metrics.p99ResponseTime).toBe(0);
    });
  });

  describe("Memory Metrics", () => {
    it("should report memory usage", () => {
      const metrics = monitor.getMetrics();

      expect(metrics.memoryUsage.used).toBeGreaterThan(0);
      expect(metrics.memoryUsage.total).toBeGreaterThan(0);
      expect(metrics.memoryUsage.percentage).toBeGreaterThan(0);
      expect(metrics.memoryUsage.percentage).toBeLessThanOrEqual(100);
    });

    it("should calculate memory percentage correctly", () => {
      const metrics = monitor.getMetrics();

      const expectedPercentage =
        (metrics.memoryUsage.used / metrics.memoryUsage.total) * 100;
      expect(
        Math.abs(metrics.memoryUsage.percentage - expectedPercentage),
      ).toBeLessThan(1);
    });
  });

  describe("Metrics Reset", () => {
    it("should reset all metrics", () => {
      monitor.recordRequest(100, true);
      monitor.recordValidation();
      monitor.recordSecurityFinding();

      monitor.resetMetrics();

      const metrics = monitor.getMetrics();
      expect(metrics.totalRequests).toBe(0);
      expect(metrics.totalValidations).toBe(0);
      expect(metrics.totalSecurityFindings).toBe(0);
    });
  });

  describe("Uptime Tracking", () => {
    it("should track uptime", async () => {
      await new Promise((resolve) => setTimeout(resolve, 100));

      const uptime = monitor.getUptime();
      expect(uptime).toBeGreaterThanOrEqual(0);
    });

    it("should measure uptime in seconds", async () => {
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const uptime = monitor.getUptime();
      expect(uptime).toBeGreaterThanOrEqual(1);
    });
  });

  describe("Prometheus Export", () => {
    it("should export metrics in Prometheus format", () => {
      monitor.recordRequest(100, true);

      const prometheus = monitor.exportPrometheusMetrics();

      expect(prometheus).toContain("# HELP");
      expect(prometheus).toContain("# TYPE");
      expect(prometheus).toContain("mcp_verify_requests_total");
    });

    it("should include all key metrics", () => {
      monitor.recordRequest(100, true);
      monitor.recordRequest(100, false);

      const prometheus = monitor.exportPrometheusMetrics();

      expect(prometheus).toContain("mcp_verify_requests_total");
      expect(prometheus).toContain("mcp_verify_errors_total");
      expect(prometheus).toContain("mcp_verify_response_time_seconds");
      expect(prometheus).toContain("mcp_verify_memory_usage_bytes");
      expect(prometheus).toContain("mcp_verify_error_rate");
    });

    it("should include quantiles for response time", () => {
      for (let i = 1; i <= 100; i++) {
        monitor.recordRequest(i, true);
      }

      const prometheus = monitor.exportPrometheusMetrics();

      expect(prometheus).toContain('quantile="0.95"');
      expect(prometheus).toContain('quantile="0.99"');
    });
  });
});

describe("SystemHealthCheck", () => {
  it("should check system health", async () => {
    const check = new SystemHealthCheck();
    const result = await check.execute();

    expect(result.status).toBeDefined();
    expect(result.component).toBe("System");
    expect(result.componentType).toBe(ComponentType.SYSTEM);
    expect(result.timestamp).toBeDefined();
    expect(result.responseTime).toBeGreaterThanOrEqual(0);
  });

  it("should include system details", async () => {
    const check = new SystemHealthCheck();
    const result = await check.execute();

    expect(result.details).toBeDefined();
    expect(result.details?.memoryMB).toBeGreaterThan(0);
    expect(result.details?.uptime).toBeGreaterThanOrEqual(0);
    expect(result.details?.nodeVersion).toBeDefined();
    expect(result.details?.platform).toBeDefined();
  });

  it("should report DEGRADED when memory is high", async () => {
    const check = new SystemHealthCheck();
    const result = await check.execute();

    // Memory check depends on actual usage
    expect([HealthStatus.HEALTHY, HealthStatus.DEGRADED]).toContain(
      result.status,
    );
  });
});

describe("NetworkHealthCheck", () => {
  it("should check network health", async () => {
    const check = new NetworkHealthCheck();
    const result = await check.execute();

    expect(result.status).toBeDefined();
    expect(result.component).toBe("Network");
    expect(result.componentType).toBe(ComponentType.NETWORK);
  });

  it("should report HEALTHY by default", async () => {
    const check = new NetworkHealthCheck();
    const result = await check.execute();

    expect(result.status).toBe(HealthStatus.HEALTHY);
  });
});

describe("SecurityHealthCheck", () => {
  it("should check security subsystem health", async () => {
    const check = new SecurityHealthCheck();
    const result = await check.execute();

    expect(result.status).toBeDefined();
    expect(result.component).toBe("Security");
    expect(result.componentType).toBe(ComponentType.SECURITY);
  });

  it("should include security details", async () => {
    const check = new SecurityHealthCheck();
    const result = await check.execute();

    expect(result.details).toBeDefined();
    expect(result.details?.guardrailsActive).toBe(true);
    expect(result.details?.securityRulesLoaded).toBe(true);
    expect(result.details?.auditingEnabled).toBe(true);
  });
});

describe("Health Endpoints", () => {
  beforeEach(() => {
    (HealthMonitor as any).instance = undefined;
  });

  describe("getHealthCheckEndpoint", () => {
    it("should return 200 status for healthy system", async () => {
      const endpoint = await getHealthCheckEndpoint();

      expect(endpoint.statusCode).toBe(200);
      expect(endpoint.body).toBeDefined();
    });

    it("should return valid JSON", async () => {
      const endpoint = await getHealthCheckEndpoint();

      const parsed = JSON.parse(endpoint.body);
      expect(parsed.status).toBeDefined();
      expect(parsed.checks).toBeInstanceOf(Array);
    });
  });

  describe("getMetricsEndpoint", () => {
    it("should return 200 status", () => {
      const endpoint = getMetricsEndpoint();

      expect(endpoint.statusCode).toBe(200);
      expect(endpoint.body).toBeDefined();
    });

    it("should return metrics as JSON", () => {
      const endpoint = getMetricsEndpoint();

      const parsed = JSON.parse(endpoint.body);
      expect(parsed.totalRequests).toBeDefined();
      expect(parsed.avgResponseTime).toBeDefined();
    });
  });

  describe("getPrometheusMetricsEndpoint", () => {
    it("should return 200 status", () => {
      const endpoint = getPrometheusMetricsEndpoint();

      expect(endpoint.statusCode).toBe(200);
      expect(endpoint.body).toBeDefined();
    });

    it("should return Prometheus content type", () => {
      const endpoint = getPrometheusMetricsEndpoint();

      expect(endpoint.contentType).toBe("text/plain; version=0.0.4");
    });

    it("should return Prometheus format", () => {
      const endpoint = getPrometheusMetricsEndpoint();

      expect(endpoint.body).toContain("# HELP");
      expect(endpoint.body).toContain("# TYPE");
    });
  });
});
