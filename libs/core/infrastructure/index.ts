/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Infrastructure Layer Exports
 *
 * Enterprise-grade infrastructure components for mcp-verify
 *
 * @module libs/core/infrastructure
 */

// Logging
export {
  Logger,
  LogLevel,
  AuditEventType,
  LogContext,
  LogEntry,
  AuditEntry,
  LoggerConfig,
  createScopedLogger,
  PerformanceTimer,
  logger,
} from "./logging/logger";

// Configuration
export {
  ConfigManager,
  McpVerifyConfig,
  SecurityConfig,
  NetworkConfig,
  LoggingConfig,
  PerformanceConfig,
  ComplianceConfig,
  SECURE_DEFAULTS,
  DEVELOPMENT_DEFAULTS,
  configManager,
} from "./config/config-manager";

// Error Handling
export {
  ErrorHandler,
  AppError,
  ValidationError,
  NetworkError,
  TimeoutError,
  SecurityError,
  RateLimitError,
  ConfigurationError,
  InternalError,
  CircuitBreaker,
  ErrorCategory,
  ErrorSeverity,
  RecoveryStrategy,
  RetryConfig,
  DEFAULT_RETRY_CONFIG,
  HandleErrors,
  errorHandler,
} from "./errors/error-handler";

// Health Monitoring
export {
  HealthMonitor,
  HealthCheck,
  SystemHealthCheck,
  NetworkHealthCheck,
  SecurityHealthCheck,
  HealthStatus,
  ComponentType,
  HealthCheckResult,
  SystemHealthReport,
  SystemMetrics,
  getHealthCheckEndpoint,
  getMetricsEndpoint,
  getPrometheusMetricsEndpoint,
  healthMonitor,
} from "./monitoring/health-check";

// Diagnostics
export { DiagnosticRunner } from "./diagnostics/diagnostic-runner";
