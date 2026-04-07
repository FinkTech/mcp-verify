/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * mcp-verify Core Library
 *
 * Enterprise-grade security validation and testing tool for MCP servers.
 * Version: 1.0.0
 *
 * @module @mcp-verify/core
 *
 * @example
 * ```typescript
 * // Infrastructure layer
 * import { Logger, ErrorHandler, ConfigManager, HealthMonitor } from '@mcp-verify/core';
 *
 * // Domain layer
 * import { SecurityScanner, SemanticAnalyzer, BadgeGenerator } from '@mcp-verify/core';
 *
 * // Use case layer
 * import { MCPValidator } from '@mcp-verify/core';
 * ```
 */

// ==================== INFRASTRUCTURE LAYER ====================
// Enterprise-grade infrastructure components

export {
  // Logging
  Logger,
  LogLevel,
  AuditEventType,
  LogContext,
  LogEntry,
  AuditEntry,
  LoggerConfig,
  createScopedLogger,
  PerformanceTimer,

  // Error Handling
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

  // Configuration
  ConfigManager,
  SECURE_DEFAULTS,
  DEVELOPMENT_DEFAULTS,

  // Health Monitoring
  HealthMonitor,
  HealthCheck,
  SystemHealthCheck,
  NetworkHealthCheck,
  SecurityHealthCheck,
  HealthStatus,
  ComponentType,
  HealthCheckResult,
  getHealthCheckEndpoint,
  getMetricsEndpoint,
  getPrometheusMetricsEndpoint,
  DiagnosticRunner,
} from "./infrastructure";

// ==================== DOMAIN LAYER ====================
// Business logic and domain entities

export {
  // Transport
  ITransport,
  StdioTransport,
  HttpTransport,

  // Configuration Types
  McpVerifyConfig,
  DEFAULT_CONFIG,
  RuleConfig,
  Severity,
  ProxyConfig,
  ConfigLoader,

  // Security - Scanner
  SecurityScanner,

  // Security - Rules (All 21 OWASP-aligned rules)
  ISecurityRule,
  PathTraversalRule,
  CommandInjectionRule,
  SSRFDetectionRule,
  DataLeakageRule,
  XXEInjectionRule,
  InsecureDeserializationRule,
  SQLInjectionRule,
  ReDoSDetectionRule,
  AuthenticationBypassRule,
  SensitiveDataExposureRule,
  RateLimitingRule,
  WeakCryptographyRule,
  PromptInjectionRule,
  ExposedEndpointRule,
  MissingAuthenticationRule,
  InsecureURISchemeRule,
  ExcessivePermissionsRule,
  SecretsInDescriptionsRule,
  MissingInputConstraintsRule,
  DangerousToolChainingRule,
  UnencryptedCredentialsRule,
} from "./domain";

export {
  // Security - Guardrails
  PIIRedactor,
  RateLimiter,
  InputSanitizer,
  HttpsEnforcer,
  SensitiveCommandBlocker,
} from "./use-cases/proxy/guardrails";

export {
  // Security - Secret Redaction
  IDetector,
  EntropyDetector,
  HighConfidenceDetector,
  PrefixDetector,
  SecretScanner,
} from "./domain/redaction";

export { IGuardrail, InterceptResult } from "./use-cases/proxy/proxy.types";

export {
  // Quality Analysis
  SemanticAnalyzer,

  // Reporting
  BadgeGenerator,
  SarifGenerator,
  EnhancedReporter,
  enhancedReporter,

  // MCP Server Entities
  Report,
  HandshakeResult,
  DiscoveryResult,
  ValidationResult,
  FuzzingReport,
  SecurityFinding,
  SecurityReport,
  QualityIssue,
  QualityReport,
  Badge,

  // MCP Protocol types
  McpTool,
  McpResource,
  McpPrompt,
  JsonValue,
  JsonObject,
  JsonArray,
  JsonPrimitive,

  // I18n & Reporting
  translations,
  Language,
  HtmlReportGenerator,

  // Disclaimer functions
  generateDisclaimer,
  generateMetadata,
  getShortDisclaimer,
  getDisclaimerText,
  getLlmNotice,
  DisclaimerOptions,
} from "./domain";

// ==================== USE CASE LAYER ====================
// Application orchestration

export { MCPValidator } from "./use-cases/validator/validator";
export {
  ProtocolComplianceTester,
  ProtocolComplianceReport,
} from "./use-cases/compliance/protocol-tester";
export type {
  JsonRpcRequest,
  JsonRpcNotification,
} from "./domain/shared/common.types";

// ==================== VERSION ====================
export const VERSION = "1.0.0";
export const PACKAGE_NAME = "mcp-verify";
