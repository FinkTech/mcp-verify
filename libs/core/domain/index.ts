/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Domain Layer Barrel Exports
 *
 * Business logic and domain entities for mcp-verify:
 * - Security (Scanner, Rules, Guardrails)
 * - Quality (Semantic Analyzer)
 * - Reporting (Badges, Reports)
 * - Transport (ITransport interface)
 * - Configuration (Config types and loader)
 */

// Transport
export { ITransport, StdioTransport, HttpTransport } from "./transport";

// Configuration
export {
  // Main types
  McpVerifyConfig,
  PartialConfig,
  DEFAULT_CONFIG,
  // Section types
  OutputConfig,
  SecurityConfig,
  QualityConfig,
  FuzzingConfig,
  NetworkConfig,
  SandboxConfig,
  ProxyConfig,
  ExitCodesConfig,
  RuleConfig,
  // Basic types
  Severity,
  ReportFormat,
  TransportType,
  // Validation
  validateConfig,
  McpVerifyConfigSchema,
  ENV_MAPPING,
} from "./config/config.types";

export {
  ConfigLoader,
  ConfigLoadOptions,
  getConfig,
  loadConfig,
} from "./config/config-loader";

// Security - Scanner
export { SecurityScanner } from "./security/security-scanner";

// Security - Rules
export { ISecurityRule } from "./security/rule.interface";
export { PathTraversalRule } from "./security/rules/path-traversal.rule";
export { CommandInjectionRule } from "./security/rules/command-injection.rule";
export { SSRFDetectionRule } from "./security/rules/ssrf.rule";
export { DataLeakageRule } from "./security/rules/data-leakage.rule";
export { XXEInjectionRule } from "./security/rules/xxe-injection.rule";
export { InsecureDeserializationRule } from "./security/rules/insecure-deserialization.rule";
export { SQLInjectionRule } from "./security/rules/sql-injection.rule";
export { ReDoSDetectionRule } from "./security/rules/redos-detection.rule";
export { AuthenticationBypassRule } from "./security/rules/auth-bypass.rule";
export { SensitiveDataExposureRule } from "./security/rules/sensitive-exposure.rule";
export { RateLimitingRule } from "./security/rules/rate-limiting.rule";
export { WeakCryptographyRule } from "./security/rules/weak-crypto.rule";
export { PromptInjectionRule } from "./security/rules/prompt-injection.rule";
export { ExposedEndpointRule } from "./security/rules/exposed-endpoint.rule";
export { MissingAuthenticationRule } from "./security/rules/missing-authentication.rule";
export { InsecureURISchemeRule } from "./security/rules/insecure-uri-scheme.rule";
export { ExcessivePermissionsRule } from "./security/rules/excessive-permissions.rule";
export { SecretsInDescriptionsRule } from "./security/rules/secrets-in-descriptions.rule";
export { MissingInputConstraintsRule } from "./security/rules/missing-input-constraints.rule";
export { DangerousToolChainingRule } from "./security/rules/dangerous-tool-chaining.rule";
export { UnencryptedCredentialsRule } from "./security/rules/unencrypted-credentials.rule";

// Security - Guardrails
export * from "../use-cases/proxy/guardrails";

// Security - Fuzzing
export * from "../use-cases/fuzzer/fuzzer";

// Quality
export { SemanticAnalyzer } from "./quality/semantic-analyzer";

// Reporting
export * from "./reporting/disclaimer";
export { BadgeGenerator } from "./reporting/badge-generator";
export { SarifGenerator } from "./reporting/sarif-generator";
export { HtmlReportGenerator } from "./reporting/html-generator";
export { TextReportGenerator } from "./reporting/text-generator";
export {
  EnhancedReporter,
  enhancedReporter,
} from "./reporting/enhanced-reporter";
export { translations, Language } from "./reporting/i18n";
export {
  generateDisclaimer,
  generateMetadata,
  getDisclaimerText,
  getShortDisclaimer,
  getLlmNotice,
  DisclaimerOptions,
} from "./reporting/disclaimer";

// MCP Server Entities
export {
  Report,
  ReportMetadata,
  ReportDisclaimer,
  GitInfo,
  HandshakeResult,
  DiscoveryResult,
  ValidationResult,
  FuzzingReport,
  SecurityFinding,
  SecurityReport,
  QualityIssue,
  QualityReport,
  Badge,
  // MCP Protocol types (re-exported from validation.types)
  McpTool,
  McpResource,
  McpPrompt,
  JsonValue,
  JsonObject,
  JsonArray,
  JsonPrimitive,
} from "./mcp-server/entities/validation.types";
