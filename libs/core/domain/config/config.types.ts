/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Unified Configuration Types
 *
 * Single source of truth for all mcp-verify configuration.
 * Consolidates settings from: CLI args, ENV vars, config files, and defaults.
 *
 * Configuration hierarchy (highest priority first):
 * 1. CLI arguments (--timeout=5000)
 * 2. Environment variables (MCP_VERIFY_TIMEOUT=5000)
 * 3. Config file (mcp-verify.config.json)
 * 4. Default values (defined here)
 */

import { z } from 'zod';

// ============================================================================
// BASIC TYPES
// ============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Language = 'en' | 'es';
export type ReportFormat = 'json' | 'html' | 'markdown' | 'sarif';
export type TransportType = 'stdio' | 'http' | 'sse';

/**
 * Security rule blocks for categorization and filtering
 * - Block A: OWASP LLM Top 10 mapped to MCP (SEC-022 to SEC-030)
 * - Block B: Multi-Agent & Agentic Chain Attacks (SEC-031 to SEC-041)
 * - Block C: Operational Security & Enterprise Compliance (SEC-042 to SEC-050)
 * - Block D: AI Weaponization & Supply Chain MCP (SEC-051 to SEC-060)
 * - OWASP: Generic OWASP Top 10 (SEC-001 to SEC-013)
 * - MCP: MCP-Specific Security (SEC-014 to SEC-021)
 */
export type SecurityRuleBlock = 'OWASP' | 'MCP' | 'A' | 'B' | 'C' | 'D';

/**
 * Rule range mapping for each block
 * Used for automatic filtering by block
 */
export const RULE_BLOCK_RANGES: Record<SecurityRuleBlock, { start: number; end: number; description: string }> = {
  'OWASP': { start: 1, end: 13, description: 'OWASP Top 10 Aligned Rules' },
  'MCP': { start: 14, end: 21, description: 'MCP-Specific Security Rules' },
  'A': { start: 22, end: 30, description: 'OWASP LLM Top 10 in MCP Context' },
  'B': { start: 31, end: 41, description: 'Multi-Agent & Agentic Attacks' },
  'C': { start: 42, end: 50, description: 'Operational & Enterprise Compliance' },
  'D': { start: 51, end: 60, description: 'AI Weaponization & Supply Chain' }
};

// ============================================================================
// CONFIGURATION SECTIONS
// ============================================================================

/**
 * Output/Reporting configuration
 */
export interface OutputConfig {
  /** Default output directory for reports */
  directory: string;
  /** Default report formats to generate */
  formats: ReportFormat[];
  /** Generate HTML reports by default */
  html: boolean;
  /** Default language for reports */
  language: Language;
  /** Organize reports by format subdirectories */
  organizeByFormat: boolean;
}

/**
 * Security scanning configuration
 */
export interface SecurityConfig {
  /** Enable or disable security scanning */
  enableSecurityScan: boolean;
  /** Minimum score to pass (0-100) */
  minScore: number;
  /** Fail validation on critical findings */
  failOnCritical: boolean;
  /** Fail validation on high findings */
  failOnHigh: boolean;
  /** Security rule blocks to enable (default: all) */
  enabledBlocks: SecurityRuleBlock[];
  /** Individual rule IDs to explicitly disable (e.g., ['SEC-029', 'SEC-037']) */
  disabledRules: string[];
  /** Per-rule configuration */
  rules: Record<string, RuleConfig>;
}

/**
 * Individual rule configuration
 */
export interface RuleConfig {
  enabled: boolean;
  severity?: Severity;
  options?: Record<string, unknown>;
}

/**
 * Quality analysis configuration
 */
export interface QualityConfig {
  /** Minimum quality score to pass (0-100) */
  minScore: number;
  /** Enable LLM-based semantic analysis */
  enableSemanticAnalysis: boolean;
  /** LLM provider for semantic analysis */
  llmProvider?: 'anthropic' | 'openai' | 'ollama';
}

/**
 * Fuzzing configuration
 */
export interface FuzzingConfig {
  /** Default timeout per request in ms */
  timeout: number;
  /** Delay between requests in ms */
  delayBetweenRequests: number;
  /** Maximum concurrent requests */
  concurrency: number;
  /** Stop fuzzing on first vulnerability */
  stopOnFirstVulnerability: boolean;
  /** Enable server fingerprinting */
  enableFingerprinting: boolean;
  /** Maximum payloads per tool */
  maxPayloadsPerTool: number;
}

/**
 * Network/Transport configuration
 */
export interface NetworkConfig {
  /** Connection timeout in ms */
  connectionTimeout: number;
  /** Request timeout in ms */
  requestTimeout: number;
  /** Allow insecure HTTP connections */
  allowInsecure: boolean;
  /** Custom headers for HTTP transport */
  headers: Record<string, string>;
}

/**
 * Sandbox configuration
 */
export interface SandboxConfig {
  /** Enable Deno sandbox for stdio transport */
  enabled: boolean;
  /** Paths allowed for reading */
  allowRead: string[];
  /** Allow environment variable access */
  allowEnv: boolean;
  /** Network hosts allowed */
  allowNet: string[];
}

/**
 * Proxy guardrails configuration
 */
export interface ProxyConfig {
  /** Commands to block */
  blockedCommands: string[];
  /** Enable PII masking */
  piiMasking: boolean;
  /** Enable rate limiting */
  rateLimiting: boolean;
  /** Requests per minute limit */
  rateLimit: number;
}

/**
 * Exit codes configuration
 */
export interface ExitCodesConfig {
  /** Exit code for successful validation */
  success: number;
  /** Exit code for validation failures */
  validationFailed: number;
  /** Exit code for critical security findings */
  criticalSecurity: number;
}

// ============================================================================
// MAIN CONFIGURATION INTERFACE
// ============================================================================

/**
 * Build integrity and verification configuration
 */
export interface IntegrityConfig {
  /** Enable integrity checking */
  enabled: boolean;
  /** Maximum number of builds to keep in history (0 = unlimited) */
  historyLimit: number;
  /** Auto-cleanup old entries */
  autoCleanup: boolean;
  /** Cleanup strategy: 'keep-last-n' | 'keep-by-age' | 'manual' */
  cleanupStrategy: 'keep-last-n' | 'keep-by-age' | 'manual';
  /** Age in days before cleanup (for 'keep-by-age' strategy) */
  cleanupAgeThreshold?: number;
  /** Verify integrity on startup (doctor auto-runs) */
  verifyOnStartup: boolean;
  /** Fail startup if integrity check fails */
  failOnMismatch: boolean;
  /** Binaries to track: 'cli', 'server', or both */
  trackBinaries: Array<'cli' | 'server'>;
  /** Path to integrity manifest (relative to project root) */
  manifestPath: string;
}

/**
 * Logging configuration
 */
export interface LoggingConfig {
  /** Log level: trace, debug, info, warn, error */
  level: 'trace' | 'debug' | 'info' | 'warn' | 'error';
  /** Enable console output */
  enableConsole: boolean;
  /** Enable file logging */
  enableFile: boolean;
  /** Directory for log files */
  fileDirectory: string;
  /** Maximum file size in bytes before rotation */
  maxFileSize: number;
  /** Maximum number of log files to keep */
  maxFiles: number;
  /** Redact secrets from logs */
  redactSecrets: boolean;
  /** Include timestamps in logs */
  includeTimestamps: boolean;
  /** Colorize console output */
  colorize: boolean;
}

/**
 * Baseline comparison configuration
 */
export interface BaselineConfig {
  /** Enable baseline comparison */
  enabled: boolean;
  /** Path to baseline file */
  path: string;
  /** Fail validation if score degrades */
  failOnDegradation: boolean;
  /** Maximum allowed score drop */
  allowedScoreDrop: number;
  /** Auto-update baseline after successful runs */
  autoUpdate: boolean;
  /** Metrics to track for regression */
  trackMetrics: Array<'security' | 'quality' | 'performance'>;
}

/**
 * Performance monitoring configuration
 */
export interface PerformanceConfig {
  /** Enable performance profiling */
  enableProfiling: boolean;
  /** Track memory usage */
  trackMemory: boolean;
  /** Track CPU usage */
  trackCpu: boolean;
  /** Threshold for slow operations (ms) */
  slowOperationThreshold: number;
  /** Log slow operations */
  logSlowOperations: boolean;
}

/**
 * Notification configuration (Coming Soon)
 */
export interface NotificationsConfig {
  /** Enable notifications */
  enabled: boolean;
  /** Email notifications */
  email?: {
    enabled: boolean;
    recipients: string[];
    onCriticalFinding: boolean;
    onScanComplete: boolean;
  };
  /** Slack notifications */
  slack?: {
    enabled: boolean;
    webhookUrl: string;
    channel: string;
  };
  /** Generic webhook notifications */
  webhook?: {
    enabled: boolean;
    url: string;
    method: 'POST' | 'PUT';
    headers: Record<string, string>;
  };
}

/**
 * CI/CD integration configuration (Coming Soon)
 */
export interface CiConfig {
  /** Enable CI/CD features */
  enabled: boolean;
  /** CI provider: github, gitlab, jenkins, circleci, etc. */
  provider: 'github' | 'gitlab' | 'jenkins' | 'circleci' | 'other';
  /** Fail pipeline on validation failure */
  failPipeline: boolean;
  /** Upload artifacts (reports) */
  uploadArtifacts: boolean;
  /** Create issues for critical findings */
  createIssues: boolean;
  /** Comment on pull requests */
  commentPR: boolean;
  /** Update status checks */
  statusChecks: boolean;
}

/**
 * Security disclaimer preferences
 */
export interface DisclaimersConfig {
  /** Enable disclaimer prompts */
  enabled: boolean;
  /** Suppress all disclaimers (not recommended) */
  suppressAll: boolean;
  /** Accepted disclaimers by command */
  accepted: {
    fuzz: boolean;
    stress: boolean;
    proxy: boolean;
    'scan-config': boolean;
  };
  /** Require explicit acceptance */
  requireAcceptance: boolean;
}

/**
 * Plugin system configuration (Coming Soon)
 */
export interface PluginsConfig {
  /** Enable plugin system */
  enabled: boolean;
  /** Directory for plugins */
  directory: string;
  /** Auto-load plugins on startup */
  autoLoad: boolean;
  /** Allow remote plugins (security risk) */
  allowRemote: boolean;
  /** Plugin registry URLs */
  registry: string[];
}

/**
 * Telemetry configuration (Coming Soon - Opt-in only)
 */
export interface TelemetryConfig {
  /** Enable anonymous telemetry */
  enabled: boolean;
  /** Anonymize all data */
  anonymize: boolean;
  /** Telemetry endpoint */
  endpoint: string;
  /** Collection interval (ms) */
  interval: number;
}

/**
 * Workspace and session configuration
 */
export interface WorkspaceConfig {
  /** Directory for workspace state (default: '.mcp-verify') */
  directory: string;
  /** Maximum number of commands to keep in history (default: 100) */
  historyLimit: number;
  /** Enable persistent storage of sessions (default: true) */
  persistenceEnabled: boolean;
  /** Filename for session state (default: 'session.json') */
  sessionFile: string;
  /** Auto-save interval (ms) */
  autoSaveInterval?: number;
  /** Backup configuration */
  backup?: {
    enabled: boolean;
    interval: number;
    maxBackups: number;
  };
}

/**
 * Complete mcp-verify configuration
 */
export interface McpVerifyConfig {
  /** Configuration schema version */
  $schema?: string;

  /** Build integrity and verification settings */
  integrity: IntegrityConfig;

  /** Output/Reporting settings */
  output: OutputConfig;

  /** Security scanning settings */
  security: SecurityConfig;

  /** Quality analysis settings */
  quality: QualityConfig;

  /** Fuzzing settings */
  fuzzing: FuzzingConfig;

  /** Network/Transport settings */
  network: NetworkConfig;

  /** Sandbox settings */
  sandbox: SandboxConfig;

  /** Proxy guardrails settings */
  proxy: ProxyConfig;

  /** Workspace settings */
  workspace: WorkspaceConfig;

  /** Baseline comparison settings */
  baseline: BaselineConfig;

  /** Logging settings */
  logging: LoggingConfig;

  /** Performance monitoring settings */
  performance: PerformanceConfig;

  /** Notification settings (Coming Soon) */
  notifications: NotificationsConfig;

  /** CI/CD integration settings (Coming Soon) */
  ci: CiConfig;

  /** Security disclaimer preferences */
  disclaimers: DisclaimersConfig;

  /** Plugin system settings (Coming Soon) */
  plugins: PluginsConfig;

  /** Telemetry settings (Coming Soon - Opt-in only) */
  telemetry: TelemetryConfig;

  /** Exit codes */
  exitCodes: ExitCodesConfig;
}

// ============================================================================
// DEFAULT CONFIGURATION
// ============================================================================

/**
 * Default configuration values
 * These are used when no config file is found or values are missing
 */
export const DEFAULT_CONFIG: McpVerifyConfig = {
  integrity: {
    enabled: true,
    historyLimit: 20,
    autoCleanup: true,
    cleanupStrategy: 'keep-last-n',
    cleanupAgeThreshold: 90,
    verifyOnStartup: false,
    failOnMismatch: false,
    trackBinaries: ['cli', 'server'],
    manifestPath: '.mcp-verify/integrity-history.json'
  },

  output: {
    directory: './reports',
    formats: ['json', 'html'],
    html: true,
    language: 'en',
    organizeByFormat: true
  },

  security: {
    enableSecurityScan: true,
    minScore: 70,
    failOnCritical: true,
    failOnHigh: false,
    enabledBlocks: ['OWASP', 'MCP', 'A', 'B', 'C'],  // All blocks except D (AI Weaponization) by default
    disabledRules: [],  // No rules explicitly disabled
    rules: {
      // Block OWASP: OWASP Top 10 Aligned Rules (SEC-001 to SEC-013)
      'SEC-001': { enabled: true, severity: 'high' },      // Authentication Bypass
      'SEC-002': { enabled: true, severity: 'critical' },  // Command Injection
      'SEC-003': { enabled: true, severity: 'high' },      // SQL Injection
      'SEC-004': { enabled: true, severity: 'high' },      // SSRF
      'SEC-005': { enabled: true, severity: 'high' },      // XXE Injection
      'SEC-006': { enabled: true, severity: 'high' },      // Insecure Deserialization
      'SEC-007': { enabled: true, severity: 'high' },      // Path Traversal
      'SEC-008': { enabled: true, severity: 'medium' },    // Data Leakage
      'SEC-009': { enabled: true, severity: 'high' },      // Sensitive Data Exposure
      'SEC-010': { enabled: true, severity: 'medium' },    // Missing Rate Limiting
      'SEC-011': { enabled: true, severity: 'medium' },    // ReDoS Detection
      'SEC-012': { enabled: true, severity: 'high' },      // Weak Cryptography
      'SEC-013': { enabled: true, severity: 'high' },      // Prompt Injection

      // Block MCP: MCP-Specific Security Rules (SEC-014 to SEC-021)
      'SEC-014': { enabled: true, severity: 'high' },      // Exposed Network Endpoint
      'SEC-015': { enabled: true, severity: 'high' },      // Missing Authentication
      'SEC-016': { enabled: true, severity: 'medium' },    // Insecure URI Scheme
      'SEC-017': { enabled: true, severity: 'medium' },    // Excessive Tool Permissions
      'SEC-018': { enabled: true, severity: 'medium' },    // Secrets in Descriptions
      'SEC-019': { enabled: true, severity: 'medium' },    // Missing Input Constraints
      'SEC-020': { enabled: true, severity: 'medium' },    // Dangerous Tool Chaining
      'SEC-021': { enabled: true, severity: 'high' },      // Unencrypted Credentials

      // Block A: OWASP LLM Top 10 in MCP Context (SEC-022 to SEC-030)
      'SEC-022': { enabled: true, severity: 'high' },      // Excessive Agency
      'SEC-023': { enabled: true, severity: 'high' },      // Prompt Injection via Tools
      'SEC-024': { enabled: true, severity: 'high' },      // Insecure Output Handling
      'SEC-025': { enabled: true, severity: 'high' },      // Supply Chain Tool Dependencies
      'SEC-026': { enabled: true, severity: 'medium' },    // Sensitive Data in Tool Responses
      'SEC-027': { enabled: true, severity: 'medium' },    // Training Data Poisoning
      'SEC-028': { enabled: true, severity: 'medium' },    // Model DoS via Tools
      'SEC-029': { enabled: true, severity: 'medium' },    // Insecure Plugin Design
      'SEC-030': { enabled: true, severity: 'medium' },    // Excessive Data Disclosure

      // Block B: Multi-Agent & Agentic Attacks (SEC-031 to SEC-041)
      'SEC-031': { enabled: true, severity: 'high' },      // Tool Result Tampering
      'SEC-032': { enabled: true, severity: 'high' },      // Recursive Agent Loop
      'SEC-033': { enabled: true, severity: 'high' },      // Multi-Agent Privilege Escalation
      'SEC-034': { enabled: true, severity: 'medium' },    // Agent State Poisoning
      'SEC-035': { enabled: true, severity: 'medium' },    // Distributed Agent DDoS
      'SEC-036': { enabled: true, severity: 'high' },      // Agent Swarm Coordination Attack
      'SEC-037': { enabled: true, severity: 'high' },      // Agent Identity Spoofing
      'SEC-038': { enabled: true, severity: 'high' },      // Cross-Agent Prompt Injection
      'SEC-039': { enabled: true, severity: 'medium' },    // Agent Reputation Hijacking
      'SEC-040': { enabled: true, severity: 'medium' },    // Tool Chaining Path Traversal
      'SEC-041': { enabled: true, severity: 'medium' },    // Agent Memory Injection

      // Block C: Operational & Enterprise Compliance (SEC-042 to SEC-050)
      'SEC-042': { enabled: true, severity: 'medium' },    // Missing Audit Logging
      'SEC-043': { enabled: true, severity: 'medium' },    // Insecure Session Management
      'SEC-044': { enabled: true, severity: 'medium' },    // Exposed Endpoint
      'SEC-045': { enabled: true, severity: 'low' },       // Insecure Default Configuration
      'SEC-046': { enabled: true, severity: 'medium' },    // Missing CORS Validation
      'SEC-047': { enabled: true, severity: 'low' },       // Schema Versioning Absent
      'SEC-048': { enabled: true, severity: 'medium' },    // Missing Capability Negotiation
      'SEC-049': { enabled: true, severity: 'medium' },    // Timing Side-Channel in Auth
      'SEC-050': { enabled: true, severity: 'low' },       // Insufficient Output Entropy

      // Block D: AI Weaponization & Supply Chain MCP (SEC-051 to SEC-060)
      'SEC-051': { enabled: false, severity: 'high' },      // Weaponized MCP Fuzzer (disabled by default)
      'SEC-052': { enabled: false, severity: 'critical' },  // Autonomous MCP Backdoor (disabled by default)
      'SEC-053': { enabled: false, severity: 'critical' },  // Malicious Config File (disabled by default)
      'SEC-054': { enabled: true, severity: 'critical' },   // API Endpoint Hijacking
      'SEC-055': { enabled: false, severity: 'high' },      // Jailbreak-as-a-Service (disabled by default)
      'SEC-056': { enabled: false, severity: 'high' },      // Phishing via MCP (disabled by default)
      'SEC-057': { enabled: false, severity: 'medium' },    // Data Exfiltration via Steganography (disabled by default)
      'SEC-058': { enabled: false, severity: 'critical' },  // Self-Replicating MCP (disabled by default)
      'SEC-059': { enabled: true, severity: 'high' },       // Unvalidated Tool Authorization
      'SEC-060': { enabled: true, severity: 'medium' }      // Missing Transaction Semantics
    }
  },

  quality: {
    minScore: 50,
    enableSemanticAnalysis: false,
    llmProvider: undefined
  },

  fuzzing: {
    timeout: 5000,
    delayBetweenRequests: 100,
    concurrency: 5,
    stopOnFirstVulnerability: false,
    enableFingerprinting: false,
    maxPayloadsPerTool: 100
  },

  network: {
    connectionTimeout: 30000,
    requestTimeout: 30000,
    allowInsecure: false,
    headers: {}
  },

  sandbox: {
    enabled: false,
    allowRead: ['.'],
    allowEnv: true,
    allowNet: []
  },

  proxy: {
    blockedCommands: ['rm -rf', 'mkfs', 'dd if=', 'format', ':(){:|:&};:'],
    piiMasking: false,
    rateLimiting: true,
    rateLimit: 60
  },

  workspace: {
    directory: '.mcp-verify',
    historyLimit: 500,
    persistenceEnabled: true,
    sessionFile: 'session.json',
    autoSaveInterval: 30000,
    backup: {
      enabled: true,
      interval: 86400000, // 24 hours
      maxBackups: 5
    }
  },

  baseline: {
    enabled: false,
    path: './baseline.json',
    failOnDegradation: false,
    allowedScoreDrop: 5,
    autoUpdate: false,
    trackMetrics: ['security', 'quality', 'performance']
  },

  logging: {
    level: 'info',
    enableConsole: true,
    enableFile: true,
    fileDirectory: '.mcp-verify/logs',
    maxFileSize: 10485760, // 10 MB
    maxFiles: 5,
    redactSecrets: true,
    includeTimestamps: true,
    colorize: true
  },

  performance: {
    enableProfiling: false,
    trackMemory: false,
    trackCpu: false,
    slowOperationThreshold: 1000,
    logSlowOperations: false
  },

  notifications: {
    enabled: false,
    email: {
      enabled: false,
      recipients: [],
      onCriticalFinding: true,
      onScanComplete: false
    },
    slack: {
      enabled: false,
      webhookUrl: '',
      channel: '#security'
    },
    webhook: {
      enabled: false,
      url: '',
      method: 'POST',
      headers: {}
    }
  },

  ci: {
    enabled: false,
    provider: 'github',
    failPipeline: true,
    uploadArtifacts: true,
    createIssues: false,
    commentPR: false,
    statusChecks: true
  },

  disclaimers: {
    enabled: true,
    suppressAll: false,
    accepted: {
      fuzz: false,
      stress: false,
      proxy: false,
      'scan-config': false
    },
    requireAcceptance: true
  },

  plugins: {
    enabled: false,
    directory: '.mcp-verify/plugins',
    autoLoad: true,
    allowRemote: false,
    registry: []
  },

  telemetry: {
    enabled: false,
    anonymize: true,
    endpoint: 'https://telemetry.mcp-verify.dev',
    interval: 86400000 // 24 hours
  },

  exitCodes: {
    success: 0,
    validationFailed: 1,
    criticalSecurity: 2
  }
};

// ============================================================================
// ZOD VALIDATION SCHEMAS
// ============================================================================

const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const LanguageSchema = z.enum(['en', 'es']);
const ReportFormatSchema = z.enum(['json', 'html', 'markdown', 'sarif']);

const RuleConfigSchema = z.object({
  enabled: z.boolean(),
  severity: SeveritySchema.optional(),
  options: z.record(z.string(), z.unknown()).optional()
});

const OutputConfigSchema = z.object({
  directory: z.string(),
  formats: z.array(ReportFormatSchema),
  html: z.boolean(),
  language: LanguageSchema,
  organizeByFormat: z.boolean()
}).partial();

const SecurityRuleBlockSchema = z.enum(['OWASP', 'MCP', 'A', 'B', 'C', 'D']);

const SecurityConfigSchema = z.object({
  enableSecurityScan: z.boolean().optional(),
  minScore: z.number().min(0).max(100),
  failOnCritical: z.boolean(),
  failOnHigh: z.boolean(),
  enabledBlocks: z.array(SecurityRuleBlockSchema),
  disabledRules: z.array(z.string()),
  rules: z.record(z.string(), RuleConfigSchema)
}).partial();

const QualityConfigSchema = z.object({
  minScore: z.number().min(0).max(100),
  enableSemanticAnalysis: z.boolean(),
  llmProvider: z.enum(['anthropic', 'openai', 'ollama']).optional()
}).partial();

const FuzzingConfigSchema = z.object({
  timeout: z.number().positive(),
  delayBetweenRequests: z.number().min(0),
  concurrency: z.number().positive(),
  stopOnFirstVulnerability: z.boolean(),
  enableFingerprinting: z.boolean(),
  maxPayloadsPerTool: z.number().positive()
}).partial();

const NetworkConfigSchema = z.object({
  connectionTimeout: z.number().positive(),
  requestTimeout: z.number().positive(),
  allowInsecure: z.boolean(),
  headers: z.record(z.string(), z.string())
}).partial();

const SandboxConfigSchema = z.object({
  enabled: z.boolean(),
  allowRead: z.array(z.string()),
  allowEnv: z.boolean(),
  allowNet: z.array(z.string())
}).partial();

const ProxyConfigSchema = z.object({
  blockedCommands: z.array(z.string()),
  piiMasking: z.boolean(),
  rateLimiting: z.boolean(),
  rateLimit: z.number().positive()
}).partial();

const WorkspaceConfigSchema = z.object({
  directory: z.string(),
  historyLimit: z.number().positive(),
  persistenceEnabled: z.boolean(),
  sessionFile: z.string(),
  autoSaveInterval: z.number().positive().optional(),
  backup: z.object({
    enabled: z.boolean(),
    interval: z.number().positive(),
    maxBackups: z.number().positive()
  }).optional()
}).partial();

const IntegrityConfigSchema = z.object({
  enabled: z.boolean(),
  historyLimit: z.number().positive(),
  autoCleanup: z.boolean(),
  cleanupStrategy: z.enum(['keep-last-n', 'keep-by-age', 'manual']),
  cleanupAgeThreshold: z.number().positive().optional(),
  verifyOnStartup: z.boolean(),
  failOnMismatch: z.boolean(),
  trackBinaries: z.array(z.enum(['cli', 'server'])),
  manifestPath: z.string()
}).partial();

const LoggingConfigSchema = z.object({
  level: z.enum(['trace', 'debug', 'info', 'warn', 'error']),
  enableConsole: z.boolean(),
  enableFile: z.boolean(),
  fileDirectory: z.string(),
  maxFileSize: z.number().positive(),
  maxFiles: z.number().positive(),
  redactSecrets: z.boolean(),
  includeTimestamps: z.boolean(),
  colorize: z.boolean()
}).partial();

const BaselineConfigSchema = z.object({
  enabled: z.boolean(),
  path: z.string(),
  failOnDegradation: z.boolean(),
  allowedScoreDrop: z.number().nonnegative(),
  autoUpdate: z.boolean(),
  trackMetrics: z.array(z.enum(['security', 'quality', 'performance']))
}).partial();

const PerformanceConfigSchema = z.object({
  enableProfiling: z.boolean(),
  trackMemory: z.boolean(),
  trackCpu: z.boolean(),
  slowOperationThreshold: z.number().positive(),
  logSlowOperations: z.boolean()
}).partial();

const NotificationsConfigSchema = z.object({
  enabled: z.boolean(),
  email: z.object({
    enabled: z.boolean(),
    recipients: z.array(z.string().email()),
    onCriticalFinding: z.boolean(),
    onScanComplete: z.boolean()
  }).optional(),
  slack: z.object({
    enabled: z.boolean(),
    webhookUrl: z.string().url(),
    channel: z.string()
  }).optional(),
  webhook: z.object({
    enabled: z.boolean(),
    url: z.string().url(),
    method: z.enum(['POST', 'PUT']),
    headers: z.record(z.string(), z.string())
  }).optional()
}).partial();

const CiConfigSchema = z.object({
  enabled: z.boolean(),
  provider: z.enum(['github', 'gitlab', 'circleci', 'jenkins']),
  failPipeline: z.boolean(),
  uploadArtifacts: z.boolean(),
  createIssues: z.boolean(),
  commentPR: z.boolean(),
  statusChecks: z.boolean()
}).partial();

const DisclaimersConfigSchema = z.object({
  enabled: z.boolean(),
  suppressAll: z.boolean(),
  accepted: z.object({
    fuzz: z.boolean(),
    stress: z.boolean(),
    proxy: z.boolean(),
    'scan-config': z.boolean()
  }),
  requireAcceptance: z.boolean()
}).partial();

const PluginsConfigSchema = z.object({
  enabled: z.boolean(),
  directory: z.string(),
  autoLoad: z.boolean(),
  allowRemote: z.boolean(),
  registry: z.array(z.string())
}).partial();

const TelemetryConfigSchema = z.object({
  enabled: z.boolean(),
  anonymize: z.boolean(),
  endpoint: z.string().url(),
  interval: z.number().positive()
}).partial();

const ExitCodesConfigSchema = z.object({
  success: z.number(),
  validationFailed: z.number(),
  criticalSecurity: z.number()
}).partial();

/**
 * Full configuration schema (all fields optional for partial configs)
 */
export const McpVerifyConfigSchema = z.object({
  $schema: z.string().optional(),
  output: OutputConfigSchema.optional(),
  security: SecurityConfigSchema.optional(),
  quality: QualityConfigSchema.optional(),
  fuzzing: FuzzingConfigSchema.optional(),
  network: NetworkConfigSchema.optional(),
  sandbox: SandboxConfigSchema.optional(),
  proxy: ProxyConfigSchema.optional(),
  workspace: WorkspaceConfigSchema.optional(),
  integrity: IntegrityConfigSchema.optional(),
  logging: LoggingConfigSchema.optional(),
  baseline: BaselineConfigSchema.optional(),
  performance: PerformanceConfigSchema.optional(),
  notifications: NotificationsConfigSchema.optional(),
  ci: CiConfigSchema.optional(),
  disclaimers: DisclaimersConfigSchema.optional(),
  plugins: PluginsConfigSchema.optional(),
  telemetry: TelemetryConfigSchema.optional(),
  exitCodes: ExitCodesConfigSchema.optional()
});

/**
 * Type for partial configuration (from config files)
 */
export type PartialConfig = z.infer<typeof McpVerifyConfigSchema>;

/**
 * Validate and parse a raw configuration object
 * @throws ZodError with detailed validation errors if config is invalid
 */
export function validateConfig(rawConfig: unknown): PartialConfig {
  return McpVerifyConfigSchema.parse(rawConfig);
}

// ============================================================================
// ENV VARIABLE MAPPING
// ============================================================================

/**
 * Environment variable to config path mapping
 * Allows override via MCP_VERIFY_* environment variables
 */
export const ENV_MAPPING: Record<string, string> = {
  'MCP_VERIFY_OUTPUT_DIR': 'output.directory',
  'MCP_VERIFY_LANGUAGE': 'output.language',
  'MCP_VERIFY_HTML': 'output.html',
  'MCP_VERIFY_TIMEOUT': 'network.requestTimeout',
  'MCP_VERIFY_SECURITY_MIN_SCORE': 'security.minScore',
  'MCP_VERIFY_FAIL_ON_CRITICAL': 'security.failOnCritical',
  'MCP_VERIFY_QUALITY_MIN_SCORE': 'quality.minScore',
  'MCP_VERIFY_FUZZ_TIMEOUT': 'fuzzing.timeout',
  'MCP_VERIFY_FUZZ_CONCURRENCY': 'fuzzing.concurrency',
  'MCP_VERIFY_SANDBOX_ENABLED': 'sandbox.enabled',
  'MCP_VERIFY_ALLOW_INSECURE': 'network.allowInsecure',
  'MCP_VERIFY_WORKSPACE_DIR': 'workspace.directory'
};
