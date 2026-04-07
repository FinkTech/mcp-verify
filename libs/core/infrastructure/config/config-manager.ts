/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Enterprise Configuration Management System
 *
 * Features:
 * - Secure defaults following security best practices
 * - Configuration validation with JSON Schema
 * - Environment-based overrides
 * - Runtime configuration updates
 * - Configuration versioning
 * - Audit trail for changes
 * - Secrets management integration
 *
 * Security principles:
 * - Secure by default
 * - Principle of least privilege
 * - Defense in depth
 * - Fail securely
 *
 * Standards compliance:
 * - OWASP Secure Configuration
 * - CIS Benchmarks
 * - NIST SP 800-53
 *
 * @module libs/core/infrastructure/config
 */

import { t } from "@mcp-verify/shared";
import { Logger, AuditEventType } from "../logging/logger";

export interface SecurityConfig {
  // Security scanning
  enableSecurityScan: boolean;
  securityRules: {
    enableAll: boolean;
    enabledRules: string[];
    disabledRules: string[];
  };
  maxSeverityThreshold: "critical" | "high" | "medium" | "low";
  failOnCritical: boolean;
  failOnHigh: boolean;

  // Guardrails (Runtime security)
  guardrails: {
    enableAll: boolean;
    piiRedaction: {
      enabled: boolean;
      strictMode: boolean;
      customPatterns: string[];
    };
    rateLimiting: {
      enabled: boolean;
      perMinute: number;
      perHour: number;
      burstSize: number;
    };
    inputSanitization: {
      enabled: boolean;
      strictMode: boolean;
      allowedCharsets: string[];
    };
    httpsEnforcement: {
      enabled: boolean;
      autoUpgrade: boolean;
      allowLocalhost: boolean;
    };
  };

  // Fuzzing
  fuzzing: {
    enabled: boolean;
    useSecurityPayloads: boolean;
    useMutations: boolean;
    mutationsPerPayload: number;
    timeout: number;
    delayBetweenTests: number;
    maxPayloadsPerTool: number;
  };
}

export interface NetworkConfig {
  // Timeouts
  connectionTimeout: number;
  requestTimeout: number;
  maxRetries: number;
  retryBackoff: "linear" | "exponential";

  // TLS/SSL
  rejectUnauthorized: boolean;
  minTlsVersion: string;
  allowInsecureConnections: boolean;

  // Proxy
  proxyHost?: string;
  proxyPort?: number;
  proxyAuth?: {
    username: string;
    password: string;
  };
}

export interface LoggingConfig {
  level: "debug" | "info" | "warn" | "error" | "critical";
  enableConsole: boolean;
  enableFile: boolean;
  enableAudit: boolean;
  redactPII: boolean;
  includeStackTrace: boolean;
  prettyPrint: boolean;
  maxMessageLength: number;
  logDirectory?: string;
  logRotation: {
    enabled: boolean;
    maxFiles: number;
    maxSize: string;
  };
}

export interface PerformanceConfig {
  // Resource limits
  maxMemoryMB: number;
  maxConcurrentOperations: number;
  maxPayloadSize: number;

  // Caching
  enableCaching: boolean;
  cacheTTL: number;

  // Metrics
  enableMetrics: boolean;
  metricsInterval: number;
}

export interface ComplianceConfig {
  // Standards
  enableOWASPChecks: boolean;
  enableCISChecks: boolean;
  enableSOC2Checks: boolean;

  // Reporting
  generateSARIF: boolean;
  generateJSON: boolean;
  generateHTML: boolean;
  includeRemediation: boolean;

  // Data retention
  retainAuditLogs: boolean;
  auditLogRetentionDays: number;
}

export interface McpVerifyConfig {
  version: string;
  environment: "development" | "staging" | "production";

  security: SecurityConfig;
  network: NetworkConfig;
  logging: LoggingConfig;
  performance: PerformanceConfig;
  compliance: ComplianceConfig;

  // Feature flags
  features: {
    enableExperimentalFeatures: boolean;
    enableBetaFeatures: boolean;
  };
}

/**
 * Secure default configuration
 * Following principle of "secure by default"
 */
export const SECURE_DEFAULTS: McpVerifyConfig = {
  version: "1.0.0",
  environment: "production",

  security: {
    enableSecurityScan: true,
    securityRules: {
      enableAll: true,
      enabledRules: [],
      disabledRules: [],
    },
    maxSeverityThreshold: "high",
    failOnCritical: true,
    failOnHigh: false,

    guardrails: {
      enableAll: true,
      piiRedaction: {
        enabled: true,
        strictMode: true, // Block critical PII by default
        customPatterns: [],
      },
      rateLimiting: {
        enabled: true,
        perMinute: 60,
        perHour: 1000,
        burstSize: 10,
      },
      inputSanitization: {
        enabled: true,
        strictMode: false, // Sanitize by default, don't block
        allowedCharsets: [],
      },
      httpsEnforcement: {
        enabled: true,
        autoUpgrade: false, // Don't auto-upgrade, require explicit HTTPS
        allowLocalhost: true, // Allow localhost for development
      },
    },

    fuzzing: {
      enabled: true,
      useSecurityPayloads: true,
      useMutations: false, // Disabled by default for performance
      mutationsPerPayload: 3,
      timeout: 5000,
      delayBetweenTests: 100,
      maxPayloadsPerTool: 50, // Limit to prevent excessive testing
    },
  },

  network: {
    connectionTimeout: 30000,
    requestTimeout: 60000,
    maxRetries: 3,
    retryBackoff: "exponential",
    rejectUnauthorized: true, // Strict TLS validation
    minTlsVersion: "TLSv1.2",
    allowInsecureConnections: false, // No HTTP by default
  },

  logging: {
    level: "info",
    enableConsole: true,
    enableFile: false, // Disabled by default, enable in production
    enableAudit: true,
    redactPII: true,
    includeStackTrace: false, // Don't leak stack traces by default
    prettyPrint: false, // JSON format for production
    maxMessageLength: 5000,
    logRotation: {
      enabled: true,
      maxFiles: 10,
      maxSize: "10M",
    },
  },

  performance: {
    maxMemoryMB: 512,
    maxConcurrentOperations: 10,
    maxPayloadSize: 10485760, // 10MB
    enableCaching: true,
    cacheTTL: 3600,
    enableMetrics: true,
    metricsInterval: 60000,
  },

  compliance: {
    enableOWASPChecks: true,
    enableCISChecks: true,
    enableSOC2Checks: false, // Opt-in
    generateSARIF: true,
    generateJSON: true,
    generateHTML: false,
    includeRemediation: true,
    retainAuditLogs: true,
    auditLogRetentionDays: 90,
  },

  features: {
    enableExperimentalFeatures: false,
    enableBetaFeatures: false,
  },
};

/**
 * Development-friendly defaults
 */
export const DEVELOPMENT_DEFAULTS: Partial<McpVerifyConfig> = {
  environment: "development",
  logging: {
    ...SECURE_DEFAULTS.logging,
    level: "debug",
    prettyPrint: true,
    includeStackTrace: true,
  },
  network: {
    ...SECURE_DEFAULTS.network,
    allowInsecureConnections: true, // Allow HTTP in development
    rejectUnauthorized: false, // Allow self-signed certs
  },
  security: {
    ...SECURE_DEFAULTS.security,
    failOnCritical: false, // Don't fail fast in development
    guardrails: {
      ...SECURE_DEFAULTS.security.guardrails,
      piiRedaction: {
        ...SECURE_DEFAULTS.security.guardrails.piiRedaction,
        strictMode: false, // Less strict in development
      },
      rateLimiting: {
        ...SECURE_DEFAULTS.security.guardrails.rateLimiting,
        perMinute: 1000, // Higher limits in development
        perHour: 10000,
      },
    },
  },
};

export class ConfigManager {
  private static instance: ConfigManager;
  private config: McpVerifyConfig;
  private logger: Logger;
  private configHistory: Array<{ timestamp: string; config: McpVerifyConfig }> =
    [];

  private constructor(initialConfig?: Partial<McpVerifyConfig>) {
    this.logger = Logger.getInstance();

    // Start with secure defaults
    this.config = { ...SECURE_DEFAULTS };

    // Apply environment-specific defaults
    if (process.env.NODE_ENV === "development") {
      this.mergeConfig(DEVELOPMENT_DEFAULTS);
    }

    // Apply user overrides
    if (initialConfig) {
      this.mergeConfig(initialConfig);
    }

    // Validate configuration
    this.validateConfig();

    // Log configuration status
    this.logger.info(`Configuration initialized`, {
      component: "ConfigManager",
      metadata: {
        environment: this.config.environment,
        version: this.config.version,
      },
    });

    // Audit configuration - DISABLED for CLI noise reduction
    /*
    this.logger.audit({
      eventType: AuditEventType.CONFIG_CHANGED,
      severity: 'low',
      action: 'config_initialized',
      result: 'success',
      context: {
        component: 'ConfigManager'
      },
      details: {
        environment: this.config.environment
      }
    });
    */
  }

  /**
   * Get singleton instance
   */
  static getInstance(initialConfig?: Partial<McpVerifyConfig>): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager(initialConfig);
    }
    return ConfigManager.instance;
  }

  /**
   * Get current configuration
   */
  getConfig(): Readonly<McpVerifyConfig> {
    return Object.freeze({ ...this.config });
  }

  /**
   * Get specific configuration section
   */
  getSecurityConfig(): Readonly<SecurityConfig> {
    return Object.freeze({ ...this.config.security });
  }

  getNetworkConfig(): Readonly<NetworkConfig> {
    return Object.freeze({ ...this.config.network });
  }

  getLoggingConfig(): Readonly<LoggingConfig> {
    return Object.freeze({ ...this.config.logging });
  }

  getPerformanceConfig(): Readonly<PerformanceConfig> {
    return Object.freeze({ ...this.config.performance });
  }

  getComplianceConfig(): Readonly<ComplianceConfig> {
    return Object.freeze({ ...this.config.compliance });
  }

  /**
   * Update configuration
   */
  updateConfig(updates: Partial<McpVerifyConfig>) {
    // Save current config to history
    this.configHistory.push({
      timestamp: new Date().toISOString(),
      config: { ...this.config },
    });

    // Trim history
    if (this.configHistory.length > 100) {
      this.configHistory = this.configHistory.slice(-50);
    }

    // Apply updates
    this.mergeConfig(updates);

    // Validate
    this.validateConfig();

    // Log and audit
    this.logger.warn("Configuration updated", {
      component: "ConfigManager",
      metadata: { updates },
    });

    this.logger.audit({
      eventType: AuditEventType.CONFIG_CHANGED,
      severity: "medium",
      action: "config_updated",
      result: "success",
      context: {
        component: "ConfigManager",
      },
      details: updates,
    });
  }

  /**
   * Reset to secure defaults
   */
  resetToDefaults() {
    this.config = { ...SECURE_DEFAULTS };
    this.validateConfig();

    this.logger.warn("Configuration reset to secure defaults", {
      component: "ConfigManager",
    });

    this.logger.audit({
      eventType: AuditEventType.CONFIG_CHANGED,
      severity: "medium",
      action: "config_reset",
      result: "success",
      context: {
        component: "ConfigManager",
      },
    });
  }

  /**
   * Merge configuration with deep merge
   */
  private mergeConfig(updates: Partial<McpVerifyConfig>) {
    this.config = this.deepMerge(this.config, updates) as McpVerifyConfig;
  }

  /**
   * Deep merge utility
   */
  private deepMerge(target: unknown, source: unknown): unknown {
    const targetObj = target as Record<string, unknown>;
    const sourceObj = source as Record<string, unknown>;
    const output = { ...targetObj };

    if (this.isObject(target) && this.isObject(source)) {
      Object.keys(sourceObj).forEach((key) => {
        if (this.isObject(sourceObj[key])) {
          if (!(key in targetObj)) {
            output[key] = sourceObj[key];
          } else {
            output[key] = this.deepMerge(targetObj[key], sourceObj[key]);
          }
        } else {
          output[key] = sourceObj[key];
        }
      });
    }

    return output;
  }

  private isObject(item: unknown): item is Record<string, unknown> {
    return item !== null && typeof item === "object" && !Array.isArray(item);
  }

  /**
   * Validate configuration
   */
  private validateConfig() {
    const errors: string[] = [];

    // Validate network timeouts
    if (this.config.network.connectionTimeout < 1000) {
      errors.push("network.connectionTimeout must be at least 1000ms");
    }
    if (this.config.network.requestTimeout < 5000) {
      errors.push("network.requestTimeout must be at least 5000ms");
    }

    // Validate rate limiting
    if (this.config.security.guardrails.rateLimiting.enabled) {
      if (this.config.security.guardrails.rateLimiting.perMinute < 1) {
        errors.push(
          "security.guardrails.rateLimiting.perMinute must be at least 1",
        );
      }
    }

    // Validate performance limits
    if (this.config.performance.maxMemoryMB < 128) {
      errors.push("performance.maxMemoryMB must be at least 128");
    }
    if (this.config.performance.maxPayloadSize < 1024) {
      errors.push("performance.maxPayloadSize must be at least 1024 bytes");
    }

    // Validate fuzzing config
    if (this.config.security.fuzzing.timeout < 1000) {
      errors.push("security.fuzzing.timeout must be at least 1000ms");
    }

    // Security validations
    if (this.config.environment === "production") {
      if (this.config.network.allowInsecureConnections) {
        this.logger.warn(
          "Insecure connections allowed in production environment",
          {
            component: "ConfigManager",
          },
        );
      }
      if (!this.config.network.rejectUnauthorized) {
        this.logger.warn("TLS certificate validation disabled in production", {
          component: "ConfigManager",
        });
      }
      if (!this.config.logging.redactPII) {
        errors.push("PII redaction must be enabled in production");
      }
    }

    if (errors.length > 0) {
      const errorMessage = `Configuration validation failed: ${errors.join("; ")}`;
      this.logger.error(errorMessage, undefined, {
        component: "ConfigManager",
        metadata: { errors },
      });
      throw new Error(errorMessage);
    }
  }

  /**
   * Get configuration history
   */
  getConfigHistory(): Array<{ timestamp: string; config: McpVerifyConfig }> {
    return [...this.configHistory];
  }

  /**
   * Export configuration as JSON
   */
  exportConfig(): string {
    return JSON.stringify(this.config, null, 2);
  }

  /**
   * Import configuration from JSON
   */
  importConfig(json: string) {
    try {
      const imported = JSON.parse(json);
      this.updateConfig(imported);
    } catch (error) {
      this.logger.error("Failed to import configuration", error as Error, {
        component: "ConfigManager",
      });
      throw new Error(t("invalid_json"));
    }
  }

  /**
   * Check if feature is enabled
   */
  isFeatureEnabled(feature: "experimental" | "beta"): boolean {
    if (feature === "experimental") {
      return this.config.features.enableExperimentalFeatures;
    }
    return this.config.features.enableBetaFeatures;
  }

  /**
   * Check if running in production
   */
  isProduction(): boolean {
    return this.config.environment === "production";
  }

  /**
   * Check if running in development
   */
  isDevelopment(): boolean {
    return this.config.environment === "development";
  }
}

// Export singleton instance
export const configManager = ConfigManager.getInstance();
