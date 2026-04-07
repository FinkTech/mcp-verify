/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ConfigManager Tests
 * Comprehensive test suite for configuration management
 */

import {
  ConfigManager,
  McpVerifyConfig,
  SECURE_DEFAULTS,
  DEVELOPMENT_DEFAULTS,
} from "../config-manager";

describe("ConfigManager", () => {
  let configManager: ConfigManager;

  beforeEach(() => {
    // Reset singleton for each test
    (ConfigManager as any).instance = undefined;
    configManager = ConfigManager.getInstance();
  });

  describe("Singleton Pattern", () => {
    it("should return the same instance", () => {
      const instance1 = ConfigManager.getInstance();
      const instance2 = ConfigManager.getInstance();
      expect(instance1).toBe(instance2);
    });

    it("should accept initial configuration", () => {
      (ConfigManager as any).instance = undefined;
      const config = ConfigManager.getInstance({ version: "2.0.0" });
      expect(config.getConfig().version).toBe("2.0.0");
    });
  });

  describe("Default Configuration", () => {
    it("should start with secure defaults", () => {
      const config = configManager.getConfig();
      expect(config.version).toBe(SECURE_DEFAULTS.version);
      expect(config.environment).toBe(SECURE_DEFAULTS.environment);
      expect(config.security.enableSecurityScan).toBe(true);
    });

    it("should use development defaults in development environment", () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";

      (ConfigManager as any).instance = undefined;
      const devConfig = ConfigManager.getInstance();

      expect(devConfig.getConfig().logging.level).toBe("debug");
      expect(devConfig.getConfig().logging.prettyPrint).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe("Security Configuration", () => {
    it("should have security scanning enabled by default", () => {
      const config = configManager.getSecurityConfig();
      expect(config.enableSecurityScan).toBe(true);
    });

    it("should have all security rules enabled by default", () => {
      const config = configManager.getSecurityConfig();
      expect(config.securityRules.enableAll).toBe(true);
    });

    it("should fail on critical vulnerabilities by default", () => {
      const config = configManager.getSecurityConfig();
      expect(config.failOnCritical).toBe(true);
    });

    it("should have all guardrails enabled by default", () => {
      const config = configManager.getSecurityConfig();
      expect(config.guardrails.enableAll).toBe(true);
      expect(config.guardrails.piiRedaction.enabled).toBe(true);
      expect(config.guardrails.rateLimiting.enabled).toBe(true);
      expect(config.guardrails.inputSanitization.enabled).toBe(true);
      expect(config.guardrails.httpsEnforcement.enabled).toBe(true);
    });

    it("should have fuzzing enabled with secure defaults", () => {
      const config = configManager.getSecurityConfig();
      expect(config.fuzzing.enabled).toBe(true);
      expect(config.fuzzing.useMutations).toBe(false); // Performance
      expect(config.fuzzing.maxPayloadsPerTool).toBe(50); // Limited
    });
  });

  describe("Network Configuration", () => {
    it("should enforce TLS by default", () => {
      const config = configManager.getNetworkConfig();
      expect(config.rejectUnauthorized).toBe(true);
      expect(config.minTlsVersion).toBe("TLSv1.2");
      expect(config.allowInsecureConnections).toBe(false);
    });

    it("should have reasonable timeouts", () => {
      const config = configManager.getNetworkConfig();
      expect(config.connectionTimeout).toBe(30000);
      expect(config.requestTimeout).toBe(60000);
      expect(config.maxRetries).toBe(3);
    });

    it("should use exponential backoff for retries", () => {
      const config = configManager.getNetworkConfig();
      expect(config.retryBackoff).toBe("exponential");
    });
  });

  describe("Logging Configuration", () => {
    it("should have PII redaction enabled by default", () => {
      const config = configManager.getLoggingConfig();
      expect(config.redactPII).toBe(true);
    });

    it("should not include stack traces by default", () => {
      const config = configManager.getLoggingConfig();
      expect(config.includeStackTrace).toBe(false);
    });

    it("should have audit logging enabled", () => {
      const config = configManager.getLoggingConfig();
      expect(config.enableAudit).toBe(true);
    });

    it("should use structured logging (not pretty print)", () => {
      const config = configManager.getLoggingConfig();
      expect(config.prettyPrint).toBe(false);
    });
  });

  describe("Performance Configuration", () => {
    it("should have reasonable resource limits", () => {
      const config = configManager.getPerformanceConfig();
      expect(config.maxMemoryMB).toBe(512);
      expect(config.maxConcurrentOperations).toBe(10);
      expect(config.maxPayloadSize).toBe(10485760); // 10MB
    });

    it("should have caching enabled", () => {
      const config = configManager.getPerformanceConfig();
      expect(config.enableCaching).toBe(true);
      expect(config.cacheTTL).toBe(3600);
    });

    it("should have metrics enabled", () => {
      const config = configManager.getPerformanceConfig();
      expect(config.enableMetrics).toBe(true);
    });
  });

  describe("Compliance Configuration", () => {
    it("should have OWASP and CIS checks enabled", () => {
      const config = configManager.getComplianceConfig();
      expect(config.enableOWASPChecks).toBe(true);
      expect(config.enableCISChecks).toBe(true);
    });

    it("should generate SARIF and JSON reports", () => {
      const config = configManager.getComplianceConfig();
      expect(config.generateSARIF).toBe(true);
      expect(config.generateJSON).toBe(true);
    });

    it("should retain audit logs", () => {
      const config = configManager.getComplianceConfig();
      expect(config.retainAuditLogs).toBe(true);
      expect(config.auditLogRetentionDays).toBe(90);
    });
  });

  describe("Configuration Updates", () => {
    it("should allow updating configuration", () => {
      configManager.updateConfig({
        version: "2.0.0",
      });

      expect(configManager.getConfig().version).toBe("2.0.0");
    });

    it("should deep merge configuration", () => {
      configManager.updateConfig({
        security: {
          guardrails: {
            rateLimiting: {
              enabled: true,
              perMinute: 100,
              perHour: 1000,
              burstSize: 20,
            },
          },
        },
      } as any);

      const config = configManager.getConfig();
      expect(config.security.guardrails.rateLimiting.perMinute).toBe(100);
      // Other values should remain
      expect(config.security.guardrails.rateLimiting.perHour).toBe(1000);
      expect(config.security.guardrails.piiRedaction.enabled).toBe(true);
    });

    it("should maintain configuration history", () => {
      const initialVersion = configManager.getConfig().version;

      configManager.updateConfig({ version: "2.0.0" });
      configManager.updateConfig({ version: "3.0.0" });

      const history = configManager.getConfigHistory();
      expect(history.length).toBe(2);
      expect(history[0].config.version).toBe(initialVersion);
      expect(history[1].config.version).toBe("2.0.0");
    });

    it("should trim history to prevent memory issues", () => {
      for (let i = 0; i < 101; i++) {
        configManager.updateConfig({ version: `${i}.0.0` });
      }

      const history = configManager.getConfigHistory();
      expect(history.length).toBe(50);
    });
  });

  describe("Configuration Validation", () => {
    it("should validate connection timeout", () => {
      expect(() => {
        configManager.updateConfig({
          network: {
            connectionTimeout: 500,
            requestTimeout: 60000,
            maxRetries: 3,
            retryBackoff: "exponential" as const,
            rejectUnauthorized: true,
            minTlsVersion: "TLSv1.2" as const,
            allowInsecureConnections: false,
          },
        } as any);
      }).toThrow("connectionTimeout must be at least 1000ms");
    });

    it("should validate request timeout", () => {
      expect(() => {
        configManager.updateConfig({
          network: {
            connectionTimeout: 30000,
            requestTimeout: 3000,
            maxRetries: 3,
            retryBackoff: "exponential" as const,
            rejectUnauthorized: true,
            minTlsVersion: "TLSv1.2" as const,
            allowInsecureConnections: false,
          },
        } as any);
      }).toThrow("requestTimeout must be at least 5000ms");
    });

    it("should validate rate limiting", () => {
      expect(() => {
        configManager.updateConfig({
          security: {
            guardrails: {
              rateLimiting: {
                enabled: true,
                perMinute: 0,
                perHour: 1000,
                burstSize: 20,
              },
            },
          },
        } as any);
      }).toThrow("perMinute must be at least 1");
    });

    it("should validate memory limits", () => {
      expect(() => {
        configManager.updateConfig({
          performance: {
            maxMemoryMB: 50,
            maxConcurrentOperations: 10,
            maxPayloadSize: 10485760,
            enableCaching: true,
            cacheTTL: 3600,
            enableMetrics: true,
            metricsInterval: 60,
          },
        } as any);
      }).toThrow("maxMemoryMB must be at least 128");
    });

    it("should validate payload size", () => {
      expect(() => {
        configManager.updateConfig({
          performance: {
            maxMemoryMB: 512,
            maxConcurrentOperations: 10,
            maxPayloadSize: 512,
            enableCaching: true,
            cacheTTL: 3600,
            enableMetrics: true,
            metricsInterval: 60,
          },
        } as any);
      }).toThrow("maxPayloadSize must be at least 1024 bytes");
    });

    it("should warn about insecure settings in production", () => {
      (ConfigManager as any).instance = undefined;
      const config = ConfigManager.getInstance({ environment: "production" });

      config.updateConfig({
        network: {
          connectionTimeout: 30000,
          requestTimeout: 60000,
          maxRetries: 3,
          retryBackoff: "exponential" as const,
          rejectUnauthorized: true,
          minTlsVersion: "TLSv1.2" as const,
          allowInsecureConnections: true,
        },
      } as any);

      // Should log warning but not throw
      expect(config.getConfig().network.allowInsecureConnections).toBe(true);
    });

    it("should enforce PII redaction in production", () => {
      (ConfigManager as any).instance = undefined;
      const config = ConfigManager.getInstance({ environment: "production" });

      expect(() => {
        config.updateConfig({
          logging: {
            level: "info" as const,
            enableConsole: true,
            redactPII: false,
            includeStackTrace: false,
            enableAudit: true,
            maxMessageLength: 1000,
            prettyPrint: false,
          },
        } as any);
      }).toThrow("PII redaction must be enabled in production");
    });
  });

  describe("Configuration Reset", () => {
    it("should reset to secure defaults", () => {
      configManager.updateConfig({
        version: "99.0.0",
      } as any);

      configManager.resetToDefaults();

      const config = configManager.getConfig();
      expect(config.version).toBe(SECURE_DEFAULTS.version);
      expect(config.security.enableSecurityScan).toBe(true);
    });
  });

  describe("Configuration Export/Import", () => {
    it("should export configuration as JSON", () => {
      const exported = configManager.exportConfig();
      const parsed = JSON.parse(exported);

      expect(parsed.version).toBeDefined();
      expect(parsed.security).toBeDefined();
      expect(parsed.network).toBeDefined();
    });

    it("should import configuration from JSON", () => {
      const config = {
        version: "5.0.0",
        security: { enableSecurityScan: false },
      };

      configManager.importConfig(JSON.stringify(config));

      expect(configManager.getConfig().version).toBe("5.0.0");
      expect(configManager.getConfig().security.enableSecurityScan).toBe(false);
    });

    it("should throw on invalid JSON import", () => {
      expect(() => {
        configManager.importConfig("invalid json");
      }).toThrow("Server returned invalid JSON");
    });
  });

  describe("Feature Flags", () => {
    it("should check experimental features", () => {
      expect(configManager.isFeatureEnabled("experimental")).toBe(false);

      configManager.updateConfig({
        features: {
          enableExperimentalFeatures: true,
          enableBetaFeatures: false,
        },
      } as any);

      expect(configManager.isFeatureEnabled("experimental")).toBe(true);
    });

    it("should check beta features", () => {
      expect(configManager.isFeatureEnabled("beta")).toBe(false);

      configManager.updateConfig({
        features: {
          enableExperimentalFeatures: false,
          enableBetaFeatures: true,
        },
      } as any);

      expect(configManager.isFeatureEnabled("beta")).toBe(true);
    });
  });

  describe("Environment Detection", () => {
    it("should detect production environment", () => {
      (ConfigManager as any).instance = undefined;
      const config = ConfigManager.getInstance({ environment: "production" });
      expect(config.isProduction()).toBe(true);
      expect(config.isDevelopment()).toBe(false);
    });

    it("should detect development environment", () => {
      (ConfigManager as any).instance = undefined;
      const config = ConfigManager.getInstance({ environment: "development" });
      expect(config.isDevelopment()).toBe(true);
      expect(config.isProduction()).toBe(false);
    });
  });

  describe("Immutability", () => {
    it("should return frozen config objects", () => {
      const config = configManager.getConfig();
      expect(Object.isFrozen(config)).toBe(true);
    });

    it("should not allow modifying returned config", () => {
      const config = configManager.getConfig();
      expect(() => {
        (config as any).version = "999.0.0";
      }).toThrow();
    });

    it("should return frozen security config", () => {
      const config = configManager.getSecurityConfig();
      expect(Object.isFrozen(config)).toBe(true);
    });
  });
});

describe("SECURE_DEFAULTS", () => {
  it("should have production environment", () => {
    expect(SECURE_DEFAULTS.environment).toBe("production");
  });

  it("should have security features enabled", () => {
    expect(SECURE_DEFAULTS.security.enableSecurityScan).toBe(true);
    expect(SECURE_DEFAULTS.security.guardrails.enableAll).toBe(true);
  });

  it("should enforce TLS", () => {
    expect(SECURE_DEFAULTS.network.rejectUnauthorized).toBe(true);
    expect(SECURE_DEFAULTS.network.allowInsecureConnections).toBe(false);
  });

  it("should have PII redaction enabled", () => {
    expect(SECURE_DEFAULTS.logging.redactPII).toBe(true);
  });

  it("should not expose stack traces", () => {
    expect(SECURE_DEFAULTS.logging.includeStackTrace).toBe(false);
  });
});

describe("DEVELOPMENT_DEFAULTS", () => {
  it("should have development environment", () => {
    expect(DEVELOPMENT_DEFAULTS.environment).toBe("development");
  });

  it("should have debug logging", () => {
    expect(DEVELOPMENT_DEFAULTS.logging?.level).toBe("debug");
    expect(DEVELOPMENT_DEFAULTS.logging?.prettyPrint).toBe(true);
    expect(DEVELOPMENT_DEFAULTS.logging?.includeStackTrace).toBe(true);
  });

  it("should allow insecure connections in development", () => {
    expect(DEVELOPMENT_DEFAULTS.network?.allowInsecureConnections).toBe(true);
    expect(DEVELOPMENT_DEFAULTS.network?.rejectUnauthorized).toBe(false);
  });

  it("should be less strict with security", () => {
    expect(DEVELOPMENT_DEFAULTS.security?.failOnCritical).toBe(false);
    expect(
      DEVELOPMENT_DEFAULTS.security?.guardrails.piiRedaction.strictMode,
    ).toBe(false);
  });

  it("should have higher rate limits", () => {
    expect(
      DEVELOPMENT_DEFAULTS.security?.guardrails.rateLimiting.perMinute,
    ).toBe(1000);
    expect(DEVELOPMENT_DEFAULTS.security?.guardrails.rateLimiting.perHour).toBe(
      10000,
    );
  });
});
