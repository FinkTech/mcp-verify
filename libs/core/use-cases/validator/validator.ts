/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { t } from '@mcp-verify/shared';
import type { ITransport } from '../../domain/transport';
import { SecurityScanner } from '../../domain/security/security-scanner';
import { SemanticAnalyzer } from '../../domain/quality/semantic-analyzer';
import { BadgeGenerator } from '../../domain/reporting/badge-generator';
import { ProtocolComplianceTester } from '../../use-cases/compliance/protocol-tester';
import type { ProtocolComplianceReport } from '../../use-cases/compliance/protocol-tester';
import { ConfigLoader } from '../../domain/config/config-loader';
import type { McpVerifyConfig, PartialConfig } from '../../domain/config/config.types';
import { schemaValidator } from '../../domain/validation/schema-validator';
import type {
  Report,
  HandshakeResult,
  DiscoveryResult,
  ValidationResult,
  SecurityReport,
  FuzzingReport
} from '../../domain/mcp-server/entities/validation.types';
import type { McpTool, McpResource, McpPrompt, JsonValue } from '../../domain/shared/common.types';

// Infrastructure Layer
import { Logger, createScopedLogger, PerformanceTimer, AuditEventType } from '../../infrastructure/logging/logger';
import { ErrorHandler, NetworkError, TimeoutError, AppError, MethodNotFoundError, ErrorCategory, ErrorSeverity } from '../../infrastructure/errors/error-handler';
import { ConfigManager } from '../../infrastructure/config/config-manager';
import { HealthMonitor } from '../../infrastructure/monitoring/health-check';

export class MCPValidator {
  private transport: ITransport;
  private startTime: number;
  private requestId: number = 1;
  private securityScanner: SecurityScanner;
  private semanticAnalyzer: SemanticAnalyzer;
  private protocolTester: ProtocolComplianceTester;
  private config: McpVerifyConfig;
  private enableSemanticCheck: boolean;

  // Infrastructure Layer
  private logger: ReturnType<typeof createScopedLogger>;
  private errorHandler: ErrorHandler;
  private configManager: ConfigManager;
  private healthMonitor: HealthMonitor;

  // SECURITY FIX: DoS Protection Limits
  private readonly MAX_TOOLS = 1000;
  private readonly MAX_RESOURCES = 1000;
  private readonly MAX_PROMPTS = 1000;
  private readonly MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB
  private readonly DISCOVERY_TIMEOUT = 30000; // 30 seconds
  private readonly VALIDATION_TIMEOUT = 120000; // 2 minutes

  private llmProvider?: string;

  constructor(
    transport: ITransport,
    configPath?: string,
    options: {
      enableSemanticCheck?: boolean;
      llmProvider?: string;
      rules?: string;
      excludeRules?: string;
      minSeverity?: string;
    } = {}
  ) {
    this.transport = transport;
    this.startTime = Date.now();
    this.enableSemanticCheck = options.enableSemanticCheck || false;
    this.llmProvider = options.llmProvider;

    // Initialize Infrastructure Layer
    this.logger = createScopedLogger('MCPValidator');
    this.errorHandler = ErrorHandler.getInstance();
    this.configManager = ConfigManager.getInstance();
    this.healthMonitor = HealthMonitor.getInstance();

    // Map options to PartialConfig
    const overrides: PartialConfig = {
      quality: {
        enableSemanticAnalysis: options.enableSemanticCheck,
        llmProvider: options.llmProvider as any
      },
      security: {
        disabledRules: options.excludeRules ? options.excludeRules.split(',') : undefined,
        // Rules string might be block names or comma-separated IDs
        enabledBlocks: options.rules ? (options.rules.split(',') as any) : undefined
      }
    };

    // Load Policy-as-Code
    this.config = ConfigLoader.load({ configPath, overrides });

    // Sync infrastructure config manager with loaded policy
    this.configManager.updateConfig(this.config as any);

    this.securityScanner = new SecurityScanner(this.config);

    // Initialize semantic analyzer with optional LLM integration
    if (this.enableSemanticCheck || this.llmProvider) {
      const { LLMSemanticAnalyzer } = require('../../domain/quality/llm-semantic-analyzer');
      const llmAnalyzer = new LLMSemanticAnalyzer();
      this.semanticAnalyzer = new SemanticAnalyzer(llmAnalyzer, this.llmProvider);
      this.logger.info('LLM semantic analysis enabled', { provider: this.llmProvider || 'not specified' });
    } else {
      this.semanticAnalyzer = new SemanticAnalyzer();
    }

    this.protocolTester = new ProtocolComplianceTester(transport);

    this.logger.info('MCPValidator initialized', {
      metadata: {
        configPath: configPath || 'default',
        transport: transport.constructor.name,
      },
    });
  }

  /**
   * SECURITY FIX: Helper to create timeout promise for DoS protection
   */
  private createTimeout(ms: number, operation: string): Promise<never> {
    return new Promise((_, reject) =>
      setTimeout(() => reject(new TimeoutError(
        `${operation} timeout after ${ms}ms. ` +
        `This may indicate a misconfigured or malicious server.`
      )), ms)
    );
  }

  /**
   * SECURITY FIX: Validate discovery result against DoS limits
   */
  private validateDiscoveryLimits(result: DiscoveryResult): void {
    // Check tools limit
    if (result.tools && result.tools.length > this.MAX_TOOLS) {
      throw new AppError(
        `[Security] Server returned too many tools: ${result.tools.length} (max: ${this.MAX_TOOLS})\n` +
        t('warn_dos_attempt'),
        'DOS_PROTECTION_TOOLS_LIMIT',
        ErrorCategory.SECURITY,
        ErrorSeverity.CRITICAL
      );
    }

    // Check resources limit
    if (result.resources && result.resources.length > this.MAX_RESOURCES) {
      throw new AppError(
        `[Security] Server returned too many resources: ${result.resources.length} (max: ${this.MAX_RESOURCES})\n` +
        t('warn_dos_attempt'),
        'DOS_PROTECTION_RESOURCES_LIMIT',
        ErrorCategory.SECURITY,
        ErrorSeverity.CRITICAL
      );
    }

    // Check prompts limit
    if (result.prompts && result.prompts.length > this.MAX_PROMPTS) {
      throw new AppError(
        `[Security] Server returned too many prompts: ${result.prompts.length} (max: ${this.MAX_PROMPTS})\n` +
        t('warn_dos_attempt'),
        'DOS_PROTECTION_PROMPTS_LIMIT',
        ErrorCategory.SECURITY,
        ErrorSeverity.CRITICAL
      );
    }

    // Check response size
    const responseSize = JSON.stringify(result).length;
    if (responseSize > this.MAX_RESPONSE_SIZE) {
      const sizeMB = (responseSize / 1024 / 1024).toFixed(2);
      const maxMB = (this.MAX_RESPONSE_SIZE / 1024 / 1024).toFixed(2);
      throw new AppError(
        `[Security] Server response too large: ${sizeMB}MB (max: ${maxMB}MB)\n` +
        t('warn_dos_attempt'),
        'DOS_PROTECTION_SIZE_LIMIT',
        ErrorCategory.SECURITY,
        ErrorSeverity.CRITICAL
      );
    }

    this.logger.debug('Discovery limits validation passed', {
      metadata: {
        tools: result.tools?.length || 0,
        resources: result.resources?.length || 0,
        prompts: result.prompts?.length || 0,
        sizeKB: (responseSize / 1024).toFixed(2)
      }
    });
  }

  /**
   * Send JSON-RPC 2.0 message to MCP server via Transport
   */
  private async sendJsonRPC(method: string, params: unknown): Promise<unknown> {
    const timer = new PerformanceTimer(`jsonrpc_${method}`, 'MCPValidator');
    const startTime = Date.now();

    try {
      this.logger.debug(`Sending ${method}`, { metadata: { method, params } });

      const response = await this.errorHandler.executeWithRetry(
        async () => {
          try {
            return await this.transport.send({
              jsonrpc: '2.0',
              id: this.requestId++,
              method,
              // Convert undefined to null (JSON spec doesn't allow undefined)
              params: params !== undefined ? (params as JsonValue) : null,
            });
          } catch (e) {
            const err = e as Error;
            this.logger.debug(`sendJsonRPC caught error for ${method}`, {
              metadata: {
                message: err.message,
                name: err.name,
                includesMethodNotFound: err.message?.includes('Method not found')
              }
            });

            // DETECT METHOD NOT FOUND to avoid retries
            if (err.message && (err.message.includes('Method not found') || err.message.includes('-32601'))) {
              this.logger.debug(`Converting to MethodNotFoundError for ${method}`);
              throw new MethodNotFoundError(method, { originalError: err });
            }
            throw e;
          }
        },
        {
          maxAttempts: this.configManager.getNetworkConfig().maxRetries,
          initialDelay: 1000,
          backoffMultiplier: 2,
        }
      );

      const duration = Date.now() - startTime;
      this.healthMonitor.recordRequest(duration, true);
      timer.end({ metadata: { method, success: true } });

      return response;
    } catch (error) {
      // Allow MethodNotFoundError to propagate without wrapping as NetworkError
      if (error instanceof MethodNotFoundError) {
        timer.endWithError(error as Error);
        throw error;
      }

      const duration = Date.now() - startTime;
      this.healthMonitor.recordRequest(duration, false);
      timer.endWithError(error as Error);

      const cause = error as Error;
      let errorMsg = t('jsonrpc_failed', { method });
      if (cause?.message) {
        errorMsg += `: ${cause.message}`;
      }

      throw new NetworkError(
        errorMsg,
        error as Error,
        { method, params }
      );
    }
  }

  async testHandshake(): Promise<HandshakeResult> {
    const timer = new PerformanceTimer('testHandshake', 'MCPValidator');

    try {
      await this.transport.connect();
      this.logger.info(t('connected_to_transport'));

      const result = await this.sendJsonRPC('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: { roots: {}, sampling: {} },
        clientInfo: { name: 'mcp-verify', version: '1.0.0' },
      }) as Record<string, unknown> | undefined;

      const protocolVersion = (result as Record<string, unknown>)?.protocolVersion as string | undefined;
      const serverName = ((result as Record<string, unknown>)?.serverInfo as Record<string, unknown> | undefined)?.name as string | undefined;

      this.logger.info('Handshake successful', {
        metadata: {
          protocolVersion,
          serverName,
        },
      });

      timer.end({ metadata: { success: true } });

      return {
        success: true,
        protocolVersion: protocolVersion || '2024-11-05',
        serverName: serverName || 'Unknown',
      };
    } catch (error) {
      this.logger.error(t('handshake_failed_log'), error as Error);
      this.errorHandler.handle(error as Error, 'MCPValidator.testHandshake');
      timer.endWithError(error as Error);

      return {
        success: false,
        error: error instanceof Error ? error.message : t('connection_failed_msg'),
      };
    }
  }

  async discoverCapabilities(): Promise<DiscoveryResult> {
    const timer = new PerformanceTimer('discoverCapabilities', 'MCPValidator');
    const result: DiscoveryResult = {
      tools: [],
      resources: [],
      prompts: [],
    };

    try {
      // SECURITY FIX: Wrap discovery in timeout to prevent DoS
      const discoveryPromise = (async () => {
        // List tools
        const toolsResponse = await this.sendJsonRPC('tools/list', {}) as Record<string, unknown> | undefined;
        const tools = toolsResponse?.tools;
        if (tools && Array.isArray(tools)) {
          result.tools = tools as McpTool[];
          this.logger.info(`Discovered ${tools.length} tools`);
        }

        // List resources (Optional)
        try {
          const resourcesResponse = await this.sendJsonRPC('resources/list', {}) as Record<string, unknown> | undefined;
          const resources = resourcesResponse?.resources;
          if (resources && Array.isArray(resources)) {
            result.resources = resources as McpResource[];
            this.logger.info(`Discovered ${resources.length} resources`);
          }
        } catch (error) {
          if (error instanceof MethodNotFoundError) {
            this.logger.info('Server does not support resources/list (optional feature)');
          } else {
            this.logger.warn(`Failed to list resources: ${(error as Error).message}`);
          }
        }

        // List prompts (Optional)
        try {
          const promptsResponse = await this.sendJsonRPC('prompts/list', {}) as Record<string, unknown> | undefined;
          const prompts = promptsResponse?.prompts;
          if (prompts && Array.isArray(prompts)) {
            result.prompts = prompts as McpPrompt[];
            this.logger.info(`Discovered ${prompts.length} prompts`);
          }
        } catch (error) {
          if (error instanceof MethodNotFoundError) {
            this.logger.info('Server does not support prompts/list (optional feature)');
          } else {
            this.logger.warn(`Failed to list prompts: ${(error as Error).message}`);
          }
        }

        return result;
      })();

      // Race between discovery and timeout
      await Promise.race([
        discoveryPromise,
        this.createTimeout(this.DISCOVERY_TIMEOUT, 'Discovery')
      ]);

      // SECURITY FIX: Validate limits to prevent DoS
      this.validateDiscoveryLimits(result);

      timer.end({
        metadata: {
          toolsCount: result.tools.length,
          resourcesCount: result.resources.length,
          promptsCount: result.prompts.length,
        },
      });

      return result;
    } catch (error) {
      this.logger.error(t('discovery_failed'), error as Error);
      this.errorHandler.handle(error as Error, 'MCPValidator.discoverCapabilities');
      timer.endWithError(error as Error);

      // Re-throw DoS protection errors to fail fast
      if (error instanceof AppError || error instanceof TimeoutError) {
        throw error;
      }

      return result;
    }
  }

  async validateSchema(): Promise<ValidationResult> {
    const timer = new PerformanceTimer('validateSchema', 'MCPValidator');
    const result: ValidationResult = {
      schemaValid: true,
      toolsValid: 0,
      toolsInvalid: 0,
      resourcesValid: 0,
      resourcesInvalid: 0,
      promptsValid: 0,
      promptsInvalid: 0
    };

    try {
      const discovery = await this.discoverCapabilities();
      this.healthMonitor.recordValidation();

      // Track total validation time
      const validationStartTime = Date.now();

      // Validate tools
      if (discovery.tools) {
        const invalidTools: string[] = [];

        for (const tool of discovery.tools) {
          if (this.isValidToolSchema(tool)) {
            result.toolsValid++;
          } else {
            result.toolsInvalid++;
            invalidTools.push(tool.name);
          }
        }

        this.logger.debug('Tool validation complete', {
          metadata: {
            valid: result.toolsValid,
            invalid: result.toolsInvalid,
            invalidToolNames: invalidTools
          },
        });
      }

      // Validate resources
      if (discovery.resources) {
        const invalidResources: string[] = [];

        for (const resource of discovery.resources) {
          if (this.isValidResourceSchema(resource)) {
            result.resourcesValid++;
          } else {
            result.resourcesInvalid++;
            invalidResources.push(resource.name);
          }
        }

        this.logger.debug('Resource validation complete', {
          metadata: {
            valid: result.resourcesValid,
            invalid: result.resourcesInvalid,
            invalidResourceNames: invalidResources
          },
        });
      }

      // Validate prompts
      if (discovery.prompts) {
        const invalidPrompts: string[] = [];

        for (const prompt of discovery.prompts) {
          if (this.isValidPromptSchema(prompt)) {
            result.promptsValid++;
          } else {
            result.promptsInvalid++;
            invalidPrompts.push(prompt.name);
          }
        }

        this.logger.debug('Prompt validation complete', {
          metadata: {
            valid: result.promptsValid,
            invalid: result.promptsInvalid,
            invalidPromptNames: invalidPrompts
          },
        });
      }

      result.schemaValid =
        result.toolsInvalid === 0 &&
        result.resourcesInvalid === 0 &&
        result.promptsInvalid === 0;

      // Log schema validator cache stats
      const validationDuration = Date.now() - validationStartTime;
      const cacheStats = schemaValidator.getCacheStats();

      this.logger.info('Schema validation completed', {
        metadata: {
          schemaValid: result.schemaValid,
          totalValid: result.toolsValid + result.resourcesValid + result.promptsValid,
          totalInvalid: result.toolsInvalid + result.resourcesInvalid + result.promptsInvalid,
          validationDurationMs: validationDuration,
          cachedSchemas: cacheStats.size
        }
      });

      timer.end({ metadata: { schemaValid: result.schemaValid } });

      return result;
    } catch (error) {
      this.logger.error('Schema validation failed', error as Error);
      this.errorHandler.handle(error as Error, 'MCPValidator.validateSchema');
      timer.endWithError(error as Error);
      result.schemaValid = false;
      return result;
    }
  }

  private isValidToolSchema(tool: McpTool): boolean {
    if (!tool || !tool.name || typeof tool.name !== 'string') {
      this.logger.warn(`Tool missing name property`, { metadata: { tool } });
      return false;
    }

    if (!tool.inputSchema) {
      this.logger.warn(`Tool ${tool.name} missing inputSchema`, { metadata: { tool: tool.name } });
      return false;
    }

    // STRICT SCHEMA VALIDATION
    const validation = schemaValidator.validateSchema(tool.inputSchema, `tool:${tool.name}`, tool.name);

    // Track slow schemas (potential DoS indicators)
    if (validation.metrics.durationMs > 50) {
      this.logger.warn(`Slow schema validation detected for tool '${tool.name}'`, {
        metadata: {
          tool: tool.name,
          durationMs: validation.metrics.durationMs,
          timedOut: validation.metrics.timedOut,
          draftVersion: validation.metrics.draftVersion
        }
      });
    }

    if (!validation.isValid) {
      this.logger.error(`Invalid JSON Schema in tool '${tool.name}'`, undefined, {
        metadata: {
          tool: tool.name,
          errors: validation.errors,
          details: validation.details?.map(d => ({
            keyword: d.keyword,
            message: d.message,
            params: d.params
          })),
          durationMs: validation.metrics.durationMs
        }
      });
      return false;
    }

    // Check for sanitization warnings
    if (validation.sanitizationWarnings && validation.sanitizationWarnings.length > 0) {
      this.logger.warn(`Sanitization warnings in tool '${tool.name}'`, {
        metadata: {
          tool: tool.name,
          warnings: validation.sanitizationWarnings
        }
      });
    }

    return true;
  }

  private isValidResourceSchema(resource: McpResource): boolean {
    if (!resource || !resource.name || !resource.uri) {
      this.logger.warn(`Resource missing required fields`, {
        metadata: {
          resource: resource?.name || 'unknown',
          hasName: !!resource?.name,
          hasUri: !!resource?.uri
        }
      });
      return false;
    }

    if (typeof resource.name !== 'string' || typeof resource.uri !== 'string') {
      this.logger.warn(`Resource has invalid field types`, {
        metadata: {
          resource: resource.name,
          nameType: typeof resource.name,
          uriType: typeof resource.uri
        }
      });
      return false;
    }

    // Note: MCP Resources don't have schema property in current spec (2024-11-05)
    // If schema validation is needed in future, it should be added to McpResource interface

    return true;
  }

  private isValidPromptSchema(prompt: McpPrompt): boolean {
    if (!prompt || !prompt.name || typeof prompt.name !== 'string') {
      this.logger.warn(`Prompt missing or invalid name`, {
        metadata: {
          prompt: prompt?.name || 'unknown',
          hasName: !!prompt?.name,
          nameType: typeof prompt?.name
        }
      });
      return false;
    }

    // Validate arguments if present
    // Note: Prompt arguments don't have schema property in current spec (2024-11-05)
    // They only have name, description, and required fields
    if (prompt.arguments && Array.isArray(prompt.arguments)) {
      for (const arg of prompt.arguments) {
        // Validate argument structure (name is required)
        if (!arg.name || typeof arg.name !== 'string') {
          this.logger.warn(`Prompt argument missing name in '${prompt.name}'`, {
            metadata: {
              prompt: prompt.name,
              argument: arg
            }
          });
          continue;
        }

        // Future: If schema validation is added to prompt arguments, validate here
        // Currently, prompt arguments only support: name, description, required
      }
    }

    return true;
  }

  public getValidationStats(): {
    cacheStats: ReturnType<typeof schemaValidator.getCacheStats>;
    validatorConfig: ReturnType<typeof schemaValidator.getConfig>;
  } {
    return {
      cacheStats: schemaValidator.getCacheStats(),
      validatorConfig: schemaValidator.getConfig()
    };
  }

  async generateReport(data: {
    handshake: HandshakeResult;
    discovery: DiscoveryResult;
    validation: ValidationResult;
    fuzzing?: FuzzingReport;
  }): Promise<Report> {
    const duration = Date.now() - this.startTime;

    const mapTools = (tools: McpTool[]) => tools.map(t => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      status: this.isValidToolSchema(t) ? 'valid' as const : 'invalid' as const
    }));

    const mapResources = (resources: McpResource[]) => resources.map(r => ({
      name: r.name,
      uri: r.uri,
      mimeType: r.mimeType,
      status: this.isValidResourceSchema(r) ? 'valid' as const : 'invalid' as const
    }));

    const mapPrompts = (prompts: McpPrompt[]) => prompts.map(p => ({
      name: p.name,
      description: p.description,
      status: this.isValidPromptSchema(p) ? 'valid' as const : 'invalid' as const
    }));

    // Run Security Scan (if enabled in config)
    let security: SecurityReport;

    if (this.configManager.getSecurityConfig().enableSecurityScan) {
      this.logger.info('Running security scan');
      security = this.securityScanner.scan(data.discovery);
    } else {
      this.logger.info('Security scan disabled in configuration');
      security = {
        score: 100,
        level: t('risk_level_low'),
        findings: []
      };
    }

    // Log security findings
    if (security.findings && security.findings.length > 0) {
      security.findings.forEach((finding) => {
        if (finding.severity === 'critical' || finding.severity === 'high') {
          this.healthMonitor.recordSecurityFinding();
          Logger.getInstance().audit({
            eventType: AuditEventType.SECURITY_FINDING,
            severity: finding.severity,
            action: 'security_scan',
            result: 'failure',
            context: {
              metadata: {
                ruleCode: finding.ruleCode || 'unknown',
                message: finding.message,
                component: finding.component,
              },
            },
          });
        }
      });
    }

    // Run Quality Analysis
    this.logger.info('Running quality analysis');
    const quality = await this.semanticAnalyzer.analyze(data.discovery);

    // Run Protocol Compliance Test (Active)
    this.logger.info(t('running_protocol_tests'));
    const protocolCompliance = await this.protocolTester.test();

    // Determine overall status based on Policy-as-Code
    const securityConfig = this.config.security;
    const isSecurityPass = !securityConfig.enableSecurityScan || (
      security.score >= securityConfig.minScore &&
      (!securityConfig.failOnCritical || !security.findings.some(f => f.severity === 'critical')) &&
      (!securityConfig.failOnHigh || !security.findings.some(f => f.severity === 'high'))
    );

    const report: Report = {
      server_name: data.handshake.serverName || 'Unknown',
      url: 'transport',
      status: (data.handshake.success && data.validation.schemaValid && isSecurityPass) ? 'valid' : 'invalid',
      protocol_version: data.handshake.protocolVersion || '2024-11-05',
      security,
      quality,
      protocolCompliance,
      fuzzing: data.fuzzing,
      tools: {
        count: data.discovery.tools ? data.discovery.tools.length : 0,
        valid: data.validation.toolsValid,
        invalid: data.validation.toolsInvalid,
        items: data.discovery.tools ? mapTools(data.discovery.tools) : []
      },
      resources: {
        count: data.discovery.resources ? data.discovery.resources.length : 0,
        valid: data.validation.resourcesValid,
        invalid: data.validation.resourcesInvalid,
        items: data.discovery.resources ? mapResources(data.discovery.resources) : []
      },
      prompts: {
        count: data.discovery.prompts ? data.discovery.prompts.length : 0,
        valid: data.validation.promptsValid,
        invalid: data.validation.promptsInvalid,
        items: data.discovery.prompts ? mapPrompts(data.discovery.prompts) : []
      },
      timestamp: new Date().toISOString(),
      duration_ms: duration
    };

    // Badges
    report.badges = BadgeGenerator.generate(report);

    // Audit log report generation
    Logger.getInstance().audit({
      eventType: AuditEventType.VALIDATION_COMPLETED,
      severity: report.status === 'valid' ? 'low' : 'medium',
      action: 'generate_report',
      result: 'success',
      context: {
        metadata: {
          serverName: report.server_name,
          status: report.status,
          duration: duration,
          toolsCount: report.tools.count,
          securityFindings: security.findings?.length || 0,
        },
      },
    });

    this.logger.info('Report generated successfully', {
      metadata: {
        serverName: report.server_name,
        status: report.status,
        duration: duration,
      },
    });

    return report;
  }

  /**
   * Get health status and metrics
   */
  async getHealthStatus() {
    return await this.healthMonitor.runHealthChecks();
  }

  /**
   * Get performance metrics
   */
  getMetrics() {
    return this.healthMonitor.getMetrics();
  }

  /**
   * Export metrics in Prometheus format
   */
  exportPrometheusMetrics() {
    return this.healthMonitor.exportPrometheusMetrics();
  }

  cleanup() {
    this.logger.info('Cleaning up MCPValidator resources');

    try {
      this.transport.close();

      // Log final audit entry
      Logger.getInstance().audit({
        eventType: AuditEventType.VALIDATION_COMPLETED,
        severity: 'low',
        action: 'cleanup',
        result: 'success',
        context: {
          metadata: {
            uptime: this.healthMonitor.getUptime(),
            totalRequests: this.healthMonitor.getMetrics().totalRequests,
          },
        },
      });

      this.logger.info('Cleanup completed successfully');
    } catch (error) {
      this.logger.error('Error during cleanup', error as Error);
      this.errorHandler.handle(error as Error, 'MCPValidator.cleanup');
    }
  }
}
