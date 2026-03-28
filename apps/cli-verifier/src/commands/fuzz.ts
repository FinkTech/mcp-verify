/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Fuzz Command
 *
 * Advanced security fuzzing for MCP servers.
 * Tests for prompt injection, protocol violations, and more.
 */

import ora from 'ora';
import chalk from 'chalk';
import { t, getCurrentLanguage, ReportingService, captureGitInfo } from '@mcp-verify/shared';
import { generateDisclaimer, generateMetadata, JsonRpcRequest, JsonRpcNotification, ProtocolComplianceReport } from '@mcp-verify/core';
import {
  FuzzerEngine,
  FuzzTarget,
  FuzzingSession,
  GeneratedPayload,
  DetectionResult,
  IPayloadGenerator,
  IVulnerabilityDetector,
  // LLM Generators
  PromptInjectionGenerator,
  // Protocol Generators
  JsonRpcGenerator,
  SchemaConfusionGenerator,
  RawProtocolGenerator,
  // Classic Security Generators
  ClassicPayloadGenerator,
  SqlInjectionGenerator,
  XssGenerator,
  CommandInjectionGenerator,
  PathTraversalGenerator,
  SsrfGenerator,
  XxeGenerator,
  NoSqlInjectionGenerator,
  TemplateInjectionGenerator,
  // Advanced Attack Generators
  JwtAttackGenerator,
  PrototypePollutionGenerator,
  TimeBasedPayloadGenerator,
  // Detectors
  PromptLeakDetector,
  JailbreakDetector,
  ProtocolViolationDetector,
  PathTraversalDetector,
  WeakIdDetector,
  InformationDisclosureDetector,
  TimingDetector,
  ErrorDetector,
  XssDetector,
  // Fingerprinting
  ServerFingerprint,
  // Report utilities
  sessionToReport,
  sessionToSummary
} from '@mcp-verify/fuzzer';
import { detectTransportType, createTransport } from '../utils/transport-factory';
import { configureLogging } from '../utils/logging-helper';
import { registerCleanup } from '../utils/cleanup-handlers';

interface FuzzOptions {
  transport?: 'http' | 'stdio';
  concurrency?: string;
  timeout?: string;
  tool?: string;
  param?: string;
  stopOnFirst?: boolean;
  verbose?: boolean;
  generators?: string;
  detectors?: string;
  output?: string;
  format?: 'json' | 'html' | 'sarif' | 'txt' | 'all';
  fingerprint?: boolean;
  header?: string[];
  rateLimit?: string; // Maximum requests per second (e.g., '10' for 10 req/s)
}

interface ToolSchema {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string }>;
    required?: string[];
  };
}

interface DiscoveryResult {
  paramName: string;
  paramType: string;
  autoDetected: boolean;
  toolFound: boolean;
  availableParams: string[];
}

interface ListToolsResponse {
  tools?: ToolSchema[];
  result?: {
    tools?: ToolSchema[];
  };
}

/**
 * Adapter that wraps MCP transport as a FuzzTarget
 */
export class McpFuzzTarget implements FuzzTarget {
  private transport: ReturnType<typeof createTransport> | null = null;
  private targetTool: string;
  private paramName: string;
  private manualParam: boolean;
  private timeout: number;
  private headers: Record<string, string>;
  private discoveryResult: DiscoveryResult | null = null;
  private toolSchema: Record<string, unknown> | null = null;

  constructor(
    private target: string,
    private transportType: 'http' | 'stdio',
    options: { tool?: string; param?: string; timeout?: number; headers?: Record<string, string> }
  ) {
    this.targetTool = options.tool || 'echo';
    this.paramName = options.param || 'input';
    this.manualParam = !!options.param;
    this.timeout = options.timeout || 5000;
    this.headers = options.headers || {};
  }

  async connect(): Promise<void> {
    this.transport = await createTransport(this.target, {
      transportType: this.transportType,
      timeout: this.timeout,
      headers: this.headers
    });
    await this.transport.connect();
  }

  /**
   * Discover the target parameter from the tool's schema
   */
  async discoverParam(): Promise<DiscoveryResult> {
    if (!this.transport) {
      throw new Error('Transport not connected');
    }

    // If user specified --param, use it but still gather info
    if (this.manualParam) {
      this.discoveryResult = {
        paramName: this.paramName,
        paramType: 'manual',
        autoDetected: false,
        toolFound: true,
        availableParams: []
      };
      return this.discoveryResult;
    }

    try {
      // Call tools/list to get available tools
      const response = await this.transport.send({
        method: 'tools/list',
        params: {}
      }) as ListToolsResponse;

      // console.log(`\n[DEBUG] Raw tools response: ${JSON.stringify(response)}`);

      // Handle both { tools: [] } and { result: { tools: [] } } patterns
      const toolsData = response?.tools || response?.result?.tools || [];
      const tools: ToolSchema[] = Array.isArray(toolsData) ? toolsData : [];

      // Find the target tool
      const tool = tools.find((t: ToolSchema) => t.name === this.targetTool);

      if (!tool) {
        // Tool not found, use default
        this.discoveryResult = {
          paramName: this.paramName,
          paramType: 'default',
          autoDetected: false,
          toolFound: false,
          availableParams: tools.map((t: ToolSchema) => t.name)
        };
        return this.discoveryResult;
      }

      // Store the tool schema for schema-aware fuzzing
      if (tool.inputSchema) {
        this.toolSchema = tool.inputSchema as Record<string, unknown>;
      }

      const properties = tool.inputSchema?.properties || {};
      const propEntries = Object.entries(properties);
      const availableParams = propEntries.map(([name]) => name);

      if (propEntries.length === 0) {
        // No parameters defined
        this.discoveryResult = {
          paramName: this.paramName,
          paramType: 'default',
          autoDetected: false,
          toolFound: true,
          availableParams: []
        };
        return this.discoveryResult;
      }

      // Priority 1: First string parameter
      const stringParam = propEntries.find(([, prop]) => prop.type === 'string');
      if (stringParam) {
        this.paramName = stringParam[0];
        this.discoveryResult = {
          paramName: this.paramName,
          paramType: 'string',
          autoDetected: true,
          toolFound: true,
          availableParams
        };
        return this.discoveryResult;
      }

      // Priority 2: First parameter of any type
      this.paramName = propEntries[0][0];
      this.discoveryResult = {
        paramName: this.paramName,
        paramType: propEntries[0][1].type || 'unknown',
        autoDetected: true,
        toolFound: true,
        availableParams
      };
      return this.discoveryResult;

    } catch (error) {
      // Discovery failed, use default
      console.log(`\n[DEBUG] Discovery failed: ${error instanceof Error ? error.message : String(error)}`);
      this.discoveryResult = {
        paramName: this.paramName,
        paramType: 'default',
        autoDetected: false,
        toolFound: false,
        availableParams: []
      };
      return this.discoveryResult;
    }
  }

  getDiscoveryResult(): DiscoveryResult | null {
    return this.discoveryResult;
  }

  getParamName(): string {
    return this.paramName;
  }

  getToolSchema(): Record<string, unknown> | null {
    return this.toolSchema;
  }

  async close(): Promise<void> {
    if (this.transport) {
      await this.transport.close();
      this.transport = null;
    }
  }

  async execute(payload: GeneratedPayload): Promise<{
    response: unknown;
    responseTimeMs: number;
    isError: boolean;
    error?: { code: number; message: string };
  }> {
    if (!this.transport) {
      throw new Error('Transport not connected');
    }

    const startTime = Date.now();

    try {
      // Build the request based on payload category
      let request: unknown;
      const isRawProtocol = payload.category === 'raw-protocol' ||
                            payload.category === 'json-rpc' ||
                            (payload.metadata as Record<string, unknown>)?.isRaw === true;

      if (isRawProtocol) {
        // Raw protocol payloads bypass the tools/call wrapper
        // They are sent directly to test transport/parser robustness
        const payloadValue = payload.value;

        if (typeof payloadValue === 'string') {
          // String payloads might be malformed JSON - try to parse
          // If parsing fails, that's expected for malformed JSON tests
          try {
            request = JSON.parse(payloadValue);
          } catch {
            // For truly malformed JSON, we need raw transport access
            // For now, wrap in a special marker that transport can detect
            request = {
              jsonrpc: '2.0',
              id: Date.now(),
              method: '__raw__',
              params: { __rawPayload__: payloadValue }
            };
          }
        } else {
          // Object payloads are sent directly (may be malformed JSON-RPC)
          request = payloadValue;
        }
      } else {
        // Regular payloads go into tool arguments
        request = {
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'tools/call',
          params: {
            name: this.targetTool,
            arguments: {
              [this.paramName]: payload.value
            }
          }
        };
      }

      // Create timeout promise
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Request timeout')), this.timeout);
      });

      // Send request with timeout
      const responsePromise = this.transport.send(request as JsonRpcRequest | JsonRpcNotification);
      const response = await Promise.race([responsePromise, timeoutPromise]);

      const responseTimeMs = Date.now() - startTime;

      // Check if response indicates an error
      const isJsonRpcError = !!(response && typeof response === 'object' && 'error' in response);

      return {
        response,
        responseTimeMs,
        isError: isJsonRpcError,
        error: isJsonRpcError ? (response as { error: { code: number; message: string } }).error : undefined
      };
    } catch (error) {
      const responseTimeMs = Date.now() - startTime;
      return {
        response: null,
        responseTimeMs,
        isError: true,
        error: {
          code: -1,
          message: error instanceof Error ? error.message : String(error)
        }
      };
    }
  }
}

/**
 * Format severity with color
 */
function formatSeverity(severity: string): string {
  switch (severity) {
    case 'critical': return chalk.bgRed.white.bold(` ${severity.toUpperCase()} `);
    case 'high': return chalk.red.bold(severity.toUpperCase());
    case 'medium': return chalk.yellow(severity.toUpperCase());
    case 'low': return chalk.blue(severity);
    default: return chalk.gray(severity);
  }
}

/**
 * Print vulnerability details
 */
function printVulnerability(detection: DetectionResult, index: number): void {
  console.log('');
  console.log(chalk.red(`  [${ index + 1}] ${detection.description}`));
  console.log(`      ${chalk.dim('Severity:')} ${formatSeverity(detection.severity)} | ${chalk.dim('Confidence:')} ${detection.confidence}`);
  console.log(`      ${chalk.dim('Detector:')} ${detection.detectorId}`);

  if (detection.cweId) {
    console.log(`      ${chalk.dim('CWE:')} ${detection.cweId}`);
  }
  if (detection.owaspCategory) {
    console.log(`      ${chalk.dim('OWASP:')} ${detection.owaspCategory}`);
  }
  if (detection.remediation) {
    console.log(`      ${chalk.dim('Fix:')} ${detection.remediation.substring(0, 100)}...`);
  }
}

/**
 * Print session summary
 */
function printSessionSummary(session: FuzzingSession): void {
  const duration = session.endedAt
    ? ((session.endedAt.getTime() - session.startedAt.getTime()) / 1000).toFixed(2)
    : '?';

  console.log('');
  console.log(chalk.bold('📊 ' + t('fuzz_session_summary') + ':'));
  console.log(chalk.gray('─'.repeat(50)));
  console.log(`  ${chalk.dim('Session ID:')} ${session.id}`);
  console.log(`  ${chalk.dim('Duration:')} ${duration}s`);
  console.log(`  ${chalk.dim('Payloads:')} ${session.payloadsExecuted}/${session.totalPayloads}`);

  // Feedback Loop Stats (Smart Fuzzing)
  if (session.feedbackStats) {
    const fb = session.feedbackStats;
    console.log('');
    console.log(chalk.bold.cyan('  Feedback Loop (Smart Fuzzer):'));
    console.log(`    ${chalk.dim('Interesting responses:')} ${fb.interestingResponsesFound}`);
    console.log(`    ${chalk.dim('Mutations injected:')}    ${fb.mutationsInjected}`);
    console.log(`    ${chalk.dim('Mutation rounds:')}       ${fb.mutationRoundsCompleted}`);
    
    if (fb.timingAnomaliesDetected > 0) {
      console.log(`    ${chalk.yellow('Timing anomalies:')}       ${fb.timingAnomaliesDetected}`);
    }
    if (fb.structuralDriftDetected > 0) {
      console.log(`    ${chalk.yellow('Structural drifts:')}      ${fb.structuralDriftDetected}`);
    }
    if (fb.serverCrashesDetected > 0) {
      console.log(`    ${chalk.red('Server crashes:')}         ${fb.serverCrashesDetected}`);
    }
  }

  // Vulnerabilities
  console.log('');
  if (session.vulnerabilities.length > 0) {
    console.log(`  ${chalk.dim('Vulnerabilities:')} ${chalk.red.bold(session.vulnerabilities.length)}`);

    // Count by severity
    const bySeverity: Record<string, number> = {};
    for (const v of session.vulnerabilities) {
      bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
    }

    const severityParts = Object.entries(bySeverity)
      .map(([sev, count]) => `${formatSeverity(sev)}: ${count}`)
      .join(' | ');
    console.log(`  ${chalk.dim('By Severity:')} ${severityParts}`);
  } else {
    console.log(`  ${chalk.dim('Vulnerabilities:')} ${chalk.green('0')}`);
  }

  // Errors
  if (session.errors.length > 0) {
    console.log(`  ${chalk.dim('Errors:')} ${chalk.yellow(session.errors.length)}`);
  }

  // Categories breakdown
  console.log('');
  console.log(chalk.dim('  Payloads by category:'));
  for (const [category, count] of Object.entries(session.payloadsByCategory)) {
    console.log(`    ${chalk.cyan(category)}: ${count}`);
  }

  if (session.aborted) {
    console.log('');
    console.log(chalk.yellow(`  ⚠️  Session aborted: ${session.abortReason}`));
  }

  console.log(chalk.gray('─'.repeat(50)));
}

/**
 * Format and display fingerprint results
 */
function printFingerprintResult(fingerprint: ServerFingerprint): void {
  console.log('');
  console.log(chalk.bold('🔍 ' + t('fingerprint_results') + ':'));
  console.log(chalk.gray('─'.repeat(50)));

  // Language
  const langConfidence = (fingerprint.languageConfidence * 100).toFixed(0);
  const langColor = fingerprint.languageConfidence >= 0.8 ? chalk.green :
                    fingerprint.languageConfidence >= 0.5 ? chalk.yellow : chalk.gray;
  console.log(`  ${chalk.dim('Language:')} ${langColor.bold(fingerprint.language.toUpperCase())} ${chalk.dim(`(${langConfidence}% confidence)`)}`);

  // Framework
  if (fingerprint.framework !== 'unknown') {
    const fwConfidence = (fingerprint.frameworkConfidence * 100).toFixed(0);
    console.log(`  ${chalk.dim('Framework:')} ${chalk.cyan(fingerprint.framework)} ${chalk.dim(`(${fwConfidence}%)`)}`);
  }

  // Database
  if (fingerprint.database !== 'unknown' && fingerprint.database !== 'none') {
    console.log(`  ${chalk.dim('Database:')} ${chalk.magenta(fingerprint.database)}`);
  }

  // Disabled generators
  if (fingerprint.disabledGenerators.length > 0) {
    console.log('');
    console.log(`  ${chalk.dim('Auto-disabled generators (irrelevant for this stack):')}`);
    for (const gen of fingerprint.disabledGenerators) {
      console.log(`    ${chalk.red('✗')} ${chalk.strikethrough(gen)}`);
    }
  }

  // Recommended generators (top 5)
  if (fingerprint.recommendedGenerators.length > 0) {
    console.log('');
    console.log(`  ${chalk.dim('Prioritized generators:')}`);
    for (const gen of fingerprint.recommendedGenerators.slice(0, 5)) {
      console.log(`    ${chalk.green('✓')} ${gen}`);
    }
    if (fingerprint.recommendedGenerators.length > 5) {
      console.log(`    ${chalk.gray(`... and ${fingerprint.recommendedGenerators.length - 5} more`)}`);
    }
  }

  // Duration
  console.log('');
  console.log(`  ${chalk.dim('Fingerprint time:')} ${fingerprint.durationMs}ms`);
  console.log(chalk.gray('─'.repeat(50)));
}

/**
 * Save reports to disk using centralized ReportingService
 */
async function saveReports(
  session: FuzzingSession,
  target: string,
  options: FuzzOptions
): Promise<void> {
  const toolName = options.tool || 'unknown';

  // Convert session to Report format
  const report = sessionToReport(session, {
    serverName: target.split('/').pop() || target,
    serverUrl: target,
    toolName
  });

  // Add disclaimer and metadata
  report.metadata = generateMetadata({
    llmUsed: false,
    modulesExecuted: ['fuzzing', 'security']
  });

  report.disclaimer = generateDisclaimer({
    language: getCurrentLanguage(),
    llmUsed: false
  });

  // Capture git info for SARIF versionControlProvenance
  const gitInfo = captureGitInfo();
  if (gitInfo) {
    report.gitInfo = gitInfo;
  }

  // Map format option to ReportingService formats
  const formatMap: Record<string, ('json' | 'html' | 'sarif' | 'txt')[]> = {
    'json': ['json'],
    'html': ['html'],
    'sarif': ['sarif'],
    'txt': ['txt'],
    'all': ['json', 'html', 'sarif', 'txt']
  };

  const formats = formatMap[options.format || 'json'] || ['json'];

  // Use centralized ReportingService
  const result = await ReportingService.saveReport({ kind: 'validation', data: report }, {
    outputDir: options.output || './reports',
    formats,
    language: getCurrentLanguage(),
    filenamePrefix: `fuzz-${toolName}`,
    organizeByFormat: true,
    includeRawSession: options.verbose,
    rawSession: session
  });

  // Print saved paths
  if (result.paths.json) {
    console.log(chalk.green(`\n📄 JSON report saved: ${result.paths.json}`));
  }
  if (result.paths.html) {
    console.log(chalk.green(`📊 HTML report saved: ${result.paths.html}`));
  }
  if (result.paths.markdown) {
    console.log(chalk.green(`📝 Markdown report saved: ${result.paths.markdown}`));
  }
  if (result.paths.txt) {
    console.log(chalk.green(`📄 Text report saved: ${result.paths.txt}`));
  }
  if (result.paths.sarif) {
    console.log(chalk.green(`🔒 SARIF report saved: ${result.paths.sarif}`));
  }
  if (result.paths.rawSession) {
    console.log(chalk.gray(`📋 Raw session saved: ${result.paths.rawSession}`));
  }

  // Report any errors
  for (const error of result.errors) {
    console.log(chalk.yellow(`⚠️  Could not generate ${error.format} report: ${error.message}`));
  }
}

/**
 * Main fuzz action
 */
export async function runFuzzAction(target: string, options: FuzzOptions): Promise<void> {
  // Check disclaimer before proceeding
  const { checkDisclaimer } = await import('../utils/disclaimer-manager.js');
  const accepted = await checkDisclaimer('fuzz');

  if (!accepted) {
    console.log(chalk.yellow(t('disclaimer_aborted')));
    return;
  }

  const spinner = ora(t('initializing_fuzzer')).start();

  // Configure logging
  configureLogging(Boolean(options.verbose));

  // Parse options
  const concurrency = parseInt(options.concurrency || '1', 10);
  const timeout = parseInt(options.timeout || '5000', 10);
  const transportType = options.transport || detectTransportType(target);

  // Select generators based on option
  const generatorNames = (options.generators || 'all').split(',').map(g => g.trim().toLowerCase());
  const generators: IPayloadGenerator[] = [];

  // Generator mapping
  const generatorMap: Record<string, () => IPayloadGenerator> = {
    // LLM/AI
    'prompt-injection': () => new PromptInjectionGenerator(),
    'prompt': () => new PromptInjectionGenerator(),
    // Protocol
    'json-rpc': () => new JsonRpcGenerator(),
    'jsonrpc': () => new JsonRpcGenerator(),
    'schema': () => new SchemaConfusionGenerator(),
    'schema-confusion': () => new SchemaConfusionGenerator(),
    // Raw Protocol (transport layer attacks)
    'raw': () => new RawProtocolGenerator(),
    'raw-protocol': () => new RawProtocolGenerator(),
    'malformed': () => new RawProtocolGenerator(),
    'batch': () => new RawProtocolGenerator({ maxBatchSize: 100 }),
    // Classic Security
    'classic': () => new ClassicPayloadGenerator(),
    'sqli': () => new SqlInjectionGenerator(),
    'sql': () => new SqlInjectionGenerator(),
    'xss': () => new XssGenerator(),
    'cmd': () => new CommandInjectionGenerator(),
    'command': () => new CommandInjectionGenerator(),
    'path': () => new PathTraversalGenerator(),
    'path-traversal': () => new PathTraversalGenerator(),
    'ssrf': () => new SsrfGenerator(),
    'xxe': () => new XxeGenerator(),
    'nosql': () => new NoSqlInjectionGenerator(),
    'object': () => new ClassicPayloadGenerator({ categories: ['objectInjection'] }),
    'pollution': () => new PrototypePollutionGenerator(),
    'proto': () => new PrototypePollutionGenerator(),
    'prototype': () => new PrototypePollutionGenerator(),
    'template': () => new TemplateInjectionGenerator(),
    'ssti': () => new TemplateInjectionGenerator(),
    // Advanced
    'jwt': () => new JwtAttackGenerator(),
    'auth': () => new JwtAttackGenerator(),
    'time': () => new TimeBasedPayloadGenerator(),
    'time-based': () => new TimeBasedPayloadGenerator(),
    'blind': () => new TimeBasedPayloadGenerator(),
  };

  // Handle 'all' - includes LLM, protocol, classic, and advanced
  // Note: 'raw-protocol' is NOT included in 'all' by default as it tests parser robustness
  // and may cause connection issues. Use --generators=all,raw to include it.
  if (generatorNames.includes('all')) {
    generators.push(new PromptInjectionGenerator());
    generators.push(new JsonRpcGenerator());
    generators.push(new SchemaConfusionGenerator());
    generators.push(new ClassicPayloadGenerator()); // All classic payloads
    generators.push(new JwtAttackGenerator());
    generators.push(new PrototypePollutionGenerator());
    generators.push(new TimeBasedPayloadGenerator());
    // Raw protocol is opt-in: use --generators=all,raw or --generators=raw
  } else {
    // Add specific generators
    for (const name of generatorNames) {
      const factory = generatorMap[name];
      if (factory) {
        generators.push(factory());
      }
    }
  }

  if (generators.length === 0) {
    spinner.fail(t('no_generators_selected'));
    console.log(chalk.yellow('Available generators:'));
    console.log(chalk.gray('  LLM/AI:     prompt-injection (prompt)'));
    console.log(chalk.gray('  Protocol:   json-rpc (jsonrpc), schema'));
    console.log(chalk.gray('  Classic:    classic (all), sqli, xss, cmd, path, ssrf, xxe, nosql, ssti'));
    console.log(chalk.gray('  Meta:       all (everything)'));
    return;
  }

  // Select detectors based on option
  const detectorNames = (options.detectors || 'all').split(',').map(d => d.trim().toLowerCase());
  const detectors: IVulnerabilityDetector[] = [];

  // Detector mapping
  const detectorMap: Record<string, () => IVulnerabilityDetector> = {
    'prompt-leak': () => new PromptLeakDetector(),
    'leak': () => new PromptLeakDetector(),
    'jailbreak': () => new JailbreakDetector(),
    'protocol': () => new ProtocolViolationDetector(),
    'protocol-violation': () => new ProtocolViolationDetector(),
    'path-traversal': () => new PathTraversalDetector(),
    'path': () => new PathTraversalDetector(),
    'weak-id': () => new WeakIdDetector(),
    'entropy': () => new WeakIdDetector(),
    'info-disclosure': () => new InformationDisclosureDetector(),
    'info': () => new InformationDisclosureDetector(),
    'disclosure': () => new InformationDisclosureDetector(),
    'timing': () => new TimingDetector(),
    'time': () => new TimingDetector(),
    'blind': () => new TimingDetector(),
    'error': () => new ErrorDetector(),
    'pattern': () => new ErrorDetector(),
    'xss': () => new XssDetector(),
  };

  if (detectorNames.includes('all')) {
    detectors.push(new PromptLeakDetector());
    detectors.push(new JailbreakDetector());
    detectors.push(new ProtocolViolationDetector());
    detectors.push(new PathTraversalDetector());
    detectors.push(new WeakIdDetector());
    detectors.push(new InformationDisclosureDetector());
    detectors.push(new TimingDetector());
    detectors.push(new ErrorDetector());
    detectors.push(new XssDetector());
  } else {
    for (const name of detectorNames) {
      const factory = detectorMap[name];
      if (factory) {
        detectors.push(factory());
      }
    }
  }

  if (detectors.length === 0) {
    spinner.warn(t('no_detectors_selected') || 'No detectors selected, using all');
    detectors.push(new PromptLeakDetector());
    detectors.push(new JailbreakDetector());
    detectors.push(new ProtocolViolationDetector());
    detectors.push(new PathTraversalDetector());
    detectors.push(new WeakIdDetector());
    detectors.push(new InformationDisclosureDetector());
    detectors.push(new TimingDetector());
    detectors.push(new ErrorDetector());
    detectors.push(new XssDetector());
  }

  // Parse headers from CLI (format: "Key: Value" or "Key=Value")
  const headers: Record<string, string> = {};
  if (options.header && options.header.length > 0) {
    for (const h of options.header) {
      // Support both "Key: Value" and "Key=Value" formats
      const colonIndex = h.indexOf(':');
      const equalsIndex = h.indexOf('=');

      let key: string, value: string;
      if (colonIndex > 0 && (equalsIndex === -1 || colonIndex < equalsIndex)) {
        key = h.substring(0, colonIndex).trim();
        value = h.substring(colonIndex + 1).trim();
      } else if (equalsIndex > 0) {
        key = h.substring(0, equalsIndex).trim();
        value = h.substring(equalsIndex + 1).trim();
      } else {
        console.log(chalk.yellow(`⚠️  Invalid header format: ${h} (use "Key: Value" or "Key=Value")`));
        continue;
      }

      headers[key] = value;
    }

    if (Object.keys(headers).length > 0) {
      spinner.info(chalk.cyan(`Using ${Object.keys(headers).length} custom header(s): ${Object.keys(headers).join(', ')}`));
      spinner.start();
    }
  }

  // Create target
  const fuzzTarget = new McpFuzzTarget(target, transportType as 'stdio' | 'http', {
    tool: options.tool,
    param: options.param,
    timeout,
    headers
  });

  // Register cleanup
  registerCleanup(async () => {
    await fuzzTarget.close();
  });

  let vulnerabilitiesFound = 0;
  let fingerprintResult: ServerFingerprint | undefined;

  // Calculate rate limit (convert requests/sec to delay in ms)
  let delayBetweenRequests: number | undefined;
  if (options.rateLimit) {
    const rps = parseInt(options.rateLimit, 10);
    if (rps > 0) {
      delayBetweenRequests = Math.floor(1000 / rps); // Convert req/s to ms delay
      console.log(chalk.cyan(`📊 ${t('rate_limit_active')}: ${rps} ${t('rate_limit_requests_per_sec')} (${delayBetweenRequests}ms delay)\n`));
    }
  }

  // Create engine
  const engine = new FuzzerEngine({
    generators,
    detectors,
    concurrency,
    timeout,
    delayBetweenRequests, // Add rate-limiting delay
    stopOnFirstVulnerability: options.stopOnFirst || false,
    // Fingerprinting configuration
    enableFingerprinting: options.fingerprint || false,
    onFingerprint: (fingerprint) => {
      fingerprintResult = fingerprint;
      spinner.stop();
      printFingerprintResult(fingerprint);

      // Show summary line
      const disabledCount = fingerprint.disabledGenerators.length;
      if (disabledCount > 0) {
        console.log(chalk.cyan(`\n🎯 Optimized: ${disabledCount} irrelevant generator(s) disabled based on ${fingerprint.language} detection\n`));
      }
      spinner.start();
    },
    onProgress: (progress) => {
      spinner.text = `${t('fuzzing_progress')}: ${progress.percentage}% (${progress.current}/${progress.total}) | ` +
        `${chalk.red('Vulns: ' + progress.vulnerabilitiesFound)} | ` +
        `${chalk.yellow('Errors: ' + progress.errorsEncountered)}`;
    },
    onVulnerability: (detection, payload) => {
      vulnerabilitiesFound++;
      if (options.verbose) {
        spinner.stop();
        console.log(chalk.red(`\n🚨 ${t('vulnerability_found')}:`));
        console.log(chalk.dim(`   Payload: ${String(payload.value).substring(0, 50)}...`));
        console.log(chalk.dim(`   Detector: ${detection.detectorId}`));
        spinner.start();
      }
    }
  });

  try {
    // Connect to target
    spinner.text = t('connecting_to_target');
    await fuzzTarget.connect();

    // Discover target parameter from schema
    spinner.text = t('discovering_schema') || 'Discovering tool schema...';
    const discovery = await fuzzTarget.discoverParam();

    // Show discovery feedback
    if (discovery.autoDetected) {
      spinner.info(chalk.cyan(`Auto-detected parameter: ${chalk.bold(discovery.paramName)} (${discovery.paramType})`));
      if (discovery.availableParams.length > 1) {
        console.log(chalk.gray(`  Available params: ${discovery.availableParams.join(', ')}`));
      }
      spinner.start();
    } else if (!discovery.toolFound) {
      spinner.warn(chalk.yellow(`Tool "${options.tool}" not found, using default param: ${discovery.paramName}`));
      spinner.start();
    }

    // Fingerprinting phase (if enabled)
    if (options.fingerprint) {
      spinner.text = t('fingerprinting_target') || 'Fingerprinting target to optimize payload selection...';
    }

    // Get tool schema for schema-aware fuzzing
    const toolSchema = fuzzTarget.getToolSchema();

    // Show pre-flight info
    const payloadCount = engine.generatePayloads(toolSchema || undefined).length;
    const fingerprintNote = options.fingerprint ? ' (fingerprint enabled)' : '';
    const schemaNote = toolSchema ? ' (schema-aware)' : '';
    spinner.text = `${t('starting_fuzz_session')}: ${payloadCount} payloads, param=${fuzzTarget.getParamName()}, concurrency=${concurrency}${fingerprintNote}${schemaNote}`;

    // Run fuzzing (includes fingerprinting if enabled, schema-aware if schema available)
    let session: FuzzingSession;
    try {
      session = await engine.fuzz(fuzzTarget, options.tool || 'unknown', toolSchema || undefined);
    } catch (error) {
      // PANIC STOP: API quota exceeded (429 error detected)
      if (error instanceof Error && error.message === 'PANIC_STOP_429') {
        spinner.stop();
        console.log('');
        console.log(chalk.red.bold(`🚨 ${t('fuzz_panic_stop')}: ${t('quota_stop_title')}`));
        console.log('');
        console.log(chalk.yellow(t('quota_stop_msg')));
        console.log('');
        console.log(chalk.cyan(t('quota_stop_recommendation')));
        console.log('');

        // Get partial session stats before exit
        const partialSession = engine.getSessionStats();
        if (partialSession) {
          console.log(chalk.dim(`Payloads tested before stop: ${partialSession.totalPayloads}`));
          console.log(chalk.dim(`Vulnerabilities found: ${partialSession.vulnerabilities.length}`));
        }

        await fuzzTarget.close();
        return;
      }
      // Re-throw other errors
      throw error;
    }

    // Disconnect
    await fuzzTarget.close();

    // Results
    if (session.vulnerabilities.length > 0) {
      spinner.fail(chalk.red(`${t('fuzz_complete_vulns_found')}: ${session.vulnerabilities.length}`));

      console.log('');
      console.log(chalk.red.bold('🚨 ' + t('vulnerabilities_detected') + ':'));

      session.vulnerabilities.forEach((v, i) => printVulnerability(v, i));
    } else {
      spinner.succeed(chalk.green(t('fuzz_complete_no_vulns')));
    }

    // Print summary
    printSessionSummary(session);

    // Errors detail (if verbose)
    if (options.verbose && session.errors.length > 0) {
      console.log('');
      console.log(chalk.yellow.bold('⚠️  ' + t('errors_during_fuzzing') + ':'));
      session.errors.slice(0, 5).forEach((err, i) => {
        console.log(chalk.yellow(`  [${i + 1}] ${err.message}`));
        if (err.stack) {
          console.log(chalk.gray(`      ${err.stack.split('\n')[1]?.trim()}`));
        }
      });
      if (session.errors.length > 5) {
        console.log(chalk.gray(`  ... and ${session.errors.length - 5} more`));
      }
    }

    // Save reports (always, defaulting to ./reports)
    await saveReports(session, target, options);

    // Exit code based on vulnerabilities
    if (session.vulnerabilities.length > 0) {
      const hasCriticalFindings = session.vulnerabilities.some(v => v.severity === 'critical');
      if (hasCriticalFindings) {
        process.exitCode = 2; // Critical vulnerabilities
      } else {
        process.exitCode = 1; // Non-critical vulnerabilities
      }
    }

  } catch (error) {
    await fuzzTarget.close();
    spinner.fail(t('fuzz_failed'));
    console.log('');
    console.error(chalk.red.bold('❌ ' + t('fuzz_error') + ':'));
    console.error(chalk.red(error instanceof Error ? error.message : String(error)));

    if (error instanceof Error && error.stack && options.verbose) {
      console.log(chalk.gray('\nStack trace:'));
      console.log(chalk.gray(error.stack));
    }

    console.log('');
    console.log(chalk.yellow.bold('💡 ' + t('suggestions') + ':'));
    console.log(chalk.gray('• ') + t('check_server_running'));
    console.log(chalk.gray('• ') + t('try_doctor_command') + ': mcp-verify doctor ' + target);
    console.log(chalk.gray('• ') + t('reduce_concurrency') + ': --concurrency 1');
    console.log('');
  }
}
