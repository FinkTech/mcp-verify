/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * @mcp-verify/fuzzer
 *
 * Advanced security fuzzer for MCP servers.
 *
 * Features:
 * - Prompt Injection attacks for LLM-based systems
 * - JSON-RPC protocol fuzzing
 * - Schema confusion and type attacks
 * - Classic security payloads (SQLi, XSS, Command Injection, etc.)
 * - Modular generator and detector architecture
 * - Concurrent execution with PromisePool
 * - Rich error handling with stack traces
 * - **Server Fingerprinting** for intelligent generator selection
 *
 * @example
 * ```typescript
 * import {
 *   FuzzerEngine,
 *   Fingerprinter,
 *   // Generators
 *   PromptInjectionGenerator,
 *   ClassicPayloadGenerator,
 *   PrototypePollutionGenerator,
 *   // Detectors
 *   PromptLeakDetector,
 *   JailbreakDetector,
 *   TimingDetector
 * } from '@mcp-verify/fuzzer';
 *
 * // Option 1: Auto-fingerprinting (recommended)
 * const engine = new FuzzerEngine({
 *   generators: [
 *     new PromptInjectionGenerator(),
 *     new ClassicPayloadGenerator(),
 *     new PrototypePollutionGenerator(),
 *   ],
 *   detectors: [
 *     new PromptLeakDetector(),
 *     new JailbreakDetector(),
 *     new TimingDetector()
 *   ],
 *   enableFingerprinting: true, // Auto-disable irrelevant generators
 *   onFingerprint: (fp) => console.log(`Detected: ${fp.summary}`),
 *   concurrency: 5
 * });
 *
 * const session = await engine.fuzz(target, 'my-tool');
 * // session.fingerprint contains detection results
 * // session.disabledGenerators lists what was skipped
 *
 * // Option 2: Manual fingerprinting
 * const fingerprinter = new Fingerprinter();
 * const fingerprint = await fingerprinter.fingerprint(target, 'tool');
 * console.log(fingerprint.language); // 'nodejs' | 'python' | 'rust' | ...
 * console.log(fingerprint.disabledGenerators); // ['PrototypePollutionGenerator']
 * ```
 */

// ==================== GENERATORS ====================
export {
  // Interfaces
  IPayloadGenerator,
  GeneratorConfig,
  GeneratedPayload,

  // LLM/AI-specific
  PromptInjectionGenerator,

  // Protocol
  JsonRpcGenerator,
  SchemaConfusionGenerator,

  // Classic Security (adapted from core)
  ClassicPayloadGenerator,
  ClassicPayloadConfig,
  ClassicPayloadCategory,
  SqlInjectionGenerator,
  XssGenerator,
  CommandInjectionGenerator,
  PathTraversalGenerator,
  SsrfGenerator,
  XxeGenerator,
  NoSqlInjectionGenerator,
  TemplateInjectionGenerator,
  BufferOverflowGenerator,
  LdapInjectionGenerator,
  FormatStringGenerator,

  // Advanced Attack Generators
  JwtAttackGenerator,
  JwtAttackConfig,
  PrototypePollutionGenerator,
  PrototypePollutionConfig,
  TimeBasedPayloadGenerator,
  TimeBasedConfig,

  // Raw Protocol (transport/parser robustness)
  RawProtocolGenerator,
  RawProtocolConfig
} from './generators';

// ==================== DETECTORS ====================
export {
  // Interfaces
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
  DetectionSeverity,
  DetectionConfidence,
  // Implementations
  PromptLeakDetector,
  PromptLeakConfig,
  JailbreakDetector,
  JailbreakConfig,
  ProtocolViolationDetector,
  ProtocolViolationConfig,
  PathTraversalDetector,
  WeakIdDetector,
  WeakIdConfig,
  InformationDisclosureDetector,
  InfoDisclosureConfig,
  TimingDetector,
  TimingConfig,
  ErrorDetector,
  ErrorDetectorConfig,
  XssDetector
} from './detectors';

// ==================== ENGINE ====================
export {
  FuzzerEngine,
  FuzzerEngineConfig,
  FuzzingSession,
  FuzzingProgress,
  FuzzingError,
  FuzzTarget,
  FeedbackStats,
  ResponseAnalysis,
  InterestLevel,
  InterestReason
} from './engine';

// ==================== FINGERPRINTING ====================
export {
  Fingerprinter,
  FingerprintConfig,
  ServerFingerprint,
  FingerprintEvidence,
  ServerLanguage,
  ServerFramework,
  DatabaseType
} from './fingerprint';

// ==================== UTILS ====================
export {
  sessionToFuzzingReport,
  sessionToSecurityFindings,
  sessionToReport,
  sessionToSummary,
  ReportMapperOptions,
  FuzzerSecurityFinding,
  FuzzingSummary
} from './utils';

// ==================== VERSION ====================
export const FUZZER_VERSION = '1.0.0';
