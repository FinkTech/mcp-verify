/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Payload Generators
 *
 * Export all generator implementations and interfaces.
 */

// Interfaces
export * from './generator.interface';

// LLM/AI-specific Generators
export { PromptInjectionGenerator } from './prompt-injection.generator';

// Protocol Generators
export { JsonRpcGenerator } from './json-rpc.generator';
export { SchemaConfusionGenerator } from './schema-confusion.generator';

// Classic Security Generators (adapted from core payloads)
export {
  // Meta generator (all classic payloads)
  ClassicPayloadGenerator,
  ClassicPayloadConfig,
  ClassicPayloadCategory,
  // Specific generators
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
  FormatStringGenerator
} from './classic-payloads.generator';

// Advanced Attack Generators
export { JwtAttackGenerator, JwtAttackConfig } from './jwt-attack.generator';
export { PrototypePollutionGenerator, PrototypePollutionConfig } from './prototype-pollution.generator';
export { TimeBasedPayloadGenerator, TimeBasedConfig } from './time-based.generator';

// Raw Protocol Generator (transport layer testing)
export { RawProtocolGenerator, RawProtocolConfig } from './raw-protocol.generator';
