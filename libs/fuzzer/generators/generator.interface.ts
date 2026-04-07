/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Generator Interface
 *
 * Base interface for all payload generators.
 * Generators create attack payloads for specific vulnerability categories.
 */

export interface GeneratorConfig {
  /** Maximum number of payloads to generate */
  maxPayloads?: number;
  /** Minimum severity level to include */
  minSeverity?: "low" | "medium" | "high" | "critical";
  /** Enable mutations on generated payloads */
  enableMutations?: boolean;
  /** Custom seed for reproducible generation */
  seed?: string;
}

export interface GeneratedPayload {
  /** The actual payload value */
  value: string | Record<string, unknown>;
  /** Attack category (e.g., 'prompt-injection', 'json-rpc', 'schema-confusion') */
  category: string;
  /** Specific attack type within category */
  type: string;
  /** Severity of the attack */
  severity: "low" | "medium" | "high" | "critical";
  /** Human-readable description */
  description: string;
  /** The parameter to target for injection */
  targetParameter?: string;
  /** Expected vulnerable behavior if attack succeeds */
  expectedVulnerableBehavior?: string;
  /** Tags for filtering */
  tags?: string[];
  /** Metadata for analysis */
  metadata?: Record<string, unknown>;
}

export interface IPayloadGenerator {
  /** Unique identifier for this generator */
  readonly id: string;
  /** Human-readable name */
  readonly name: string;
  /** Attack category this generator targets */
  readonly category?: string;
  /** Description of what this generator does */
  readonly description: string;

  /**
   * Generate payloads based on configuration
   * @param config Generator configuration
   * @returns Array of generated payloads
   */
  generate(config?: GeneratorConfig): GeneratedPayload[];

  /**
   * Generate payloads for a specific tool schema
   * @param toolSchema JSON Schema of the tool's input
   * @param config Generator configuration
   * @returns Array of payloads tailored to the schema
   */
  generateForSchema?(
    toolSchema: Record<string, unknown>,
    config?: GeneratorConfig,
  ): GeneratedPayload[];
}
