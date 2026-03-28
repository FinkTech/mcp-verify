/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-027: Training Data Poisoning via MCP (LLM03)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: Medium
 * Type: Static + Semantic
 *
 * Detects MCP tools that accept user-generated content for model training,
 * fine-tuning, or RAG indexing without validation.
 *
 * Detection:
 * Static:
 * - Tools with names like "train_", "finetune_", "index_", "embed_"
 * - Parameters accepting "training_data", "corpus", "documents"
 * - Missing validation schema for training inputs
 *
 * Semantic:
 * - LLM analyzes if tool purpose involves model training
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM03: Training Data Poisoning
 * - CWE-506: Embedded Malicious Code
 * - Backdoor Attacks on Language Models
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class TrainingDataPoisoningRule implements ISecurityRule {
  code = 'SEC-027';
  name = 'Training Data Poisoning via MCP';
  severity: 'medium' = 'medium';

  private readonly TRAINING_TOOL_PATTERNS = [
    /train/i, /finetune/i, /fine.*tune/i, /retrain/i,
    /index/i, /embed/i, /vectorize/i, /ingest/i,
    /update.*model/i, /improve.*model/i, /learn/i
  ];

  private readonly TRAINING_KEYWORDS = [
    'training_data', 'train_data', 'corpus', 'dataset',
    'documents', 'examples', 'samples', 'labels',
    'annotations', 'embeddings', 'vectors', 'feedback'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isTrainingTool = this.isTrainingRelatedTool(tool);

      if (isTrainingTool) {
        const hasValidation = this.hasInputValidation(tool);

        if (!hasValidation) {
          findings.push({
            severity: this.severity,
            message: t('sec_027_training_poisoning', {
              toolName: tool.name
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t('sec_027_recommendation'),
            references: [
              'OWASP LLM Top 10 2025 - LLM03: Training Data Poisoning',
              'CWE-506: Embedded Malicious Code',
              'Backdoor Attacks on Language Models (2023)'
            ]
          });
        }
      }
    }

    return findings;
  }

  private isTrainingRelatedTool(tool: McpTool): boolean {
    // Check tool name
    const nameMatches = this.TRAINING_TOOL_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.TRAINING_TOOL_PATTERNS.some(pattern =>
        pattern.test(descLower)
      );
      if (descMatches) return true;
    }

    // Check for training-related parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const hasTrainingParam = this.TRAINING_KEYWORDS.some(keyword =>
          propLower.includes(keyword)
        );
        if (hasTrainingParam) return true;
      }
    }

    return false;
  }

  private hasInputValidation(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    // Check if training data parameters have validation constraints
    for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
      const propLower = propName.toLowerCase();
      const isTrainingParam = this.TRAINING_KEYWORDS.some(keyword =>
        propLower.includes(keyword)
      );

      if (isTrainingParam) {
        const schema = propSchema as {
          pattern?: string;
          format?: string;
          enum?: unknown[];
          maxLength?: number;
          maxItems?: number;
          [key: string]: unknown;
        };

        // Check for validation constraints
        const hasPattern = Boolean(schema.pattern);
        const hasFormat = Boolean(schema.format);
        const hasEnum = Boolean(schema.enum && schema.enum.length > 0);
        const hasSizeLimit = Boolean(schema.maxLength || schema.maxItems);

        if (hasPattern || hasFormat || hasEnum || hasSizeLimit) {
          return true;
        }
      }
    }

    return false;
  }
}
