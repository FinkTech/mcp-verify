/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * suggestSecureSchema - Shield Pattern for Automatic Schema Hardening
 *
 * Analyzes MCP tool input schemas and suggests security-hardened versions with:
 * - String length constraints (maxLength, pattern)
 * - Numeric bounds (minimum, maximum)
 * - Array size limits (maxItems, minItems)
 * - Enum constraints for finite sets
 * - Type strictness (additionalProperties: false)
 * - Required field enforcement
 *
 * Use case: "This tool schema is too permissive, how can I harden it?"
 */

import {
  MCPValidator,
  createScopedLogger,
  StdioTransport,
  translations,
  Language
} from '@mcp-verify/core';
import type { McpTool } from '@mcp-verify/core/domain/shared/common.types';
import { formatForLLM } from '../utils/llm-formatter.js';

const logger = createScopedLogger('suggestSecureSchemaTool');
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || 'en';
const t = translations[lang];

interface SuggestSecureSchemaArgs {
  command?: string;
  args?: string[];
  toolName?: string;
  toolDefinition?: McpTool;
  strictness?: 'minimal' | 'balanced' | 'maximum';
}

interface SuggestSecureSchemaResult {
  content: Array<{
    type: 'text';
    text: string;
  }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/**
 * Security constraints by strictness level
 */
const STRICTNESS_LEVELS = {
  minimal: {
    maxStringLength: 10 * 1024 * 1024,  // 10MB
    maxArrayItems: 10000,
    requirePatterns: false,
    requireEnums: false,
    blockAdditionalProperties: false
  },
  balanced: {
    maxStringLength: 1024 * 1024,  // 1MB
    maxArrayItems: 1000,
    requirePatterns: true,  // For sensitive fields
    requireEnums: true,     // For known sets
    blockAdditionalProperties: true
  },
  maximum: {
    maxStringLength: 65536,  // 64KB
    maxArrayItems: 100,
    requirePatterns: true,
    requireEnums: true,
    blockAdditionalProperties: true
  }
};

/**
 * Execute schema hardening analysis
 */
export async function suggestSecureSchemaTool(
  args: unknown
): Promise<SuggestSecureSchemaResult> {
  const {
    command,
    args: serverArgs = [],
    toolName,
    toolDefinition,
    strictness = 'balanced'
  } = args as SuggestSecureSchemaArgs;

  logger.info('Starting suggestSecureSchema', {
    metadata: {
      command,
      toolName,
      hasToolDefinition: !!toolDefinition,
      strictness
    }
  });

  try {
    let targetTool: McpTool;

    // Case 1: Tool definition provided directly
    if (toolDefinition) {
      targetTool = toolDefinition;
      logger.info(`Analyzing provided tool definition: ${toolDefinition.name}`);
    }
    // Case 2: Fetch tool from server
    else if (command && toolName) {
      logger.info('Fetching tool from server', { command, toolName });

      const transport = StdioTransport.create(command, serverArgs);
      const validator = new MCPValidator(transport);

      // Test handshake
      const handshake = await validator.testHandshake();
      if (!handshake.success) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                status: 'error',
                error: handshake.error || t.mcp_error_handshake_failed,
                message: t.mcp_error_failed_to_connect
              }, null, 2)
            }
          ],
          isError: true
        };
      }

      // Discover capabilities
      const discovery = await validator.discoverCapabilities();
      const foundTool = discovery.tools?.find(tool => tool.name === toolName);

      if (!foundTool) {
        validator.cleanup();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                status: 'error',
                error: `Tool "${toolName}" not found`,
                message: `Available tools: ${discovery.tools?.map(t => t.name).join(', ') || 'none'}`,
                availableTools: discovery.tools?.map(t => t.name) || []
              }, null, 2)
            }
          ],
          isError: true
        };
      }

      targetTool = foundTool;
      validator.cleanup();
    }
    // Case 3: Missing required arguments
    else {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'error',
              error: 'Missing required arguments',
              message: 'Provide either: (1) toolDefinition, or (2) command + toolName',
              usage: {
                option1: 'suggestSecureSchema({ toolDefinition: {...} })',
                option2: 'suggestSecureSchema({ command: "node server.js", toolName: "my_tool" })'
              }
            }, null, 2)
          }
        ],
        isError: true
      };
    }

    // Analyze and harden schema
    const originalSchema = targetTool.inputSchema;
    if (!originalSchema || !originalSchema.properties) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'no_schema',
              message: `Tool "${targetTool.name}" has no input schema to harden`,
              recommendation: 'This tool accepts no parameters or has no schema defined'
            }, null, 2)
          }
        ]
      };
    }

    const hardeningResult = hardenSchema(
      originalSchema,
      targetTool.name,
      strictness
    );

    // Build response
    const response = {
      status: 'completed',
      tool: targetTool.name,
      strictness_level: strictness,

      llm_summary: hardeningResult.changes.length > 0
        ? `🛡️  Schema hardening complete: Applied ${hardeningResult.changes.length} security improvements to "${targetTool.name}". ` +
          `${hardeningResult.criticalChanges} CRITICAL, ${hardeningResult.highChanges} HIGH priority changes. ` +
          `Suggested schema blocks ${hardeningResult.attackVectorsMitigated.length} attack vector(s).`
        : `✅ Schema for "${targetTool.name}" is already well-constrained. ` +
          `No significant hardening needed for ${strictness} strictness level.`,

      original_schema: originalSchema,
      hardened_schema: hardeningResult.hardenedSchema,

      improvements: {
        total_changes: hardeningResult.changes.length,
        critical_changes: hardeningResult.criticalChanges,
        high_changes: hardeningResult.highChanges,
        medium_changes: hardeningResult.mediumChanges,
        attack_vectors_mitigated: hardeningResult.attackVectorsMitigated
      },

      changes: hardeningResult.changes.map(change => ({
        parameter: change.parameter,
        priority: change.priority,
        category: change.category,
        before: change.before,
        after: change.after,
        rationale: change.rationale,
        attack_mitigated: change.attackMitigated
      })),

      implementation_guide: {
        schema_diff: hardeningResult.changes.map(c =>
          `${c.parameter}: ${c.before} → ${c.after}`
        ),
        code_example: generateCodeExample(targetTool.name, hardeningResult.hardenedSchema),
        validation_example: generateValidationExample(targetTool.name)
      },

      next_steps: hardeningResult.changes.length > 0 ? [
        `Apply ${hardeningResult.criticalChanges + hardeningResult.highChanges} critical/high priority changes first`,
        `Update tool schema in your MCP server implementation`,
        `Re-validate server: validateServer({ command: "${command || 'N/A'}" })`,
        `Test with edge cases to ensure constraints work as expected`,
        hardeningResult.attackVectorsMitigated.length > 0
          ? `Mitigating: ${hardeningResult.attackVectorsMitigated.join(', ')}`
          : 'Consider fuzzing to verify hardening: fuzzTool({...})'
      ] : [
        `✅ Schema is already secure for ${strictness} strictness`,
        `Consider ${strictness === 'balanced' ? 'maximum' : 'balanced'} strictness for additional hardening`,
        `Validate implementation matches schema: validateServer({...})`
      ]
    };

    logger.info('Schema hardening completed', {
      metadata: {
        toolName: targetTool.name,
        changesApplied: hardeningResult.changes.length,
        strictness
      }
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response, null, 2)
        }
      ],
      _meta: {
        toolName: targetTool.name,
        changesCount: hardeningResult.changes.length,
        strictness
      }
    };
  } catch (error) {
    logger.error('suggestSecureSchema failed', error as Error);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: 'error',
            error: (error as Error).message,
            message: 'Schema analysis failed',
            stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}

/**
 * Analyze schema and suggest hardened version
 */
function hardenSchema(
  schema: Record<string, unknown>,
  toolName: string,
  strictness: 'minimal' | 'balanced' | 'maximum'
): {
  hardenedSchema: Record<string, unknown>;
  changes: SchemaChange[];
  criticalChanges: number;
  highChanges: number;
  mediumChanges: number;
  attackVectorsMitigated: string[];
} {
  const config = STRICTNESS_LEVELS[strictness];
  const changes: SchemaChange[] = [];
  const attackVectors = new Set<string>();

  // Deep clone schema
  const hardenedSchema = JSON.parse(JSON.stringify(schema));
  const properties = hardenedSchema.properties as Record<string, Record<string, unknown>>;

  if (!properties) {
    return {
      hardenedSchema,
      changes: [],
      criticalChanges: 0,
      highChanges: 0,
      mediumChanges: 0,
      attackVectorsMitigated: []
    };
  }

  // Analyze each parameter
  for (const [paramName, paramSchema] of Object.entries(properties)) {
    const type = paramSchema.type as string;

    // String constraints
    if (type === 'string') {
      // Add maxLength if missing
      if (!paramSchema.maxLength) {
        paramSchema.maxLength = config.maxStringLength;
        changes.push({
          parameter: paramName,
          priority: 'critical',
          category: 'DoS Prevention',
          before: 'No length limit',
          after: `maxLength: ${config.maxStringLength}`,
          rationale: 'Prevents memory exhaustion attacks via unbounded string inputs',
          attackMitigated: 'DoS via large strings'
        });
        attackVectors.add('DoS via unbounded input');
      }

      // Suggest pattern for sensitive fields
      if (config.requirePatterns && isSensitiveField(paramName) && !paramSchema.pattern && !paramSchema.enum) {
        const suggestedPattern = suggestPattern(paramName);
        if (suggestedPattern) {
          paramSchema.pattern = suggestedPattern.pattern;
          changes.push({
            parameter: paramName,
            priority: 'high',
            category: 'Input Validation',
            before: 'No format validation',
            after: `pattern: ${suggestedPattern.pattern}`,
            rationale: suggestedPattern.rationale,
            attackMitigated: 'Injection via malformed input'
          });
          attackVectors.add('Injection attacks');
        }
      }
    }

    // Number constraints
    if (type === 'number' || type === 'integer') {
      if (paramSchema.minimum === undefined && paramSchema.maximum === undefined) {
        // Suggest reasonable bounds
        paramSchema.minimum = 0;
        paramSchema.maximum = type === 'integer' ? 2147483647 : Number.MAX_SAFE_INTEGER;
        changes.push({
          parameter: paramName,
          priority: 'medium',
          category: 'Bounds Checking',
          before: 'No numeric bounds',
          after: `minimum: ${paramSchema.minimum}, maximum: ${paramSchema.maximum}`,
          rationale: 'Prevents integer overflow/underflow and unexpected behavior',
          attackMitigated: 'Integer overflow exploitation'
        });
        attackVectors.add('Integer overflow');
      }
    }

    // Array constraints
    if (type === 'array') {
      if (!paramSchema.maxItems) {
        paramSchema.maxItems = config.maxArrayItems;
        changes.push({
          parameter: paramName,
          priority: 'critical',
          category: 'DoS Prevention',
          before: 'No array size limit',
          after: `maxItems: ${config.maxArrayItems}`,
          rationale: 'Prevents memory exhaustion via unbounded arrays',
          attackMitigated: 'DoS via large arrays'
        });
        attackVectors.add('DoS via unbounded arrays');
      }
    }

    // Object constraints
    if (type === 'object') {
      if (config.blockAdditionalProperties && paramSchema.additionalProperties !== false) {
        paramSchema.additionalProperties = false;
        changes.push({
          parameter: paramName,
          priority: 'high',
          category: 'Type Safety',
          before: 'additionalProperties: true (implicit)',
          after: 'additionalProperties: false',
          rationale: 'Prevents prototype pollution and unexpected property injection',
          attackMitigated: 'Prototype pollution'
        });
        attackVectors.add('Prototype pollution');
      }
    }

    // Enum suggestions
    if (config.requireEnums && isFiniteSet(paramName, paramSchema) && !paramSchema.enum) {
      const suggestedEnum = suggestEnum(paramName);
      if (suggestedEnum) {
        paramSchema.enum = suggestedEnum.values;
        changes.push({
          parameter: paramName,
          priority: 'medium',
          category: 'Input Validation',
          before: 'Accepts any value',
          after: `enum: [${suggestedEnum.values.join(', ')}]`,
          rationale: suggestedEnum.rationale,
          attackMitigated: 'Unexpected input exploitation'
        });
      }
    }
  }

  // Enforce required fields
  const currentRequired = (hardenedSchema.required as string[]) || [];
  const criticalParams = Object.keys(properties).filter(isCriticalParameter);
  const missingRequired = criticalParams.filter(p => !currentRequired.includes(p));

  if (missingRequired.length > 0) {
    hardenedSchema.required = [...currentRequired, ...missingRequired];
    changes.push({
      parameter: missingRequired.join(', '),
      priority: 'high',
      category: 'Required Fields',
      before: `Optional: ${missingRequired.join(', ')}`,
      after: `Required: ${missingRequired.join(', ')}`,
      rationale: 'Critical parameters should be required to prevent undefined behavior',
      attackMitigated: 'Logic bugs from missing inputs'
    });
  }

  // Block additional properties at schema root
  if (config.blockAdditionalProperties && hardenedSchema.additionalProperties !== false) {
    hardenedSchema.additionalProperties = false;
    changes.push({
      parameter: '<root>',
      priority: 'high',
      category: 'Type Safety',
      before: 'additionalProperties: true (implicit)',
      after: 'additionalProperties: false',
      rationale: 'Block unexpected top-level properties',
      attackMitigated: 'Parameter injection'
    });
  }

  // Count by priority
  const criticalChanges = changes.filter(c => c.priority === 'critical').length;
  const highChanges = changes.filter(c => c.priority === 'high').length;
  const mediumChanges = changes.filter(c => c.priority === 'medium').length;

  return {
    hardenedSchema,
    changes,
    criticalChanges,
    highChanges,
    mediumChanges,
    attackVectorsMitigated: Array.from(attackVectors)
  };
}

interface SchemaChange {
  parameter: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  before: string;
  after: string;
  rationale: string;
  attackMitigated: string;
}

/**
 * Check if parameter is sensitive (needs pattern validation)
 */
function isSensitiveField(paramName: string): boolean {
  const sensitivePatterns = [
    'path', 'file', 'dir', 'folder',
    'url', 'uri', 'link', 'href',
    'email', 'username', 'user',
    'command', 'cmd', 'exec',
    'query', 'sql', 'search'
  ];
  const lower = paramName.toLowerCase();
  return sensitivePatterns.some(pattern => lower.includes(pattern));
}

/**
 * Suggest regex pattern for parameter
 */
function suggestPattern(paramName: string): { pattern: string; rationale: string } | null {
  const lower = paramName.toLowerCase();

  if (lower.includes('path') || lower.includes('file') || lower.includes('dir')) {
    return {
      pattern: '^[a-zA-Z0-9._/-]+$',
      rationale: 'Restricts file paths to alphanumeric, dots, slashes (blocks traversal patterns like ../)'
    };
  }

  if (lower.includes('url') || lower.includes('uri')) {
    return {
      pattern: '^https://[a-zA-Z0-9.-]+(/[a-zA-Z0-9._~:/?#\\[\\]@!$&\'()*+,;=-]*)?$',
      rationale: 'Enforces HTTPS URLs with safe characters (blocks SSRF via file://, javascript:, etc.)'
    };
  }

  if (lower.includes('email')) {
    return {
      pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
      rationale: 'Standard email format validation'
    };
  }

  if (lower.includes('username') || lower.includes('user')) {
    return {
      pattern: '^[a-zA-Z0-9_-]{3,32}$',
      rationale: 'Alphanumeric usernames with 3-32 character limit'
    };
  }

  return null;
}

/**
 * Check if parameter represents a finite set (good enum candidate)
 */
function isFiniteSet(paramName: string, schema: Record<string, unknown>): boolean {
  const lower = paramName.toLowerCase();
  const finiteSetPatterns = [
    'type', 'kind', 'mode', 'status', 'state',
    'level', 'priority', 'severity',
    'format', 'encoding', 'method'
  ];
  return finiteSetPatterns.some(pattern => lower.includes(pattern));
}

/**
 * Suggest enum values for parameter
 */
function suggestEnum(paramName: string): { values: string[]; rationale: string } | null {
  const lower = paramName.toLowerCase();

  if (lower.includes('type') || lower.includes('kind')) {
    return {
      values: ['type1', 'type2', 'type3'],
      rationale: 'Replace with actual valid types for your use case'
    };
  }

  if (lower.includes('mode')) {
    return {
      values: ['read', 'write', 'readwrite'],
      rationale: 'Restricts to known operation modes'
    };
  }

  if (lower.includes('level') || lower.includes('priority')) {
    return {
      values: ['low', 'medium', 'high', 'critical'],
      rationale: 'Standard priority/level values'
    };
  }

  if (lower.includes('format')) {
    return {
      values: ['json', 'xml', 'yaml', 'csv'],
      rationale: 'Common data format types'
    };
  }

  return null;
}

/**
 * Check if parameter is critical (should be required)
 */
function isCriticalParameter(paramName: string): boolean {
  const criticalPatterns = [
    'id', 'key', 'name', 'type',
    'action', 'operation', 'method',
    'target', 'destination', 'source'
  ];
  const lower = paramName.toLowerCase();
  return criticalPatterns.some(pattern => lower === pattern || lower.endsWith(pattern));
}

/**
 * Generate code example for hardened schema
 */
function generateCodeExample(toolName: string, schema: Record<string, unknown>): string {
  return `// TypeScript example for hardened ${toolName} tool

const toolDefinition = {
  name: '${toolName}',
  description: 'Tool description here',
  inputSchema: ${JSON.stringify(schema, null, 2)}
};

// Register with your MCP server
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === '${toolName}') {
    // Input automatically validated against hardened schema
    const params = request.params.arguments;
    // ... tool implementation
  }
});`;
}

/**
 * Generate validation example
 */
function generateValidationExample(toolName: string): string {
  return `// Example: Validate inputs before execution

import Ajv from 'ajv';
const ajv = new Ajv();

const validate = ajv.compile(hardenedSchema);
const isValid = validate(userInput);

if (!isValid) {
  throw new Error(\`Invalid input for ${toolName}: \${ajv.errorsText(validate.errors)}\`);
}

// Safe to proceed with validated input
executeTool(userInput);`;
}
