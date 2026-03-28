/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * MCP Verify Server
 *
 * Exposes mcp-verify validation capabilities as MCP tools that AI agents can call.
 * This is the market differentiator - first tool that allows agents to validate MCP servers.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';

import { createScopedLogger, translations, Language } from '@mcp-verify/core';
import { validateServerTool } from './tools/validate-server.js';
import { scanSecurityTool } from './tools/scan-security.js';
import { analyzeQualityTool } from './tools/analyze-quality.js';
import { generateReportTool } from './tools/generate-report.js';
import { listInstalledServersTool } from './tools/list-installed-servers.js';
import { selfAuditTool } from './tools/self-audit.js';
import { compareServersTool } from './tools/compare-servers.js';
import { fuzzToolTool } from './tools/fuzz-tool.js';
import { inspectToolSemanticsTool } from './tools/inspect-semantics.js';
import { suggestSecureSchemaTool } from './tools/suggest-secure-schema.js';

const logger = createScopedLogger('MCPVerifyServer');

// MCP Server uses English by default (can be configured via MCP_VERIFY_LANG env var)
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || 'en';
const t = translations[lang];

/**
 * Available tools exposed by mcp-verify server
 */
const TOOLS: Tool[] = [
  {
    name: 'validateServer',
    description: t.mcp_tool_validate_server_desc,
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: t.mcp_param_command_desc
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: t.mcp_param_args_desc
        },
        configPath: {
          type: 'string',
          description: t.mcp_param_config_path_desc
        }
      },
      required: ['command']
    }
  },
  {
    name: 'scanSecurity',
    description: t.mcp_tool_scan_security_desc,
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: t.mcp_param_command_desc_short
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: t.mcp_param_args_desc
        },
        rules: {
          type: 'array',
          items: { type: 'string' },
          description: t.mcp_param_rules_desc
        }
      },
      required: ['command']
    }
  },
  {
    name: 'analyzeQuality',
    description: t.mcp_tool_analyze_quality_desc,
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: t.mcp_param_command_desc_short
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: t.mcp_param_args_desc
        }
      },
      required: ['command']
    }
  },
  {
    name: 'generateReport',
    description: t.mcp_tool_generate_report_desc,
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: t.mcp_param_command_desc_short
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: t.mcp_param_args_desc
        },
        format: {
          type: 'string',
          enum: ['json', 'sarif', 'text'],
          description: t.mcp_param_format_desc,
          default: 'json'
        },
        outputPath: {
          type: 'string',
          description: t.mcp_param_output_path_desc
        }
      },
      required: ['command']
    }
  },
  {
    name: 'listInstalledServers',
    description: t.mcp_tool_list_installed_servers_desc,
    inputSchema: {
      type: 'object',
      properties: {
        configPath: {
          type: 'string',
          description: t.mcp_param_config_path_desc_claude
        }
      },
      required: []
    }
  },
  {
    name: 'selfAudit',
    description: t.mcp_tool_self_audit_desc,
    inputSchema: {
      type: 'object',
      properties: {
        configPath: {
          type: 'string',
          description: t.mcp_param_config_path_desc_claude
        },
        skipServerValidation: {
          type: 'boolean',
          description: t.mcp_param_skip_validation_desc
        }
      },
      required: []
    }
  },
  {
    name: 'compareServers',
    description: t.mcp_tool_compare_servers_desc,
    inputSchema: {
      type: 'object',
      properties: {
        serverNames: {
          type: 'array',
          items: { type: 'string' },
          description: 'Names of configured servers to compare.'
        },
        servers: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: {
                type: 'string',
                description: t.mcp_param_server_name_desc
              },
              command: {
                type: 'string',
                description: t.mcp_param_command_desc_compare
              },
              args: {
                type: 'array',
                items: { type: 'string' },
                description: t.mcp_param_args_desc_compare
              }
            },
            required: ['name', 'command']
          },
          description: t.mcp_param_servers_desc
        }
      },
      required: []
    }
  },
  {
    name: 'fuzzTool',
    description: 'Execute selective fuzzing on a specific MCP tool to identify security vulnerabilities. Supports light, balanced, and aggressive profiles for targeted security testing.',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'Command to run the MCP server (e.g., "node server.js")'
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional arguments for the server command'
        },
        toolName: {
          type: 'string',
          description: 'Name of the specific tool to fuzz'
        },
        profile: {
          type: 'string',
          enum: ['light', 'balanced', 'aggressive'],
          description: 'Fuzzing intensity: light (25 payloads, 30s), balanced (50 payloads, 60s), aggressive (100 payloads, 120s)',
          default: 'balanced'
        },
        maxDuration: {
          type: 'number',
          description: 'Maximum fuzzing duration in seconds',
          default: 120
        }
      },
      required: ['command', 'toolName']
    }
  },
  {
    name: 'inspectToolSemantics',
    description: 'Analyze an MCP tool for malicious intent using strict LLM analysis. Detects discrepancies between tool descriptions and actual capabilities to identify deceptive or dangerous tools.',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'Command to run the MCP server (if fetching tool from server)'
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional arguments for the server command'
        },
        toolName: {
          type: 'string',
          description: 'Name of the tool to analyze (if fetching from server)'
        },
        toolDefinition: {
          type: 'object',
          description: 'Direct tool definition to analyze (alternative to fetching from server)'
        },
        llmProvider: {
          type: 'string',
          enum: ['anthropic', 'openai', 'ollama', 'gemini'],
          description: 'LLM provider for semantic analysis',
          default: 'anthropic'
        },
        llmModel: {
          type: 'string',
          description: 'Specific model to use (overrides default for provider)'
        }
      },
      required: []
    }
  },
  {
    name: 'suggestSecureSchema',
    description: 'Analyze MCP tool input schema and suggest security-hardened version with constraints (maxLength, patterns, bounds, enums). Implements the Shield Pattern for automatic schema hardening.',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'Command to run the MCP server (if fetching tool from server)'
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional arguments for the server command'
        },
        toolName: {
          type: 'string',
          description: 'Name of the tool to analyze (if fetching from server)'
        },
        toolDefinition: {
          type: 'object',
          description: 'Direct tool definition to analyze (alternative to fetching from server)'
        },
        strictness: {
          type: 'string',
          enum: ['minimal', 'balanced', 'maximum'],
          description: 'Hardening strictness level: minimal (DoS only), balanced (recommended), maximum (strict constraints)',
          default: 'balanced'
        }
      },
      required: []
    }
  }
];

/**
 * Create and configure the MCP Verify Server
 */
export function createMCPVerifyServer(): Server {
  const server = new Server(
    {
      name: 'mcp-verify-server',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Register tools/list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    logger.info('Listing available tools', {
      metadata: { toolCount: TOOLS.length }
    });

    return {
      tools: TOOLS
    };
  });

  // Register tools/call handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    logger.info('Tool called', {
      metadata: {
        toolName: name,
        arguments: args
      }
    });

    try {
      switch (name) {
        case 'validateServer':
          return await validateServerTool(args);

        case 'scanSecurity':
          return await scanSecurityTool(args);

        case 'analyzeQuality':
          return await analyzeQualityTool(args);

        case 'generateReport':
          return await generateReportTool(args);

        case 'listInstalledServers':
          return await listInstalledServersTool(args);

        case 'selfAudit':
          return await selfAuditTool(args);

        case 'compareServers':
          return await compareServersTool(args);

        case 'fuzzTool':
          return await fuzzToolTool(args);

        case 'inspectToolSemantics':
          return await inspectToolSemanticsTool(args);

        case 'suggestSecureSchema':
          return await suggestSecureSchemaTool(args);

        default:
          throw new Error(`${t.mcp_error_unknown_tool}: ${name}`);
      }
    } catch (error) {
      logger.error('Tool execution failed', error as Error);
      throw error;
    }
  });

  // Error handling
  server.onerror = (error) => {
    logger.error('Server error', error as Error);
  };

  logger.info('MCP Verify Server configured', {
    metadata: {
      toolsRegistered: TOOLS.length,
      version: '1.0.0'
    }
  });

  return server;
}

/**
 * Start the MCP Verify Server with stdio transport
 */
export async function startServer(): Promise<void> {
  logger.info('Starting MCP Verify Server');

  const server = createMCPVerifyServer();
  const transport = new StdioServerTransport();

  await server.connect(transport);

  logger.info('MCP Verify Server started successfully', {
    metadata: {
      transport: 'stdio',
      pid: process.pid
    }
  });
}
