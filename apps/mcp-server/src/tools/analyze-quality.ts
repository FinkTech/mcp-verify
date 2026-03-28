/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * analyzeQuality Tool
 *
 * Quality analysis of an MCP server:
 * - Documentation completeness
 * - Naming conventions
 * - Description clarity
 * - Semantic analysis
 */

import {
  MCPValidator,
  SemanticAnalyzer,
  createScopedLogger,
  StdioTransport,
  translations,
  Language,
  Report
} from '@mcp-verify/core';
import { formatForLLM } from '../utils/llm-formatter.js';
import { ReportingService } from '@mcp-verify/shared';

const logger = createScopedLogger('analyzeQualityTool');
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || 'en';
const t = translations[lang];

interface AnalyzeQualityArgs {
  command: string;
  args?: string[];
}

interface AnalyzeQualityResult {
  content: Array<{
    type: 'text';
    text: string;
  }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/**
 * Execute quality analysis on an MCP server
 */
export async function analyzeQualityTool(
  args: unknown
): Promise<AnalyzeQualityResult> {
  const { command, args: serverArgs = [] } = args as AnalyzeQualityArgs;

  logger.info('Starting analyzeQuality', {
    metadata: {
      command,
      args: serverArgs
    }
  });

  try {
    // Create transport
    const transport = StdioTransport.create(command, serverArgs);

    // Create validator
    const validator = new MCPValidator(transport);

    // Connect and discover
    logger.info('Connecting to server');
    const handshake = await validator.testHandshake();

    if (!handshake.success) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'error',
              error: handshake.error || t.mcp_error_connection_failed,
              message: t.mcp_error_failed_to_connect_quality
            }, null, 2)
          }
        ],
        isError: true
      };
    }

    logger.info('Discovering capabilities');
    const discovery = await validator.discoverCapabilities();

    // Run quality analysis
    logger.info('Running quality analysis');
    const analyzer = new SemanticAnalyzer();
    const qualityReport = await analyzer.analyze(discovery);

    // Cleanup
    validator.cleanup();

    // Save report files (like CLI does)
    logger.info('Saving quality report files');

    // Build minimal Report structure for LLM formatting
    const miniReport: Report = {
      server_name: handshake.serverName || t.mcp_unknown_server,
      url: command,
      status: 'valid',
      protocol_version: handshake.protocolVersion || t.mcp_not_available,
      timestamp: new Date().toISOString(),
      duration_ms: 0,

      // Security (not scanned, use defaults)
      security: {
        level: t.risk_level_low,
        score: 100,
        findings: []
      },

      // Quality results
      quality: qualityReport,

      // Protocol compliance (not scanned, assume passed)
      protocolCompliance: {
        passed: true,
        score: 100,
        issues: []
      },

      // Capabilities from discovery
      tools: {
        count: discovery.tools?.length || 0,
        valid: discovery.tools?.length || 0,
        invalid: 0,
        items: (discovery.tools || []).map(tool => ({ 
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
          status: 'valid' as const 
        }))
      },
      resources: {
        count: discovery.resources?.length || 0,
        valid: discovery.resources?.length || 0,
        invalid: 0,
        items: (discovery.resources || []).map(r => ({ ...r, status: 'valid' as const }))
      },
      prompts: {
        count: discovery.prompts?.length || 0,
        valid: discovery.prompts?.length || 0,
        invalid: 0,
        items: (discovery.prompts || []).map(p => ({ ...p, status: 'valid' as const }))
      },
      metadata: {
        toolVersion: '1.0.0',
        modulesExecuted: ['quality'],
        llmUsed: false
      }
    };

    // Save files to disk
    const savedReports = await ReportingService.saveReport({ 
      kind: 'validation', 
      data: miniReport 
    }, {
      outputDir: './reports',
      formats: ['json', 'markdown', 'html'],
      language: lang,
      filenamePrefix: 'mcp-quality',
      organizeByFormat: true
    });

    const savedPaths = savedReports.paths;

    logger.info('Quality reports saved to disk', {
      metadata: savedPaths as unknown as Record<string, unknown>
    });

    // Format for LLM consumption
    const llmOutput = formatForLLM(miniReport);

    // Add scan metadata
    const response = {
      ...llmOutput,
      serverInfo: {
        name: handshake.serverName || t.mcp_unknown_server,
        protocolVersion: handshake.protocolVersion || t.mcp_not_available
      },
      capabilities: {
        tools: discovery.tools?.length || 0,
        resources: discovery.resources?.length || 0,
        prompts: discovery.prompts?.length || 0
      }
    };

    logger.info('Quality analysis completed', {
      metadata: {
        score: qualityReport.score,
        issues: qualityReport.issues?.length || 0,
        recommendation: llmOutput.recommendation
      }
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response, null, 2)
        }
      ]
    };
  } catch (error) {
    logger.error('Quality analysis failed', error as Error);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: 'error',
            error: (error as Error).message,
            message: t.mcp_error_failed_to_analyze_quality
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}
