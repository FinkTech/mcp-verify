/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * compareServers Tool
 *
 * Compare security and quality across multiple MCP servers:
 * - Validates each server
 * - Compares security scores, findings, and quality
 * - Identifies best and worst performers
 * - Provides side-by-side comparison
 * - Enables informed decision-making
 */

import { promises as fs } from 'fs';
import * as path from 'path';
import { createScopedLogger, translations, Language } from '@mcp-verify/core';
import { validateServerTool } from './validate-server.js';
import { resolveServerByName, RawServerEntry } from '../utils/config-discovery.js';
import { ReportingService } from '@mcp-verify/shared';

const logger = createScopedLogger('compareServersTool');
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || 'en';
const t = translations[lang];

interface ServerToCompare {
  name: string;
  command: string;
  args?: string[];
}

interface CompareServersArgs {
  serverNames?: string[];
  servers?: ServerToCompare[];
}

interface CompareServersResult {
  content: Array<{
    type: 'text';
    text: string;
  }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

interface ValidationResult {
  name: string;
  command: string;
  status: 'validated' | 'failed';
  error?: string;
  scores: {
    security: number;
    quality: number;
    protocol: number;
    overall: number;
  };
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  capabilities: {
    tools: number;
    resources: number;
    prompts: number;
  };
  recommendation: string;
  llmSummary?: string;
}

interface ComparisonAnalysis {
  mostSecure?: ValidationResult;
  leastSecure?: ValidationResult;
  highestQuality?: ValidationResult;
  lowestQuality?: ValidationResult;
  avgSecurity: number;
  avgQuality: number;
  avgProtocol: number;
  avgOverall: number;
  totalFindings: number;
}

/**
 * Compare security and quality across multiple MCP servers
 */
export async function compareServersTool(
  args: unknown
): Promise<CompareServersResult> {
  const { serverNames = [], servers = [] } = (args || {}) as CompareServersArgs;

  logger.info('Starting compareServers', {
    metadata: {
      serverNamesCount: serverNames.length,
      explicitServersCount: servers.length
    }
  });

  // Resolve all servers to a unified list
  const finalServers: ServerToCompare[] = [];

  // 1. Resolve serverNames from config
  for (const name of serverNames) {
    const resolved = resolveServerByName(name);
    if (resolved) {
      finalServers.push({
        name,
        command: resolved.command,
        args: resolved.args
      });
    } else {
      logger.warn(`Could not resolve server by name: ${name}`);
    }
  }

  // 2. Add explicit servers, but try to resolve missing args if name matches
  for (const s of servers) {
    if (!s.args || s.args.length === 0) {
      const resolved = resolveServerByName(s.name);
      if (resolved) {
        finalServers.push({
          name: s.name,
          command: s.command || resolved.command,
          args: resolved.args
        });
        continue;
      }
    }
    finalServers.push(s);
  }

  // Final Validation
  if (finalServers.length < 2) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: 'error',
            error: t.mcp_error_at_least_two_servers,
            message: t.mcp_error_please_provide_two_servers,
            llm_summary: '⚠️ Cannot compare servers: At least 2 servers are required.',
            next_steps: [
              'Provide at least 2 servers in the servers array',
              'Or provide names of configured servers in the serverNames array',
              'Example: {serverNames: ["server-a", "server-b"]}'
            ]
          }, null, 2)
        }
      ],
      isError: true
    };
  }

  try {
    // Validate each server
    logger.info('Validating servers for comparison', {
      metadata: { count: finalServers.length }
    });

    const validationResults: ValidationResult[] = [];

    for (const server of finalServers) {
      logger.info('Validating server', {
        metadata: { name: server.name }
      });

      try {
        const validateResult = await validateServerTool({
          command: server.command,
          args: server.args || []
        });

        let validateData: any;
        try {
          validateData = JSON.parse(validateResult.content[0].text);
        } catch (parseError) {
          throw new Error(`Failed to parse validation result for ${server.name}: ${(parseError as Error).message}`);
        }

        if (validateData.status === 'error' || validateResult.isError) {
          validationResults.push({
            name: server.name,
            command: server.command,
            status: 'failed',
            error: validateData.error || 'Unknown validation error',
            scores: { security: 0, quality: 0, protocol: 0, overall: 0 },
            findings: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
            capabilities: { tools: 0, resources: 0, prompts: 0 },
            recommendation: 'validation_failed'
          });
          continue;
        }

        validationResults.push({
          name: server.name,
          command: server.command,
          status: 'validated',

          scores: {
            security: validateData.scores?.security || 0,
            quality: validateData.scores?.quality || 0,
            protocol: validateData.scores?.protocol || 0,
            overall: validateData.scores?.overall || 0
          },

          findings: {
            total: validateData.raw_report?.security_findings || 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
          },

          capabilities: validateData.capabilities || {
            tools: 0,
            resources: 0,
            prompts: 0
          },

          recommendation: validateData.recommendation || 'unknown',
          llmSummary: validateData.llm_summary
        });
      } catch (error) {
        logger.error('Failed to validate server', error as Error, {
          metadata: { serverName: server.name }
        });

        validationResults.push({
          name: server.name,
          command: server.command,
          status: 'failed',
          error: (error as Error).message,
          scores: {
            security: 0,
            quality: 0,
            protocol: 0,
            overall: 0
          },
          findings: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
          capabilities: { tools: 0, resources: 0, prompts: 0 },
          recommendation: 'validation_failed'
        });
      }
    }

    // Analyze comparison
    const analysis = analyzeComparison(validationResults);

    // Generate comparison report
    const llmSummary = generateComparisonSummary(validationResults, analysis);
    const nextSteps = generateComparisonNextSteps(validationResults, analysis);

    // --- REPORT GENERATION (Centralized via ReportingService) ---
    let reportPath = '';
    try {
      const savedReports = await ReportingService.saveReport({ 
        kind: 'compare', 
        data: { results: validationResults, analysis } 
      }, {
        outputDir: './reports',
        formats: ['json', 'markdown'],
        language: lang,
        filenamePrefix: 'mcp-comparison',
        organizeByFormat: true
      });
      
      reportPath = savedReports.paths.markdown || '';
      logger.info('Comparison report saved', { metadata: { path: reportPath as any } });
    } catch (err) {
      logger.error('Failed to save comparison report', err as Error);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: 'success',
            llm_summary: llmSummary,
            next_steps: nextSteps,
            report_file: reportPath,

            // Comparison results
            comparison: {
              totalServers: finalServers.length,
              validatedServers: validationResults.filter((r) => r.status === 'validated').length,
              failedValidations: validationResults.filter((r) => r.status === 'failed').length,

              // Best and worst
              mostSecure: analysis.mostSecure?.name,
              leastSecure: analysis.leastSecure?.name,
              highestQuality: analysis.highestQuality?.name,
              lowestQuality: analysis.lowestQuality?.name,

              // Aggregate stats
              averageScores: {
                security: analysis.avgSecurity,
                quality: analysis.avgQuality,
                protocol: analysis.avgProtocol,
                overall: analysis.avgOverall
              },

              totalFindings: analysis.totalFindings
            },

            // Detailed results per server
            results: validationResults.map((r) => ({
              name: r.name,
              status: r.status,
              scores: r.scores,
              findings: r.findings,
              capabilities: r.capabilities,
              recommendation: r.recommendation,
              summary: r.llmSummary
            })),

            // Side-by-side scores
            scoreComparison: {
              security: validationResults.map((r) => ({ name: r.name, score: r.scores.security })),
              quality: validationResults.map((r) => ({ name: r.name, score: r.scores.quality })),
              overall: validationResults.map((r) => ({ name: r.name, score: r.scores.overall }))
            }
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    logger.error('Server comparison failed', error as Error);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: 'error',
            error: (error as Error).message,
            message: t.mcp_error_failed_to_compare_servers,
            llm_summary: `⚠️ Server comparison failed: ${(error as Error).message}`,
            next_steps: [
              'Verify all servers are properly configured',
              'Check that server commands and args are correct',
              'Try validating servers individually first'
            ]
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}

/**
 * Analyze comparison results
 */
function analyzeComparison(results: ValidationResult[]): ComparisonAnalysis {
  const validResults = results.filter((r) => r.status === 'validated');

  if (validResults.length === 0) {
    return {
      avgSecurity: 0,
      avgQuality: 0,
      avgProtocol: 0,
      avgOverall: 0,
      totalFindings: 0
    };
  }

  // Find best and worst
  const mostSecure = validResults.reduce((a, b) =>
    a.scores.security > b.scores.security ? a : b
  );

  const leastSecure = validResults.reduce((a, b) =>
    a.scores.security < b.scores.security ? a : b
  );

  const highestQuality = validResults.reduce((a, b) =>
    a.scores.quality > b.scores.quality ? a : b
  );

  const lowestQuality = validResults.reduce((a, b) =>
    a.scores.quality < b.scores.quality ? a : b
  );

  // Calculate averages
  const avgSecurity = Math.round(
    validResults.reduce((sum, r) => sum + r.scores.security, 0) / validResults.length
  );

  const avgQuality = Math.round(
    validResults.reduce((sum, r) => sum + r.scores.quality, 0) / validResults.length
  );

  const avgOverall = Math.round(
    validResults.reduce((sum, r) => sum + r.scores.overall, 0) / validResults.length
  );

  const avgProtocol = Math.round(
    validResults.reduce((sum, r) => sum + r.scores.protocol, 0) / validResults.length
  );

  const totalFindings = results.reduce((sum, r) => sum + (r.findings?.total || 0), 0);

  return {
    mostSecure,
    leastSecure,
    highestQuality,
    lowestQuality,
    avgSecurity,
    avgQuality,
    avgProtocol,
    avgOverall,
    totalFindings
  };
}

/**
 * Generate comparison summary
 */
function generateComparisonSummary(results: ValidationResult[], analysis: ComparisonAnalysis): string {
  const parts: string[] = [];

  const validCount = results.filter((r) => r.status === 'validated').length;
  const failedCount = results.filter((r) => r.status === 'failed').length;

  parts.push(`📊 SECURITY COMPARISON: Analyzed ${results.length} MCP server(s)`);

  if (failedCount > 0) {
    parts.push(`⚠️ ${failedCount} server(s) failed validation and could not be compared.`);
  }

  if (validCount === 0) {
    parts.push('No servers could be validated successfully.');
    return parts.join(' ');
  }

  // Best and worst
  if (analysis.mostSecure && analysis.leastSecure) {
    const securityGap = analysis.mostSecure.scores.security - analysis.leastSecure.scores.security;

    parts.push('');
    parts.push('Security Rankings:');
    parts.push(`  🥇 Most Secure: "${analysis.mostSecure.name}" (${analysis.mostSecure.scores.security}/100)`);
    parts.push(`  🔻 Least Secure: "${analysis.leastSecure.name}" (${analysis.leastSecure.scores.security}/100)`);

    if (securityGap > 20) {
      parts.push(`  ⚠️ Large security gap detected: ${securityGap} points difference`);
    }
  }

  // Quality rankings
  if (analysis.highestQuality && analysis.lowestQuality) {
    parts.push('');
    parts.push('Quality Rankings:');
    parts.push(`  🥇 Best Quality: "${analysis.highestQuality.name}" (${analysis.highestQuality.scores.quality}/100)`);
    parts.push(`  🔻 Lowest Quality: "${analysis.lowestQuality.name}" (${analysis.lowestQuality.scores.quality}/100)`);
  }

  // Averages
  parts.push('');
  parts.push(`Average Security Score: ${analysis.avgSecurity}/100`);
  parts.push(`Average Quality Score: ${analysis.avgQuality}/100`);
  parts.push(`Total Security Findings: ${analysis.totalFindings}`);

  return parts.join('\n');
}

/**
 * Generate actionable next steps
 */
function generateComparisonNextSteps(results: ValidationResult[], analysis: ComparisonAnalysis): string[] {
  const steps: string[] = [];

  // Failed validations
  const failed = results.filter((r) => r.status === 'failed');
  if (failed.length > 0) {
    failed.forEach((server) => {
      steps.push(`Fix validation failure for "${server.name}": ${server.error}`);
    });
  }

  // Least secure server
  if (analysis.leastSecure && analysis.leastSecure.scores.security < 70 && analysis.leastSecure.status === 'validated') {
    steps.push(`Priority: Improve security of "${analysis.leastSecure.name}" (currently ${analysis.leastSecure.scores.security}/100)`);
  }

  // Servers with blocking issues
  const blocking = results.filter((r) => r.recommendation === 'blocking_issues');
  blocking.forEach((server) => {
    steps.push(`URGENT: Fix critical issues in "${server.name}" before deployment`);
  });

  // Servers needing review
  const needsReview = results.filter((r) => r.recommendation === 'review_required');
  if (needsReview.length > 0) {
    steps.push(`Review security warnings for ${needsReview.length} server(s): ${needsReview.map((s) => s.name).join(', ')}`);
  }

  // Consider standardization
  if (analysis.avgSecurity < 80 && results.filter(r => r.status === 'validated').length > 0) {
    steps.push('Consider standardizing security practices across all servers');
  }

  // If all good
  if (steps.length === 0 && results.length > 0) {
    steps.push('All servers are performing well - maintain current security standards');
    steps.push(`Consider using "${analysis.mostSecure?.name}" as a security template for other servers`);
  }

  return steps;
}
