/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * LLM Output Formatter
 *
 * Transforms raw validation reports into LLM-friendly formats with:
 * - Human-readable summaries
 * - Actionable recommendations
 * - Clear next steps
 * - Prioritized findings
 */

import { Report, SecurityFinding } from '@mcp-verify/core';

export interface LLMFriendlyOutput {
  // High-level status
  status: 'valid' | 'invalid' | 'error';
  recommendation: 'safe_to_deploy' | 'review_required' | 'blocking_issues';

  // Human-readable summary for LLMs
  llm_summary: string;

  // Actionable next steps
  next_steps: string[];

  // Detailed scores
  scores: {
    security: number;
    quality: number;
    protocol: number;
    overall: number;
  };

  // Capabilities summary
  capabilities: {
    tools: number;
    resources: number;
    prompts: number;
  };

  // Actionable findings (prioritized)
  actionable_items?: Array<{
    priority: 'critical' | 'high' | 'medium' | 'low';
    category: string;
    issue: string;
    impact: string;
    fix: string;
    location?: {
      type: string;
      name: string;
      parameter?: string;
    };
  }>;

  // Raw data for detailed analysis
  raw_report: {
    security_findings: number;
    quality_issues: number;
    protocol_violations: number;
  };
}

/**
 * Format a validation report for LLM consumption
 */
export function formatForLLM(report: Report): LLMFriendlyOutput {
  // Calculate overall score (weighted average)
  const overallScore = calculateOverallScore(report);

  // Determine recommendation
  const recommendation = determineRecommendation(report);

  // Generate human-readable summary
  const llmSummary = generateLLMSummary(report, recommendation);

  // Generate actionable next steps
  const nextSteps = generateNextSteps(report, recommendation);

  // Extract actionable items from findings
  const actionableItems = extractActionableItems(report);

  return {
    status: report.status,
    recommendation,
    llm_summary: llmSummary,
    next_steps: nextSteps,

    scores: {
      security: report.security.score,
      quality: report.quality?.score || 0,
      protocol: report.protocolCompliance?.score || 100,
      overall: overallScore,
    },

    capabilities: {
      tools: report.tools.count,
      resources: report.resources.count,
      prompts: report.prompts.count,
    },

    actionable_items: actionableItems.length > 0 ? actionableItems : undefined,

    raw_report: {
      security_findings: report.security.findings.length,
      quality_issues: report.quality?.issues.length || 0,
      protocol_violations: report.protocolCompliance?.issues.length || 0,
    },
  };
}

/**
 * Calculate overall health score
 */
function calculateOverallScore(report: Report): number {
  const weights = {
    security: 0.5, // Security is most important
    quality: 0.3,
    protocol: 0.2,
  };

  const securityScore = report.security.score;
  const qualityScore = report.quality?.score || 0;
  const protocolScore = report.protocolCompliance?.score || 100;

  return Math.round(
    securityScore * weights.security +
    qualityScore * weights.quality +
    protocolScore * weights.protocol
  );
}

/**
 * Determine deployment recommendation
 */
function determineRecommendation(
  report: Report
): 'safe_to_deploy' | 'review_required' | 'blocking_issues' {
  const criticalCount = report.security.criticalCount || 0;
  const highCount = report.security.highCount || 0;
  const securityScore = report.security.score;

  // Blocking: Any critical issues
  if (criticalCount > 0) {
    return 'blocking_issues';
  }

  // Review required: High severity issues or low security score
  if (highCount > 0 || securityScore < 70) {
    return 'review_required';
  }

  // Safe: No major issues
  return 'safe_to_deploy';
}

/**
 * Generate human-readable summary
 */
function generateLLMSummary(
  report: Report,
  recommendation: string
): string {
  const parts: string[] = [];

  // Overall status
  if (recommendation === 'blocking_issues') {
    parts.push(`🔴 CRITICAL: This MCP server has blocking security issues that must be fixed before deployment.`);
  } else if (recommendation === 'review_required') {
    parts.push(`🟡 WARNING: This MCP server has security concerns that should be reviewed.`);
  } else {
    parts.push(`🟢 This MCP server passes security validation and appears safe to deploy.`);
  }

  // Security details
  const criticalCount = report.security.criticalCount || 0;
  const highCount = report.security.highCount || 0;
  const mediumCount = report.security.mediumCount || 0;

  if (criticalCount > 0) {
    const criticalIssues = report.security.findings
      .filter((f) => f.severity === 'critical')
      .map((f) => f.message)
      .slice(0, 2) // Top 2
      .join('; ');

    parts.push(
      `Found ${criticalCount} CRITICAL security issue(s): ${criticalIssues}${criticalCount > 2 ? ` and ${criticalCount - 2} more` : ''}.`
    );
  }

  if (highCount > 0) {
    parts.push(`Found ${highCount} HIGH severity security issue(s).`);
  }

  if (mediumCount > 0) {
    parts.push(`Found ${mediumCount} MEDIUM severity issue(s).`);
  }

  // Capabilities summary
  parts.push(
    `Server exposes ${report.tools.count} tool(s), ${report.resources.count} resource(s), and ${report.prompts.count} prompt(s).`
  );

  // Quality note
  if (report.quality && report.quality.score < 70) {
    parts.push(
      `Quality score is ${report.quality.score}/100 - documentation and naming could be improved.`
    );
  }

  // Protocol compliance
  if (report.protocolCompliance && !report.protocolCompliance.passed) {
    parts.push(`Protocol compliance issues detected - server may not follow JSON-RPC 2.0 standards correctly.`);
  }

  return parts.join(' ');
}

/**
 * Generate actionable next steps
 */
function generateNextSteps(
  report: Report,
  recommendation: string
): string[] {
  const steps: string[] = [];

  const criticalFindings = report.security.findings.filter((f) => f.severity === 'critical');
  const highFindings = report.security.findings.filter((f) => f.severity === 'high');

  // Critical fixes (top 3)
  criticalFindings.slice(0, 3).forEach((finding, i) => {
    steps.push(`Fix CRITICAL issue #${i + 1}: ${finding.message} (${finding.ruleCode || finding.component})`);
  });

  // High priority fixes (top 2 if no criticals)
  if (criticalFindings.length === 0 && highFindings.length > 0) {
    highFindings.slice(0, 2).forEach((finding, i) => {
      steps.push(`Fix HIGH severity issue #${i + 1}: ${finding.message} (${finding.ruleCode || finding.component})`);
    });
  }

  // Quality improvements
  if (report.quality && report.quality.issues.length > 0) {
    const qualityIssue = report.quality.issues[0];
    steps.push(`Improve quality: ${qualityIssue.message} - ${qualityIssue.suggestion}`);
  }

  // Protocol compliance
  if (report.protocolCompliance && report.protocolCompliance.issues.length > 0) {
    const protocolIssue = report.protocolCompliance.issues[0];
    steps.push(`Fix protocol issue: ${protocolIssue.message} (${protocolIssue.code})`);
  }

  // Re-scan recommendation
  if (steps.length > 0) {
    steps.push(`After fixes, re-run validation to verify: validateServer({command: "node server.js"})`);
  }

  // If no issues, suggest best practices
  if (steps.length === 0) {
    steps.push(`Consider running stress testing: stressTest({command: "node server.js", users: 10})`);
    steps.push(`Consider enabling fuzzing for chaos testing: runFuzzing({command: "node server.js"})`);
  }

  return steps;
}

/**
 * Extract actionable items from findings
 */
function extractActionableItems(report: Report): Array<{
  priority: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  issue: string;
  impact: string;
  fix: string;
  location?: {
    type: string;
    name: string;
    parameter?: string;
  };
}> {
  const items: ReturnType<typeof extractActionableItems> = [];

  // Security findings
  report.security.findings.forEach((finding) => {
    items.push({
      priority: finding.severity as 'critical' | 'high' | 'medium' | 'low',
      category: 'Security',
      issue: finding.message,
      impact: determineImpact(finding),
      fix: finding.remediation || getSuggestedFix(finding),
      location: finding.location ? {
        type: finding.location.type || '',
        name: finding.location.name || '',
        parameter: finding.location.parameter
      } : undefined,
    });
  });

  // Quality issues (only major ones)
  if (report.quality) {
    report.quality.issues
      .filter((issue) => issue.severity === 'high' || issue.severity === 'medium')
      .forEach((issue) => {
        items.push({
          priority: issue.severity as 'high' | 'medium',
          category: 'Quality',
          issue: issue.message,
          impact: 'Reduces code maintainability and clarity',
          fix: issue.suggestion,
        });
      });
  }

  // Sort by priority
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  items.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  // Return top 10
  return items.slice(0, 10);
}

/**
 * Determine impact of a security finding
 */
function determineImpact(finding: SecurityFinding): string {
  const ruleCode = finding.ruleCode || '';

  if (ruleCode.includes('001')) return 'SQL injection attack - database compromise';
  if (ruleCode.includes('002')) return 'Command injection - arbitrary code execution';
  if (ruleCode.includes('003')) return 'SSRF attack - internal network access';
  if (ruleCode.includes('004')) return 'Data leakage - sensitive information exposure';
  if (ruleCode.includes('005')) return 'Path traversal - unauthorized file access';
  if (ruleCode.includes('006')) return 'XSS attack - user session hijacking';
  if (ruleCode.includes('007')) return 'XXE attack - server-side request forgery';
  if (ruleCode.includes('008')) return 'Deserialization attack - remote code execution';
  if (ruleCode.includes('009')) return 'Weak authentication - unauthorized access';
  if (ruleCode.includes('010')) return 'Sensitive data exposure - privacy breach';
  if (ruleCode.includes('011')) return 'DoS attack - service unavailability';
  if (ruleCode.includes('012')) return 'Missing security headers - various attacks';

  return 'Security vulnerability - potential attack vector';
}

/**
 * Get suggested fix for a finding
 */
function getSuggestedFix(finding: SecurityFinding): string {
  const message = finding.message.toLowerCase();

  if (message.includes('sql injection')) {
    return 'Use parameterized queries or an ORM. Never concatenate user input into SQL.';
  }
  if (message.includes('command injection')) {
    return 'Validate and sanitize all command inputs. Use allowlists for permitted commands.';
  }
  if (message.includes('ssrf')) {
    return 'Validate and restrict URLs. Block access to internal networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).';
  }
  if (message.includes('path traversal')) {
    return 'Validate file paths. Use path.resolve() and ensure paths stay within allowed directories.';
  }
  if (message.includes('rate limit')) {
    return 'Implement rate limiting using a library like express-rate-limit or custom middleware.';
  }
  if (message.includes('sensitive data')) {
    return 'Remove sensitive data from responses. Use environment variables for secrets.';
  }

  return 'Review and fix the security issue according to OWASP guidelines.';
}
