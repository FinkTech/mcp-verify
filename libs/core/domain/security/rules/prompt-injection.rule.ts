/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Prompt Injection Detection Rule (SEC-013)
 *
 * Enterprise-grade detection of prompt injection vulnerabilities in MCP servers.
 * Since MCP is designed for LLM interaction, untrusted input in prompts
 * is a primary attack vector (OWASP LLM01:2023).
 *
 * Detection Capabilities:
 * - Direct prompt injection: Parameters explicitly handling prompts
 * - Indirect prompt injection: Tools that process external content (URLs, files)
 *   which could contain malicious instructions
 * - NLP processing indicators: Tools that summarize, translate, extract, or analyze
 *   external text are high-risk vectors
 * - Missing safety constraints: maxLength, pattern, enum restrictions
 *
 * @module libs/core/domain/security/rules/prompt-injection.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

// ─────────────────────────────────────────────────────────────────────────────
// KEYWORD CATEGORIES FOR DETECTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Direct prompt indicators - parameters explicitly named as prompts/messages
 * High confidence of being injection vectors
 */
const DIRECT_PROMPT_KEYWORDS: readonly string[] = [
  'prompt',
  'instruction',
  'message',
  'user_input',
  'user_message',
  'system_prompt',
  'assistant_message',
  'chat_message',
  'conversation',
];

/**
 * NLP processing indicators - descriptions that suggest LLM processing
 * Medium-High confidence - these tools process text that may contain injections
 */
const NLP_PROCESSING_KEYWORDS: readonly string[] = [
  'summarize',
  'summarise',
  'translate',
  'extract',
  'analyze',
  'analyse',
  'parse',
  'interpret',
  'generate',
  'rewrite',
  'paraphrase',
  'classify',
  'categorize',
  'sentiment',
  'answer',
  'respond',
  'reply',
  'explain',
  'describe',
];

/**
 * Generic text input indicators - parameters that accept free-form text
 * Medium confidence - may or may not be processed by LLM
 */
const GENERIC_TEXT_KEYWORDS: readonly string[] = [
  'input',
  'query',
  'text',
  'content',
  'body',
  'data',
  'request',
  'question',
  'task',
  'command',
];

/**
 * Indirect injection sources - tools that fetch/read external content
 * Critical risk if content is then processed by LLM
 */
const INDIRECT_INJECTION_KEYWORDS: readonly string[] = [
  'url',
  'uri',
  'link',
  'fetch',
  'read',
  'load',
  'download',
  'scrape',
  'crawl',
  'import',
  'webpage',
  'website',
  'file',
  'document',
  'email',
  'attachment',
];

/**
 * Suggested regex patterns for sanitizing prompt inputs
 * These block common injection control characters
 */
const RECOMMENDED_PATTERNS = {
  /**
   * Basic: Alphanumeric + common punctuation, no control chars
   * Blocks: backticks, pipes, angle brackets, null bytes
   */
  basic: '^[\\p{L}\\p{N}\\s.,!?;:\'"()\\-@#$%&*+=\\[\\]{}]+$',

  /**
   * Strict: Alphanumeric + minimal punctuation
   * Maximum security, may be too restrictive for some use cases
   */
  strict: '^[\\p{L}\\p{N}\\s.,!?;:]+$',

  /**
   * Block injection markers: Prevents common prompt injection delimiters
   * Blocks: [INST], <<SYS>>, ###, ---, ~~~, etc.
   */
  noInjectionMarkers: '^(?!.*\\[(?:INST|SYSTEM|USER|ASSISTANT)\\])(?!.*(?:<<|>>)SYS)(?!.*(?:###|---|~~~|\\*\\*\\*)).*$',
};

/**
 * Keyword risk categorization result
 */
interface KeywordMatch {
  category: 'direct' | 'nlp' | 'generic' | 'indirect';
  keyword: string;
  riskLevel: 'critical' | 'high' | 'medium';
}

/**
 * Analyzes text for prompt injection risk indicators
 */
function analyzeTextForRisk(text: string): KeywordMatch | null {
  const lower = text.toLowerCase();

  // Check direct prompt keywords (highest risk)
  for (const kw of DIRECT_PROMPT_KEYWORDS) {
    if (lower.includes(kw)) {
      return { category: 'direct', keyword: kw, riskLevel: 'high' };
    }
  }

  // Check NLP processing keywords (high risk)
  for (const kw of NLP_PROCESSING_KEYWORDS) {
    if (lower.includes(kw)) {
      return { category: 'nlp', keyword: kw, riskLevel: 'high' };
    }
  }

  // Check indirect injection sources (critical when combined with NLP)
  for (const kw of INDIRECT_INJECTION_KEYWORDS) {
    if (lower.includes(kw)) {
      return { category: 'indirect', keyword: kw, riskLevel: 'critical' };
    }
  }

  // Check generic text keywords (medium risk)
  for (const kw of GENERIC_TEXT_KEYWORDS) {
    if (lower.includes(kw)) {
      return { category: 'generic', keyword: kw, riskLevel: 'medium' };
    }
  }

  return null;
}

/**
 * Legacy function for backwards compatibility
 */
function containsPromptKeyword(value: string): boolean {
  return analyzeTextForRisk(value) !== null;
}

export class PromptInjectionRule implements ISecurityRule {
  readonly code = 'SEC-013';
  get name() { return t('sec_prompt_injection_name'); }
  get description() { return t('sec_prompt_injection_desc'); }
  readonly helpUri = 'https://owasp.org/www-project-top-10-for-large-language-model-applications/';
  readonly tags = ['LLM01', 'OWASP-LLM', 'Prompt Injection'];

  /**
   * Evaluates the MCP server discovery data for prompt injection risks.
   */
  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (discovery.tools) {
      findings.push(...this.analyzeTools(discovery.tools));
    }

    if (discovery.prompts) {
      findings.push(...this.analyzePrompts(discovery.prompts));
    }

    return findings;
  }

  /**
   * Iterates over every tool's input-schema properties and checks whether
   * prompt-like string parameters are missing safety constraints.
   * Enhanced with multi-category risk detection and specific remediation.
   */
  private analyzeTools(tools: McpTool[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const tool of tools) {
      // Tool-level analysis for indirect injection chains
      const toolMatch = this.analyzeToolForIndirectInjection(tool);

      const schema = tool.inputSchema;
      if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
        // Tool with indirect injection indicators but no schema = high risk
        if (toolMatch && toolMatch.category === 'indirect') {
          findings.push(this.createIndirectInjectionFinding(tool, toolMatch));
        }
        continue;
      }

      const properties = (schema as Record<string, unknown>).properties;
      if (!properties || typeof properties !== 'object' || Array.isArray(properties)) {
        if (toolMatch && toolMatch.category === 'indirect') {
          findings.push(this.createIndirectInjectionFinding(tool, toolMatch));
        }
        continue;
      }

      for (const [paramName, paramConfig] of Object.entries(properties)) {
        const config = paramConfig as Record<string, JsonValue>;

        // Only inspect string-typed parameters
        if (config.type !== 'string') continue;

        const description = typeof config.description === 'string' ? config.description : '';

        // Enhanced risk analysis
        const paramMatch = analyzeTextForRisk(paramName);
        const descMatch = analyzeTextForRisk(description);
        const match = paramMatch || descMatch;

        // Skip parameters with no risk indicators
        if (!match) continue;

        // Determine severity based on risk category
        const { severity, isIndirect } = this.calculateRiskSeverity(match, toolMatch);

        // ── MISSING maxLength ──────────────────────────────────────────
        if (config.maxLength === undefined || config.maxLength === null) {
          findings.push({
            ruleCode: this.code,
            severity: severity,
            message: t('finding_prompt_injection_no_limit', { param: paramName, tool: tool.name }),
            component: `tool:${tool.name}`,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              parameter: paramName,
              riskCategory: match.category,
              matchedKeyword: match.keyword,
              isIndirectVector: isIndirect,
              risk: this.getRiskDescription(match, isIndirect)
            },
            remediation: t('remediation_prompt_injection_limit_enterprise', {
              maxLength: this.getRecommendedMaxLength(match.category)
            })
          });
        }

        // ── MISSING pattern - with specific regex recommendations ─────
        if (config.pattern === undefined || config.pattern === null) {
          const recommendedPattern = this.getRecommendedPattern(match.category, isIndirect);

          findings.push({
            ruleCode: this.code,
            severity: severity === 'medium' ? 'low' : 'medium', // One level lower than no-limit
            message: t('finding_prompt_injection_no_pattern', { param: paramName, tool: tool.name }),
            component: `tool:${tool.name}`,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              parameter: paramName,
              riskCategory: match.category,
              matchedKeyword: match.keyword,
              suggestedPattern: recommendedPattern.pattern,
              patternDescription: recommendedPattern.description
            },
            remediation: t('remediation_prompt_injection_pattern_specific', {
              pattern: recommendedPattern.pattern,
              description: recommendedPattern.description
            })
          });
        }

        // ── WEAK pattern (too permissive) ─────────────────────────────
        if (config.pattern && this.isWeakPattern(String(config.pattern))) {
          findings.push({
            ruleCode: this.code,
            severity: 'medium',
            message: t('finding_prompt_injection_weak_pattern', { param: paramName, tool: tool.name }),
            component: `tool:${tool.name}`,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              parameter: paramName,
              currentPattern: config.pattern,
              weakness: 'Pattern allows injection control characters'
            },
            remediation: t('remediation_prompt_injection_strengthen_pattern')
          });
        }
      }

      // Add tool-level indirect injection finding if applicable
      if (toolMatch && toolMatch.category === 'indirect' && this.hasNLPProcessing(tool)) {
        findings.push(this.createIndirectInjectionChainFinding(tool, toolMatch));
      }
    }

    return findings;
  }

  /**
   * Analyzes tool description and name for indirect injection indicators
   */
  private analyzeToolForIndirectInjection(tool: McpTool): KeywordMatch | null {
    const toolText = `${tool.name} ${tool.description || ''}`;
    return analyzeTextForRisk(toolText);
  }

  /**
   * Checks if tool description suggests NLP/LLM processing
   */
  private hasNLPProcessing(tool: McpTool): boolean {
    const text = `${tool.name} ${tool.description || ''}`.toLowerCase();
    return NLP_PROCESSING_KEYWORDS.some(kw => text.includes(kw));
  }

  /**
   * Calculates severity based on risk category and context
   */
  private calculateRiskSeverity(match: KeywordMatch, toolMatch: KeywordMatch | null): {
    severity: 'critical' | 'high' | 'medium' | 'low';
    isIndirect: boolean;
  } {
    const isIndirect = match.category === 'indirect' || toolMatch?.category === 'indirect';

    // Indirect injection combined with NLP processing = critical
    if (isIndirect && toolMatch &&
        (toolMatch.category === 'nlp' || match.category === 'nlp')) {
      return { severity: 'critical', isIndirect: true };
    }

    // Direct prompt inputs without limits = high
    if (match.category === 'direct') {
      return { severity: 'high', isIndirect };
    }

    // NLP processing inputs = high
    if (match.category === 'nlp') {
      return { severity: 'high', isIndirect };
    }

    // Indirect sources = medium (could be used for injection)
    if (match.category === 'indirect') {
      return { severity: 'medium', isIndirect: true };
    }

    // Generic text inputs = medium
    return { severity: 'medium', isIndirect };
  }

  /**
   * Creates a finding for indirect injection vulnerability
   */
  private createIndirectInjectionFinding(tool: McpTool, match: KeywordMatch): SecurityFinding {
    return {
      ruleCode: this.code,
      severity: 'high',
      message: t('finding_prompt_injection_indirect', { tool: tool.name, keyword: match.keyword }),
      component: `tool:${tool.name}`,
      location: { type: 'tool', name: tool.name },
      evidence: {
        riskCategory: 'indirect',
        matchedKeyword: match.keyword,
        risk: 'Tool fetches external content that may contain malicious prompt injections'
      },
      remediation: t('remediation_prompt_injection_indirect')
    };
  }

  /**
   * Creates a finding for indirect injection chain (fetch + process)
   */
  private createIndirectInjectionChainFinding(tool: McpTool, match: KeywordMatch): SecurityFinding {
    return {
      ruleCode: this.code,
      severity: 'critical',
      message: t('finding_prompt_injection_chain', { tool: tool.name }),
      component: `tool:${tool.name}`,
      location: { type: 'tool', name: tool.name },
      evidence: {
        riskCategory: 'indirect-chain',
        indirectKeyword: match.keyword,
        risk: 'Tool fetches AND processes external content - high indirect injection risk',
        attackScenario: 'Attacker embeds malicious instructions in fetched content (URL, file, email)'
      },
      remediation: t('remediation_prompt_injection_chain')
    };
  }

  /**
   * Returns recommended maxLength based on risk category
   */
  private getRecommendedMaxLength(category: string): number {
    switch (category) {
      case 'direct': return 10000; // Prompts need reasonable length
      case 'nlp': return 50000;    // Documents may be larger
      case 'generic': return 5000; // General inputs
      case 'indirect': return 1000; // URLs/paths should be short
      default: return 5000;
    }
  }

  /**
   * Returns recommended pattern based on risk category
   */
  private getRecommendedPattern(category: string, isIndirect: boolean): {
    pattern: string;
    description: string;
  } {
    if (isIndirect) {
      return {
        pattern: '^https?://[\\w\\-]+(\\.[\\w\\-]+)+(/[\\w\\-./]*)?$',
        description: 'HTTPS URLs only, no query params (prevents data exfiltration)'
      };
    }

    switch (category) {
      case 'direct':
        return {
          pattern: RECOMMENDED_PATTERNS.noInjectionMarkers,
          description: 'Blocks common prompt injection markers ([INST], <<SYS>>, ###, etc.)'
        };
      case 'nlp':
        return {
          pattern: RECOMMENDED_PATTERNS.basic,
          description: 'Alphanumeric + punctuation, no control characters'
        };
      default:
        return {
          pattern: RECOMMENDED_PATTERNS.strict,
          description: 'Strict alphanumeric with minimal punctuation'
        };
    }
  }

  /**
   * Checks if a pattern is too permissive (weak)
   */
  private isWeakPattern(pattern: string): boolean {
    // Patterns that match everything or most things
    const weakPatterns = [
      /^\.\*$/,           // .*
      /^\.\+$/,           // .+
      /^\[\^\]\*$/,       // [^]*
      /^\\s\*\\S/,        // \s*\S (too permissive)
    ];
    return weakPatterns.some(wp => wp.test(pattern));
  }

  /**
   * Returns a human-readable risk description
   */
  private getRiskDescription(match: KeywordMatch, isIndirect: boolean): string {
    if (isIndirect) {
      return 'Indirect injection vector: external content may contain malicious instructions';
    }

    switch (match.category) {
      case 'direct':
        return 'Direct prompt parameter - primary injection target';
      case 'nlp':
        return 'NLP processing indicator - text will be processed by LLM';
      case 'generic':
        return 'Generic text input - may be processed by downstream LLM';
      default:
        return 'Potential injection surface';
    }
  }

  /**
   * Checks whether any MCP Prompt definition exposes unvalidated arguments.
   * Per the MCP spec (2024-11-05), prompt arguments carry no schema, so
   * every argument is an implicit injection surface.
   */
  private analyzePrompts(prompts: any[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const prompt of prompts) {
      const args = prompt.arguments;
      if (!Array.isArray(args) || args.length === 0) continue;

      findings.push({
        ruleCode: this.code,
        severity: 'low',
        message: t('finding_prompt_injection_prompt_args', { prompt: prompt.name }),
        component: `prompt:${prompt.name}`,
        evidence: {
            promptName: prompt.name,
            argumentCount: args.length
        },
        remediation: t('remediation_prompt_injection_prompt_args')
      });
    }

    return findings;
  }
}
