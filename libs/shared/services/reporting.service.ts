/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ReportingService
 *
 * Universal, format-agnostic reporting hub for all mcp-verify commands.
 *
 * Design goals:
 *   - Zero `any`: every payload is discriminated via a typed envelope.
 *   - Strategy pattern: each format delegates to a generator that declares
 *     which payload kinds it supports.
 *   - Consistent hierarchy:
 *       <outputDir> / <YYYY-MM-DD> / <command> / <format> / <lang> / <file>
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

import type { Report } from '@mcp-verify/core/domain/mcp-server/entities/validation.types';
import type { Language } from '@mcp-verify/core/domain/reporting/i18n';

// ---------------------------------------------------------------------------
// Payload discriminated union
// ---------------------------------------------------------------------------

export interface ValidationPayload {
  readonly kind: 'validation';
  readonly data: Report;
}

export interface DoctorPayload {
  readonly kind: 'doctor';
  readonly data: ReadonlyArray<DoctorSectionResult>;
}

export interface ComparisonPayload {
  readonly kind: 'compare';
  readonly data: {
    results: any[];
    analysis: any;
  };
}

export interface GenericPayload {
  readonly kind: 'generic';
  readonly data: Record<string, unknown>;
}

export type ReportPayload = ValidationPayload | DoctorPayload | ComparisonPayload | GenericPayload;

// ---------------------------------------------------------------------------
// Doctor domain types
// ---------------------------------------------------------------------------

export type DoctorCheckStatus = 'pass' | 'fail' | 'warn' | 'skip';

export interface DoctorCheckResult {
  readonly name: string;
  readonly status: DoctorCheckStatus;
  readonly value?: string;
  readonly message?: string;
}

export interface DoctorSectionResult {
  readonly title: string;
  readonly icon: string;
  readonly checks: ReadonlyArray<DoctorCheckResult>;
  readonly verboseLogs?: string[];
}

// ---------------------------------------------------------------------------
// Public API — options & result
// ---------------------------------------------------------------------------

export type ReportFormat = 'json' | 'html' | 'markdown' | 'sarif' | 'txt' | 'all';

export interface ReportSaveOptions {
  outputDir?: string;
  formats?: ReportFormat[];
  language?: Language;
  filenamePrefix?: string;
  organizeByFormat?: boolean;
  includeRawSession?: boolean;
  rawSession?: unknown;
  baselineComparison?: any; // Kept for validation reports
}

export interface SavedReports {
  timestamp: string;
  baseFilename: string;
  paths: {
    json?: string;
    html?: string;
    markdown?: string;
    sarif?: string;
    txt?: string;
    rawSession?: string;
  };
  errors: Array<{ format: string; message: string }>;
}

// ---------------------------------------------------------------------------
// ReportingService
// ---------------------------------------------------------------------------

export class ReportingService {
  private static htmlGenerator: any = null;
  private static sarifGenerator: any = null;
  private static markdownGenerator: any = null;
  private static textGenerator: any = null;

  static async saveReport(
    payload: ReportPayload,
    options: ReportSaveOptions = {}
  ): Promise<SavedReports> {
    const {
      outputDir = './reports',
      formats = ['json'],
      language = 'en',
      filenamePrefix = 'report',
      organizeByFormat = true,
      includeRawSession = false,
      rawSession,
      baselineComparison,
    } = options;

    const command = this.commandFromKind(payload.kind);
    const effectiveFormats = formats.includes('all')
      ? ['json', 'html', 'markdown', 'sarif', 'txt'] as ReportFormat[]
      : formats;

    const now = new Date();
    const dateDir = now.toISOString().split('T')[0];
    const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(11, 19);
    const baseFilename = `${filenamePrefix}-${timestamp}`;

    const result: SavedReports = {
      timestamp,
      baseFilename,
      paths: {},
      errors: [],
    };

    const resolvedOutputDir = path.resolve(outputDir);

    const getFormatDir = (format: string): string => {
      const dir = organizeByFormat
        ? path.join(resolvedOutputDir, dateDir, command, format, language)
        : path.join(resolvedOutputDir, dateDir);
      fs.mkdirSync(dir, { recursive: true });
      return dir;
    };

    // 1. Save JSON (Universal)
    if (effectiveFormats.includes('json')) {
      try {
        const p = path.join(getFormatDir('json'), `${baseFilename}.json`);
        fs.writeFileSync(p, JSON.stringify(payload.data, null, 2));
        result.paths.json = p;
      } catch (e: any) {
        result.errors.push({ format: 'json', message: e.message });
      }
    }

    // 2. Save Markdown (Graceful fallback)
    if (effectiveFormats.includes('markdown')) {
      try {
        const content = await this.renderMarkdown(payload, language);
        const p = path.join(getFormatDir('markdown'), `${baseFilename}.md`);
        fs.writeFileSync(p, content);
        result.paths.markdown = p;
      } catch (e: any) {
        result.errors.push({ format: 'markdown', message: e.message });
      }
    }

    // 3. Save Text (Professional ASCII)
    if (effectiveFormats.includes('txt')) {
      try {
        const content = await this.renderText(payload, language);
        const p = path.join(getFormatDir('txt'), `${baseFilename}.txt`);
        fs.writeFileSync(p, content);
        result.paths.txt = p;
      } catch (e: any) {
        result.errors.push({ format: 'txt', message: e.message });
      }
    }

    // 4. HTML & SARIF (Validation only)
    if (payload.kind === 'validation') {
      await this.loadGenerators();
      
      if (effectiveFormats.includes('html') && this.htmlGenerator) {
        try {
          const content = this.htmlGenerator.generate(payload.data, language, baselineComparison);
          const p = path.join(getFormatDir('html'), `${baseFilename}.html`);
          fs.writeFileSync(p, content);
          result.paths.html = p;
        } catch (e: any) {
          result.errors.push({ format: 'html', message: e.message });
        }
      }

      if (effectiveFormats.includes('sarif') && this.sarifGenerator) {
        try {
          const content = this.sarifGenerator.generate(payload.data, language);
          const p = path.join(getFormatDir('sarif'), `${baseFilename}.sarif`);
          fs.writeFileSync(p, content);
          result.paths.sarif = p;
        } catch (e: any) {
          result.errors.push({ format: 'sarif', message: e.message });
        }
      }
    }

    return result;
  }

  private static commandFromKind(kind: ReportPayload['kind']): string {
    switch (kind) {
      case 'validation': return 'validate';
      case 'doctor': return 'doctor';
      case 'compare': return 'compare';
      default: return 'general';
    }
  }

  private static async renderMarkdown(payload: ReportPayload, lang: Language): Promise<string> {
    if (payload.kind === 'doctor') {
      return this.renderDoctorMarkdown(payload.data);
    }

    if (payload.kind === 'compare') {
      return this.renderComparisonMarkdown(payload.data.results, payload.data.analysis, lang);
    }
    
    await this.loadGenerators();
    if (payload.kind === 'validation' && this.markdownGenerator) {
      return this.markdownGenerator.generate(payload.data, lang);
    }

    return `# Report\n\n\`\`\`json\n${JSON.stringify(payload.data, null, 2)}\n\`\`\``;
  }

  private static async renderText(payload: ReportPayload, lang: Language): Promise<string> {
    await this.loadGenerators();
    if (payload.kind === 'validation' && this.textGenerator) {
      return this.textGenerator.generate(payload.data, lang);
    }

    if (payload.kind === 'doctor') {
      // Basic text fallback for doctor if needed, or reuse markdown
      return this.renderDoctorMarkdown(payload.data).replace(/#|\||:-+:|`|/g, '');
    }

    return `REPORT KIND: ${payload.kind}\n\n${JSON.stringify(payload.data, null, 2)}`;
  }

  private static renderComparisonMarkdown(results: any[], analysis: any, lang: Language): string {
    const getScoreEmoji = (score: number) => {
      if (score >= 90) return '🟢';
      if (score >= 70) return '🟡';
      return '🔴';
    };

    const lines = [];
    lines.push('# ⚔️ MCP Server Comparison Matrix');
    lines.push('');
    lines.push(`**Date:** ${new Date().toLocaleString()}`);
    lines.push(`**Servers Analyzed:** ${results.length}`);
    lines.push('');

    lines.push('## 🏆 Executive Summary');
    if (analysis.mostSecure) {
      lines.push(`- **🛡️ Most Secure:** ${analysis.mostSecure.name} (**${analysis.mostSecure.scores.security}**/100)`);
    }
    if (analysis.highestQuality) {
      lines.push(`- **💎 Highest Quality:** ${analysis.highestQuality.name} (**${analysis.highestQuality.scores.quality}**/100)`);
    }
    lines.push(`- **Average Security:** ${analysis.avgSecurity}/100`);
    lines.push('');

    lines.push('## 📊 Comparison Table');
    lines.push('');
    lines.push('| Server | Security | Quality | Protocol | Findings | Status |');
    lines.push('| :--- | :---: | :---: | :---: | :---: | :---: |');

    for (const r of results) {
      if (r.status === 'validated') {
        const sec = `${getScoreEmoji(r.scores.security)} ${r.scores.security}`;
        const qual = `${getScoreEmoji(r.scores.quality)} ${r.scores.quality}`;
        const proto = `${getScoreEmoji(r.scores.protocol)} ${r.scores.protocol}`;
        const findings = r.findings.total;
        const status = r.scores.security < 70 ? '⚠️ Review' : '✅ Valid';

        lines.push(`| **${r.name}** | ${sec} | ${qual} | ${proto} | ${findings} | ${status} |`);
      } else {
        lines.push(`| **${r.name}** | ❌ Error | N/A | N/A | N/A | ❌ Failed |`);
      }
    }

    lines.push('');
    lines.push('## 📝 Detailed Insights');

    for (const r of results.filter(res => res.status === 'validated')) {
      lines.push(`### 🔹 ${r.name}`);
      lines.push(`- **Capabilities:** Tools: ${r.capabilities.tools}, Resources: ${r.capabilities.resources}, Prompts: ${r.capabilities.prompts}`);
      lines.push(`- **Summary:** ${r.llmSummary || 'No summary available.'}`);
      lines.push('');
    }

    return lines.join('\n');
  }

  private static renderDoctorMarkdown(sections: ReadonlyArray<DoctorSectionResult>): string {
    let md = `# 🩺 mcp-verify Diagnostic Report\n\n`;
    sections.forEach(s => {
      md += `## ${s.icon} ${s.title}\n\n`;
      md += `| Status | Check | Value | Message |\n| :--- | :--- | :--- | :--- |\n`;
      s.checks.forEach(c => {
        const icon = c.status === 'pass' ? '✅' : c.status === 'fail' ? '❌' : '⚠️';
        md += `| ${icon} | ${c.name} | \`${c.value || 'N/A'}\` | ${c.message || ''} |\n`;
      });
      if (s.verboseLogs && s.verboseLogs.length > 0) {
        md += `\n<details><summary>Logs</summary>\n\n\`\`\`\n${s.verboseLogs.map(l => l.replace(/\x1b\[[0-9;]*m/g, '')).join('\n')}\n\`\`\`\n</details>\n`;
      }
      md += `\n---\n`;
    });
    return md;
  }

  private static async loadGenerators() {
    if (this.htmlGenerator && this.sarifGenerator && this.markdownGenerator && this.textGenerator) return;

    if (!this.htmlGenerator) {
      try {
        const { HtmlReportGenerator } = await import('@mcp-verify/core/domain/reporting/html-generator');
        this.htmlGenerator = HtmlReportGenerator;
      } catch {}
    }
    if (!this.markdownGenerator) {
      try {
        const { MarkdownReportGenerator } = await import('@mcp-verify/core/domain/reporting/markdown-generator');
        this.markdownGenerator = MarkdownReportGenerator;
      } catch {}
    }
    if (!this.textGenerator) {
      try {
        const { TextReportGenerator } = await import('@mcp-verify/core/domain/reporting/text-generator');
        this.textGenerator = TextReportGenerator;
      } catch {}
    }
    if (!this.sarifGenerator) {
      try {
        const { SarifGenerator } = await import('@mcp-verify/core/domain/reporting/sarif-generator');
        this.sarifGenerator = SarifGenerator;
      } catch {}
    }
  }
}
