/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * TextReportGenerator - Component-Based Terminal UI
 *
 * Refactored architecture with clear separation of concerns:
 *   1. Layout primitives (rep, pad, centre, wordWrap)
 *   2. UI components (pure functions: data → formatted string)
 *   3. Data transformers (business logic, no formatting)
 *   4. Section composers (compose UI components)
 *   5. Main compositor (generate - orchestrates sections only)
 *
 * Design goals:
 *   - Pure functions: no side effects, no global state access
 *   - Composability: small functions combined into larger sections
 *   - Testability: each component can be unit tested in isolation
 *   - Zero runtime dependencies (pure string manipulation)
 *   - i18n via translations object passed as parameter
 *
 * Usage:
 *   const txt = TextReportGenerator.generate(report, 'en');
 *   fs.writeFileSync('report.txt', txt);
 */

import { translations, type Language } from './i18n';

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityFinding {
  rule:          string;
  severity:      Severity;
  message:       string;
  remediation?:  string;
  component:     string;
  cwe?:          string;
  payload?:      string;
  evidence?:     Record<string, unknown>;
}

export interface FeedbackStats {
  interestingResponsesFound: number;
  mutationsInjected:         number;
  timingAnomaliesDetected:   number;
  structuralDriftDetected:   number;
  serverCrashesDetected:     number;
}

export interface FuzzingReport {
  executed:       boolean;
  totalTests:     number;
  failedTests:    number;
  crashes:        number;
  feedbackStats?: FeedbackStats;
}

export interface Report {
  server_name:      string;
  url:              string;
  status:           'valid' | 'invalid';
  protocol_version: string;
  security: {
    score:    number;
    findings: SecurityFinding[];
  };
  quality: {
    score:  number;
    issues: unknown[];
  };
  tools?: {
    count:   number;
    valid:   number;
    invalid: number;
    items?:  Array<{ name: string; status: 'valid' | 'invalid' }>;
  };
  resources?: {
    count:   number;
    valid:   number;
    invalid: number;
  };
  prompts?: {
    count:   number;
    valid:   number;
    invalid: number;
  };
  fuzzing?:   FuzzingReport;
  timestamp:  string;
  gitInfo?:   { branch: string; hash: string };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PAGE_WIDTH = 70;
const LABEL_WIDTH = 16;
const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_ICON: Record<Severity, string> = {
  critical: '[!!!]',
  high:     '[!! ]',
  medium:   '[!  ]',
  low:      '[.  ]',
  info:     '[i  ]',
};

// ---------------------------------------------------------------------------
// 1. LAYOUT PRIMITIVES (low-level string manipulation)
// ---------------------------------------------------------------------------

/** Repeat a character N times. */
export const rep = (ch: string, n: number): string => ch.repeat(Math.max(0, n));

/** Pad or truncate `s` to exactly `width` characters (left-aligned). */
export const pad = (s: string, width: number): string =>
  s.length >= width ? s.slice(0, width) : s + rep(' ', width - s.length);

/** Centre `text` within `width` characters using `fill` on both sides. */
export function centre(text: string, width: number, fill = ' '): string {
  const gap   = Math.max(0, width - text.length);
  const left  = Math.floor(gap / 2);
  const right = gap - left;
  return rep(fill, left) + text + rep(fill, right);
}

/** Wrap a long string at word boundaries to fit within `maxWidth`. */
export function wordWrap(text: string, maxWidth: number, indent = ''): string {
  if (text.length <= maxWidth) return indent + text;
  const words   = text.split(' ');
  const lines: string[] = [];
  let   current = '';

  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > maxWidth && current) {
      lines.push(indent + current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(indent + current);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// 2. UI COMPONENTS (pure functions: data → formatted string)
// ---------------------------------------------------------------------------

/** Component: Title box with double-line border ╔══╗ */
export const TitleBox = (title: string): string => {
  const inner  = ` ${title} `;
  const width  = Math.max(PAGE_WIDTH, inner.length + 2);
  const top    = '╔' + rep('═', width - 2) + '╗';
  const mid    = '║' + centre(inner, width - 2) + '║';
  const bottom = '╚' + rep('═', width - 2) + '╝';
  return [top, mid, bottom].join('\n');
};

/** Component: Section header ╔══[ LABEL ]══╗ */
export const SectionHeader = (label: string): string => {
  const tag    = `[ ${label} ]`;
  const fill   = Math.max(0, PAGE_WIDTH - tag.length - 2);
  const left   = Math.floor(fill / 2);
  const right  = fill - left;
  return '╔' + rep('═', left) + tag + rep('═', right) + '╗';
};

/** Component: Horizontal separator lines */
export const Separator = {
  thin:   '  ' + rep('─', PAGE_WIDTH - 4),
  medium: '  ' + rep('·', PAGE_WIDTH - 4),
  thick:  '  ' + rep('═', PAGE_WIDTH - 4),
};

/** Component: Key-value row with consistent alignment */
export const KeyValueRow = (label: string, value: string, indent = '  '): string =>
  `${indent}${pad(label + ':', LABEL_WIDTH)} ${value}`;

/** Component: ASCII score gauge  ▓▓▓▓▓▓░░░░  75/100 */
export const ScoreGauge = (score: number, width = 20): string => {
  const clamped = Math.max(0, Math.min(100, score));
  const filled  = Math.round((clamped / 100) * width);
  const empty   = width - filled;
  return rep('▓', filled) + rep('░', empty) + `  ${clamped}/100`;
};

/** Component: Simple box table */
export interface TableOptions {
  headers: string[];
  rows: string[][];
  columnWidths: number[];
  title?: string;
}

export const Table = (options: TableOptions): string => {
  const { headers, rows, columnWidths, title } = options;
  const lines: string[] = [];

  const tableRow = (cells: string[]) =>
    '  │ ' + cells.map((v, i) => pad(v, columnWidths[i])).join(' │ ') + ' │';

  const tableSep = (ch = '─') =>
    '  ├─' + columnWidths.map(w => rep(ch, w)).join('─┼─') + '─┤';

  const tableTop = () =>
    '  ┌─' + columnWidths.map(w => rep('─', w)).join('─┬─') + '─┐';

  const tableBot = () =>
    '  └─' + columnWidths.map(w => rep('─', w)).join('─┴─') + '─┘';

  lines.push(tableTop());

  if (title) {
    const totalWidth = columnWidths.reduce((a, b) => a + b, 0) + (columnWidths.length - 1) * 3 + 4;
    lines.push('  │' + pad(centre(title, totalWidth - 2), totalWidth - 2) + '│');
    lines.push(tableSep('═'));
  }

  lines.push(tableRow(headers));
  lines.push(tableSep('═'));

  for (let i = 0; i < rows.length; i++) {
    lines.push(tableRow(rows[i]));
    if (i < rows.length - 1) {
      lines.push(tableSep());
    }
  }

  lines.push(tableBot());
  return lines.join('\n');
};

/** Component: Finding card with metadata */
export interface FindingCardData {
  index: number;
  icon: string;
  message: string;
  count: number;
  rule: string;
  component: string;
  cwe?: string;
  payloads: string[];
  remediation?: string;
  labels: {
    rule: string;
    component: string;
    cwe: string;
    remediation: string;
  };
}

export const FindingCard = (data: FindingCardData): string => {
  const lines: string[] = [];
  const indent = '       ';

  // Header
  const countLabel = data.count > 1 ? ` (x${data.count})` : '';
  lines.push(`  ${data.index}. ${data.icon} ${data.message}${countLabel}`);

  // Metadata
  lines.push(`${indent}${pad(data.labels.rule, 10)} ${data.rule}`);
  lines.push(`${indent}${pad(data.labels.component, 10)} ${data.component}`);

  if (data.cwe) {
    lines.push(`${indent}${pad(data.labels.cwe, 10)} ${data.cwe}`);
  }

  // Payloads
  if (data.payloads.length > 0) {
    const payloadLabel = data.payloads.length > 1 ? 'Payloads' : 'Payload';
    lines.push(`${indent}${pad(payloadLabel, 10)}`);

    const MAX_SHOWN = 5;
    const shown = data.payloads.slice(0, MAX_SHOWN);
    for (const p of shown) {
      lines.push(`${indent}  - ${p}`);
    }

    if (data.payloads.length > MAX_SHOWN) {
      lines.push(`${indent}  ... and ${data.payloads.length - MAX_SHOWN} more unique variants`);
    }
  }

  // Remediation
  if (data.remediation) {
    lines.push(`${indent}${data.labels.remediation}`);
    const maxWidth = PAGE_WIDTH - indent.length - 4;
    const wrapped  = wordWrap(data.remediation, maxWidth, `${indent}    `);
    lines.push(wrapped);
  }

  lines.push(Separator.medium);
  return lines.join('\n');
};

// ---------------------------------------------------------------------------
// 3. DATA TRANSFORMERS (business logic, no formatting)
// ---------------------------------------------------------------------------

/** Transform: Calculate risk label from score */
export const calculateRiskLabel = (score: number, t: typeof translations['en']): string => {
  if (score >= 90) return t.risk_level_low      ?? 'LOW RISK';
  if (score >= 70) return t.risk_level_medium   ?? 'MEDIUM RISK';
  if (score >= 50) return t.risk_level_high     ?? 'HIGH RISK';
  return                    t.risk_level_critical ?? 'CRITICAL RISK';
};

/** Transform: Format ISO timestamp */
export const formatTimestamp = (iso: string): string => {
  try {
    return new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  } catch {
    return iso;
  }
};

/** Transform: Group findings by severity */
export interface GroupedFinding {
  finding: SecurityFinding;
  count: number;
  payloads: Set<string>;
}

export const groupFindingsBySeverity = (findings: SecurityFinding[]): Map<Severity, Map<string, GroupedFinding>> => {
  const result = new Map<Severity, Map<string, GroupedFinding>>();

  for (const sev of SEVERITY_ORDER) {
    const group = findings.filter(f => f.severity === sev);
    if (group.length === 0) continue;

    const grouped = new Map<string, GroupedFinding>();

    for (const f of group) {
      const signature = `${f.rule}|${f.message}|${f.component}|${f.cwe || ''}`;
      if (!grouped.has(signature)) {
        grouped.set(signature, {
          finding: f,
          count: 0,
          payloads: new Set()
        });
      }
      const entry = grouped.get(signature)!;
      entry.count++;
      if (f.payload) entry.payloads.add(f.payload);
    }

    result.set(sev, grouped);
  }

  return result;
};

/** Transform: Calculate fuzzing pass rate */
export const calculateFuzzPassRate = (fuzzing: FuzzingReport): string => {
  if (fuzzing.totalTests === 0) return '0.0';
  const rate = ((fuzzing.totalTests - fuzzing.failedTests) / fuzzing.totalTests) * 100;
  return rate.toFixed(1);
};

// ---------------------------------------------------------------------------
// 4. SECTION COMPOSERS (compose UI components into sections)
// ---------------------------------------------------------------------------

const ExecutiveSummarySection = (report: Report, t: typeof translations['en']): string => {
  const statusLabel = report.status === 'valid'
    ? (t.status_valid   ?? 'VALID   ✓')
    : (t.status_invalid ?? 'INVALID ✗');

  const secScore  = report.security.score;
  const qualScore = report.quality.score;
  const risk      = calculateRiskLabel(secScore, t);
  const dateStr   = formatTimestamp(report.timestamp);

  const summaryTable = Table({
    headers: [],
    rows: [
      [`  ${pad((t as Record<string, string>).label_status ?? 'Status', 12)} ${statusLabel}`],
      [`  ${pad((t as Record<string, string>).label_security ?? 'Security', 12)} ${ScoreGauge(secScore, 16)}  (${risk})`],
      [`  ${pad((t as Record<string, string>).label_quality ?? 'Quality', 12)} ${ScoreGauge(qualScore, 16)}`],
      [`  ${pad((t as Record<string, string>).label_date ?? 'Date', 12)} ${dateStr}`],
    ],
    columnWidths: [PAGE_WIDTH - 4],
    title: (t as Record<string, string>).executive_summary ?? 'EXECUTIVE SUMMARY'
  });

  return summaryTable;
};

const TargetInfoSection = (report: Report, t: typeof translations['en']): string => {
  const lines: string[] = [];

  lines.push(SectionHeader((t as Record<string, string>).section_target ?? 'TARGET INFO'));
  lines.push('');
  lines.push(KeyValueRow((t as Record<string, string>).label_server   ?? 'Server',   report.server_name));
  lines.push(KeyValueRow((t as Record<string, string>).label_url      ?? 'URL',       report.url));
  lines.push(KeyValueRow((t as Record<string, string>).label_protocol ?? 'Protocol',  report.protocol_version));

  if (report.gitInfo) {
    lines.push(KeyValueRow((t as Record<string, string>).label_branch ?? 'Branch', report.gitInfo.branch));
    lines.push(KeyValueRow((t as Record<string, string>).label_commit ?? 'Commit', report.gitInfo.hash));
  }

  lines.push('');
  return lines.join('\n');
}

const SecurityFindingsSection = (report: Report, t: typeof translations['en']): string => {
  const lines: string[] = [];
  const findings = report.security.findings;

  lines.push(SectionHeader((t as Record<string, string>).section_security ?? 'SECURITY FINDINGS'));
  lines.push('');
  lines.push(KeyValueRow(
    (t as Record<string, string>).label_score ?? 'Score',
    `${report.security.score}/100  (${calculateRiskLabel(report.security.score, t)})`
  ));
  lines.push('');

  if (findings.length === 0) {
    lines.push(`  ${(t as Record<string, string>).no_findings ?? 'No security findings detected.'}`);
    lines.push('');
    return lines.join('\n');
  }

  const grouped = groupFindingsBySeverity(findings);
  let counter = 1;

  for (const sev of SEVERITY_ORDER) {
    const severityGroup = grouped.get(sev);
    if (!severityGroup) continue;

    const sevLabel = sev.toUpperCase();
    const groupSize = Array.from(severityGroup.values()).reduce((sum, g) => sum + g.count, 0);
    lines.push(`  ── ${sevLabel} (${groupSize}) ${'─'.repeat(Math.max(0, PAGE_WIDTH - 12 - sevLabel.length - String(groupSize).length))}`);
    lines.push('');

    for (const entry of severityGroup.values()) {
      const { finding, count, payloads } = entry;

      const cardData: FindingCardData = {
        index: counter++,
        icon: SEVERITY_ICON[finding.severity],
        message: finding.message,
        count,
        rule: finding.rule,
        component: finding.component,
        cwe: finding.cwe,
        payloads: Array.from(payloads),
        remediation: finding.remediation,
        labels: {
          rule:        (t as Record<string, string>).label_rule        ?? 'Rule',
          component:   (t as Record<string, string>).label_component   ?? 'Component',
          cwe:         (t as Record<string, string>).label_cwe         ?? 'CWE',
          remediation: (t as Record<string, string>).label_remediation ?? 'Remediation',
        }
      };

      lines.push(FindingCard(cardData));
    }

    lines.push('');
  }

  return lines.join('\n');
};

// ===========================================================================
// SECTION COMPOSERS
// ===========================================================================
// These functions compose UI components to build complete report sections.
// They handle data extraction and component orchestration only.

/** Composer: Smart Fuzzing Analysis section */
const FuzzingSection = (fuzzing: FuzzingReport, t: typeof translations['en']): string => {
  const lines: string[] = [];

  lines.push(SectionHeader((t as Record<string, string>).section_fuzzing ?? 'SMART FUZZING ANALYSIS'));
  lines.push('');

  if (!fuzzing.executed) {
    lines.push(`  ${(t as Record<string, string>).fuzzing_not_executed ?? 'Fuzzing was not executed in this session.'}`);
    lines.push('');
    return lines.join('\n');
  }

  const passRate = calculateFuzzPassRate(fuzzing);
  const failRate = (100 - parseFloat(passRate)).toFixed(1);

  lines.push(KeyValueRow((t as Record<string, string>).label_total_tests  ?? 'Total Tests',   String(fuzzing.totalTests)));
  lines.push(KeyValueRow((t as Record<string, string>).label_failed_tests ?? 'Failed Tests',  `${fuzzing.failedTests} (${failRate}%)`));
  lines.push(KeyValueRow((t as Record<string, string>).label_pass_rate    ?? 'Pass Rate',      `${passRate}%`));
  lines.push(KeyValueRow((t as Record<string, string>).label_crashes      ?? 'Crashes',        String(fuzzing.crashes)));

  if (fuzzing.feedbackStats) {
    const fb = fuzzing.feedbackStats;

    lines.push('');
    lines.push(Separator.thin);
    lines.push(`  ${(t as Record<string, string>).subsection_feedback_loop ?? 'FEEDBACK LOOP STATISTICS'}`);
    lines.push(Separator.thin);
    lines.push('');

    const feedbackTable = Table({
      headers: [],
      rows: [
        [(t as Record<string, string>).label_interesting_responses ?? 'Interesting Responses',   String(fb.interestingResponsesFound)],
        [(t as Record<string, string>).label_mutations_injected    ?? 'Mutations Injected',      String(fb.mutationsInjected)],
        [(t as Record<string, string>).label_timing_anomalies      ?? 'Timing Anomalies',        String(fb.timingAnomaliesDetected)],
        [(t as Record<string, string>).label_structural_drift      ?? 'Structural Drift',        String(fb.structuralDriftDetected)],
        [(t as Record<string, string>).label_server_crashes        ?? 'Server Crashes Detected', String(fb.serverCrashesDetected)],
      ],
      columnWidths: [38, 4],
      title: (t as Record<string, string>).label_smart_fuzzer ?? 'Smart Fuzzer — Engine Telemetry'
    });

    lines.push(feedbackTable);
  }

  lines.push('');
  return lines.join('\n');
};

/** Composer: Capabilities Overview section */
const CapabilitiesSection = (report: Report, t: typeof translations['en']): string => {
  const lines: string[] = [];

  lines.push(SectionHeader((t as Record<string, string>).section_capabilities ?? 'CAPABILITIES OVERVIEW'));
  lines.push('');

  const none = `  ${(t as Record<string, string>).capabilities_not_available ?? 'Capability data not available.'}`;

  if (!report.tools && !report.resources && !report.prompts) {
    lines.push(none);
    lines.push('');
    return lines.join('\n');
  }

  // Build table rows
  const tableRows: string[][] = [];
  if (report.tools) {
    tableRows.push([
      (t as Record<string, string>).label_tools ?? 'Tools',
      String(report.tools.count),
      String(report.tools.valid),
      String(report.tools.invalid)
    ]);
  }
  if (report.resources) {
    tableRows.push([
      (t as Record<string, string>).label_resources ?? 'Resources',
      String(report.resources.count),
      String(report.resources.valid),
      String(report.resources.invalid)
    ]);
  }
  if (report.prompts) {
    tableRows.push([
      (t as Record<string, string>).label_prompts ?? 'Prompts',
      String(report.prompts.count),
      String(report.prompts.valid),
      String(report.prompts.invalid)
    ]);
  }

  const capabilitiesTable = Table({
    headers: [
      (t as Record<string, string>).label_capability ?? 'Capability',
      (t as Record<string, string>).label_total      ?? 'Total',
      (t as Record<string, string>).label_valid      ?? 'Valid',
      (t as Record<string, string>).label_invalid    ?? 'Invalid',
    ],
    rows: tableRows,
    columnWidths: [24, 10, 10, 10]
  });

  lines.push(capabilitiesTable);

  // Optional: list first N tool names
  if (report.tools?.items && report.tools.items.length > 0) {
    const MAX_SHOWN = 10;
    lines.push('');
    lines.push(`  ${(t as Record<string, string>).label_tool_list ?? 'Tool list'}:`);
    const items = report.tools.items.slice(0, MAX_SHOWN);
    for (const item of items) {
      const icon = item.status === 'valid' ? '✓' : '✗';
      lines.push(`    ${icon} ${item.name}`);
    }
    if (report.tools.items.length > MAX_SHOWN) {
      lines.push(`    … ${report.tools.items.length - MAX_SHOWN} ${(t as Record<string, string>).label_more ?? 'more'}`);
    }
  }

  lines.push('');
  return lines.join('\n');
};

/** Composer: Footer section */
const FooterSection = (t: typeof translations['en']): string => {
  const msg = (t as Record<string, string>).footer_generated_by ?? 'Generated by mcp-verify — https://github.com/FinkTech/mcp-verify';
  return [
    rep('═', PAGE_WIDTH),
    centre(msg, PAGE_WIDTH),
    rep('═', PAGE_WIDTH),
    '',
  ].join('\n');
};

// ---------------------------------------------------------------------------
// TextReportGenerator
// ---------------------------------------------------------------------------

export class TextReportGenerator {
  /**
   * Generate a plain-text security report from a validated `Report` object.
   *
   * Main compositor - orchestrates section composers only, no string formatting.
   *
   * @param report  The report produced by `MCPValidator.generateReport()`
   * @param lang    Output language ('en' | 'es')
   * @returns       Multi-line string ready to write to a .txt file or stdout
   */
  static generate(report: Report, lang: Language = 'en'): string {
    const t = translations[lang] ?? translations['en'];
    const sections: string[] = [];

    // ── Header ─────────────────────────────────────────────────────────────
    sections.push('');
    sections.push(TitleBox(t.title ?? 'MCP-VERIFY SECURITY REPORT'));
    sections.push('');

    // ── Executive Summary ──────────────────────────────────────────────────
    sections.push(ExecutiveSummarySection(report, t));
    sections.push('');

    // ── Target Info ────────────────────────────────────────────────────────
    sections.push(TargetInfoSection(report, t));

    // ── Security Findings ──────────────────────────────────────────────────
    sections.push(SecurityFindingsSection(report, t));

    // ── Smart Fuzzing Analysis (optional) ──────────────────────────────────
    if (report.fuzzing) {
      sections.push(FuzzingSection(report.fuzzing, t));
    }

    // ── Capabilities Overview (optional) ───────────────────────────────────
    if (report.tools || report.resources || report.prompts) {
      sections.push(CapabilitiesSection(report, t));
    }

    // ── Footer ─────────────────────────────────────────────────────────────
    sections.push(FooterSection(t));

    return sections.join('\n');
  }
}
