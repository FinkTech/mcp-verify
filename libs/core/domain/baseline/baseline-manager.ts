/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Baseline Manager
 *
 * Manages baseline reports for regression detection.
 * Allows teams to track if security/quality scores are improving or degrading.
 *
 * Use cases:
 *   - CI/CD: Fail build if score drops below baseline
 *   - Technical Debt: Accept current score as baseline, prevent regression
 *   - Progress Tracking: Compare current state vs initial audit
 *
 * @module libs/core/domain/baseline/baseline-manager
 */

import * as fs from 'fs';
import * as path from 'path';
import { t } from '@mcp-verify/shared';
import type { Report } from '../mcp-server/entities/validation.types';

export interface BaselineComparison {
  baseline: BaselineSnapshot;
  current: BaselineSnapshot;
  delta: {
    securityScore: number;
    qualityScore: number;
    newCriticalFindings: number;
    newHighFindings: number;
    fixedFindings: number;
  };
  status: 'improved' | 'unchanged' | 'degraded' | 'critical_degradation';
  message: string;
}

export interface BaselineSnapshot {
  timestamp: string;
  serverName: string;
  securityScore: number;
  qualityScore: number;
  protocolScore: number;
  toolCount: number;
  resourceCount: number;
  promptCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findings: Array<{
    ruleCode: string;
    message: string;
    severity: string;
    component: string;
  }>;
  findingHashes: string[]; // Keep for legacy/fast comparison
}

export class BaselineManager {
  /**
   * Save current report as baseline
   */
  static saveBaseline(report: Report, baselinePath: string): void {
    const snapshot = this.createSnapshot(report);

    // Ensure directory exists
    const dir = path.dirname(baselinePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(baselinePath, JSON.stringify(snapshot, null, 2));
  }

  /**
   * Load baseline from file
   */
  static loadBaseline(baselinePath: string): BaselineSnapshot | null {
    if (!fs.existsSync(baselinePath)) {
      return null;
    }

    try {
      const content = fs.readFileSync(baselinePath, 'utf-8');
      return JSON.parse(content) as BaselineSnapshot;
    } catch (error) {
      throw new Error(t('baseline_parse_error', { error: (error as Error).message }));
    }
  }

  /**
   * Compare current report against baseline
   */
  static compare(report: Report, baseline: BaselineSnapshot): BaselineComparison {
    const current = this.createSnapshot(report);

    // Calculate deltas
    const securityDelta = current.securityScore - baseline.securityScore;
    const qualityDelta = current.qualityScore - baseline.qualityScore;

    // Calculate new findings
    const baselineHashes = new Set(baseline.findingHashes);
    const currentHashes = new Set(current.findingHashes);

    const newFindings = current.findingHashes.filter(h => !baselineHashes.has(h));
    const fixedFindings = baseline.findingHashes.filter(h => !currentHashes.has(h));

    const newCriticalFindings = current.criticalCount - baseline.criticalCount;
    const newHighFindings = current.highCount - baseline.highCount;

    // Determine status
    let status: BaselineComparison['status'] = 'unchanged';
    let message = '';

    if (newCriticalFindings > 0) {
      status = 'critical_degradation';
      message = t('baseline_critical_degradation', { count: newCriticalFindings });
    } else if (securityDelta < -10 || qualityDelta < -10) {
      status = 'degraded';
      message = t('baseline_score_dropped', { sec: securityDelta.toFixed(1), qual: qualityDelta.toFixed(1) });
    } else if (securityDelta < 0 || qualityDelta < 0 || newHighFindings > 0) {
      status = 'degraded';
      message = t('baseline_degraded', { sec: securityDelta.toFixed(1), qual: qualityDelta.toFixed(1) });
    } else if (securityDelta > 5 || qualityDelta > 5 || fixedFindings.length > 0) {
      status = 'improved';
      message = t('baseline_improved', { sec: securityDelta.toFixed(1), qual: qualityDelta.toFixed(1), fixed: fixedFindings.length });
    } else {
      status = 'unchanged';
      message = t('baseline_no_changes');
    }

    return {
      baseline,
      current,
      delta: {
        securityScore: securityDelta,
        qualityScore: qualityDelta,
        newCriticalFindings: Math.max(0, newCriticalFindings),
        newHighFindings: Math.max(0, newHighFindings),
        fixedFindings: fixedFindings.length
      },
      status,
      message
    };
  }

  /**
   * Create snapshot from report
   */
  private static createSnapshot(report: Report): BaselineSnapshot {
    // Create hash for each finding (for change detection)
    const findingHashes = report.security.findings.map(f =>
      this.hashFinding(f.ruleCode || '', f.component, f.severity)
    );

    return {
      timestamp: report.timestamp,
      serverName: report.server_name,
      securityScore: report.security.score,
      qualityScore: report.quality.score,
      protocolScore: report.protocolCompliance?.score || 0,
      toolCount: report.tools.count,
      resourceCount: report.resources.count,
      promptCount: report.prompts.count,
      criticalCount: report.security.criticalCount || 0,
      highCount: report.security.highCount || 0,
      mediumCount: report.security.mediumCount || 0,
      lowCount: report.security.lowCount || 0,
      findings: report.security.findings.map(f => ({
        ruleCode: f.ruleCode || 'UNKNOWN',
        message: f.message,
        severity: f.severity,
        component: f.component
      })),
      findingHashes
    };
  }

  /**
   * Create a simple hash for a finding
   */
  private static hashFinding(ruleCode: string, component: string, severity: string): string {
    return `${ruleCode}:${component}:${severity}`;
  }

  /**
   * Check if comparison should fail CI/CD build
   */
  static shouldFailBuild(
    comparison: BaselineComparison,
    options: {
      failOnCritical?: boolean;
      failOnDegradation?: boolean;
      allowedScoreDrop?: number;
    } = {}
  ): boolean {
    const {
      failOnCritical = true,
      failOnDegradation = true,
      allowedScoreDrop = 5
    } = options;

    // Always fail on critical degradation if enabled
    if (failOnCritical && comparison.status === 'critical_degradation') {
      return true;
    }

    // Fail on any degradation if strict mode
    if (failOnDegradation && comparison.status === 'degraded') {
      // But allow small score drops if configured
      const securityDrop = Math.abs(Math.min(0, comparison.delta.securityScore));
      const qualityDrop = Math.abs(Math.min(0, comparison.delta.qualityScore));

      if (securityDrop > allowedScoreDrop || qualityDrop > allowedScoreDrop) {
        return true;
      }
    }

    return false;
  }
}
