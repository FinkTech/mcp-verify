/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { ScanHistory, RegressionReport, CompareOptions } from './types';

/**
 * Detects security/quality regressions between scans
 */
export class RegressionDetector {
  /**
   * Compare two scans and detect regressions
   */
  static compare(current: ScanHistory, baseline: ScanHistory, options: CompareOptions = {}): RegressionReport {
    const scoreThreshold = options.scoreThreshold || 10;

    // Calculate score changes
    const scoreChange = {
      security: {
        before: baseline.security_score,
        after: current.security_score,
        delta: current.security_score - baseline.security_score,
      },
      quality: {
        before: baseline.quality_score,
        after: current.quality_score,
        delta: current.quality_score - baseline.quality_score,
      },
      protocol: {
        before: baseline.protocol_score,
        after: current.protocol_score,
        delta: current.protocol_score - baseline.protocol_score,
      },
    };

    // Calculate findings changes
    const findingsChange = {
      total: {
        before: baseline.total_findings,
        after: current.total_findings,
        delta: current.total_findings - baseline.total_findings,
      },
      critical: {
        before: baseline.critical_count,
        after: current.critical_count,
        delta: current.critical_count - baseline.critical_count,
      },
      high: {
        before: baseline.high_count,
        after: current.high_count,
        delta: current.high_count - baseline.high_count,
      },
      medium: {
        before: baseline.medium_count,
        after: current.medium_count,
        delta: current.medium_count - baseline.medium_count,
      },
      low: {
        before: baseline.low_count,
        after: current.low_count,
        delta: current.low_count - baseline.low_count,
      },
    };

    // Detect new and resolved issues
    const baselineFindings = baseline.report.security.findings.map((f) => ({
      severity: f.severity,
      message: f.message,
      component: f.component,
      ruleCode: f.ruleCode,
    }));

    const currentFindings = current.report.security.findings.map((f) => ({
      severity: f.severity,
      message: f.message,
      component: f.component,
      ruleCode: f.ruleCode,
    }));

    // Find new issues (in current but not in baseline)
    const newIssues = currentFindings.filter(
      (cf) => !baselineFindings.some((bf) => bf.message === cf.message && bf.component === cf.component)
    );

    // Find resolved issues (in baseline but not in current)
    const resolvedIssues = baselineFindings.filter(
      (bf) => !currentFindings.some((cf) => cf.message === bf.message && cf.component === bf.component)
    );

    // Determine degradation severity
    let degradationSeverity: 'none' | 'info' | 'warning' | 'blocking' = 'none';
    let degradationDetected = false;

    // BLOCKING: New critical issues
    if (findingsChange.critical.delta > 0) {
      degradationSeverity = 'blocking';
      degradationDetected = true;
    }
    // WARNING: Security score dropped significantly or new high severity issues
    else if (scoreChange.security.delta < -scoreThreshold || findingsChange.high.delta > 0) {
      degradationSeverity = 'warning';
      degradationDetected = true;
    }
    // INFO: Minor changes
    else if (
      scoreChange.security.delta < 0 ||
      findingsChange.medium.delta > 0 ||
      findingsChange.low.delta > 0
    ) {
      degradationSeverity = 'info';
      degradationDetected = true;
    }

    // Determine recommendation
    let recommendation: 'safe_to_deploy' | 'review_required' | 'blocking_issues';
    if (degradationSeverity === 'blocking') {
      recommendation = 'blocking_issues';
    } else if (degradationSeverity === 'warning') {
      recommendation = 'review_required';
    } else {
      recommendation = 'safe_to_deploy';
    }

    // Generate summary
    const summary = this.generateSummary(
      scoreChange,
      findingsChange,
      newIssues,
      resolvedIssues,
      degradationSeverity
    );

    return {
      current_scan: current.scan_id,
      baseline_scan: baseline.scan_id,
      current,
      baseline,
      degradation_detected: degradationDetected,
      new_issues: newIssues,
      resolved_issues: resolvedIssues,
      score_change: scoreChange,
      findings_change: findingsChange,
      recommendation,
      summary,
      degradation_severity: degradationSeverity,
    };
  }

  /**
   * Generate human-readable summary
   */
  private static generateSummary(
    scoreChange: RegressionReport['score_change'],
    findingsChange: RegressionReport['findings_change'],
    newIssues: RegressionReport['new_issues'],
    resolvedIssues: RegressionReport['resolved_issues'],
    severity: string
  ): string {
    const parts: string[] = [];

    // Security score change
    if (scoreChange.security.delta !== 0) {
      const direction = scoreChange.security.delta > 0 ? 'improved' : 'degraded';
      parts.push(
        `Security score ${direction} from ${scoreChange.security.before} to ${scoreChange.security.after} (${scoreChange.security.delta > 0 ? '+' : ''}${scoreChange.security.delta})`
      );
    }

    // New critical/high issues
    if (findingsChange.critical.delta > 0) {
      parts.push(`${findingsChange.critical.delta} new CRITICAL issue(s) detected`);
    }
    if (findingsChange.high.delta > 0) {
      parts.push(`${findingsChange.high.delta} new HIGH severity issue(s) detected`);
    }

    // Resolved issues
    if (resolvedIssues.length > 0) {
      parts.push(`${resolvedIssues.length} issue(s) resolved`);
    }

    // New issues details
    if (newIssues.length > 0 && newIssues.length <= 3) {
      parts.push(`New issues: ${newIssues.map((i) => `${i.severity} - ${i.message}`).join('; ')}`);
    } else if (newIssues.length > 3) {
      parts.push(`${newIssues.length} new issues detected (see details)`);
    }

    // Severity-based conclusion
    if (severity === 'blocking') {
      parts.push('⛔ BLOCKING: Critical issues must be fixed before deployment');
    } else if (severity === 'warning') {
      parts.push('⚠️  WARNING: Review required before deployment');
    } else if (severity === 'info') {
      parts.push('ℹ️  INFO: Minor changes detected');
    } else {
      parts.push('✅ No degradation detected');
    }

    return parts.join('. ');
  }

  /**
   * Analyze trend across multiple scans
   */
  static analyzeTrend(scans: ScanHistory[]): {
    trend: 'improving' | 'stable' | 'degrading';
    average_security_score: number;
    average_quality_score: number;
    total_scans: number;
    date_range: { from: string; to: string };
  } {
    if (scans.length === 0) {
      return {
        trend: 'stable',
        average_security_score: 0,
        average_quality_score: 0,
        total_scans: 0,
        date_range: { from: 'N/A', to: 'N/A' },
      };
    }

    // Sort by timestamp (oldest first for trend calculation)
    const sorted = [...scans].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    const avgSecurity = scans.reduce((sum, s) => sum + s.security_score, 0) / scans.length;
    const avgQuality = scans.reduce((sum, s) => sum + s.quality_score, 0) / scans.length;

    // Simple trend: compare first half vs second half
    const midpoint = Math.floor(sorted.length / 2);
    const firstHalf = sorted.slice(0, midpoint);
    const secondHalf = sorted.slice(midpoint);

    const firstHalfAvg =
      firstHalf.reduce((sum, s) => sum + s.security_score, 0) / (firstHalf.length || 1);
    const secondHalfAvg =
      secondHalf.reduce((sum, s) => sum + s.security_score, 0) / (secondHalf.length || 1);

    let trend: 'improving' | 'stable' | 'degrading';
    if (secondHalfAvg > firstHalfAvg + 5) {
      trend = 'improving';
    } else if (secondHalfAvg < firstHalfAvg - 5) {
      trend = 'degrading';
    } else {
      trend = 'stable';
    }

    return {
      trend,
      average_security_score: Math.round(avgSecurity * 10) / 10,
      average_quality_score: Math.round(avgQuality * 10) / 10,
      total_scans: scans.length,
      date_range: {
        from: sorted[0].timestamp,
        to: sorted[sorted.length - 1].timestamp,
      },
    };
  }
}
