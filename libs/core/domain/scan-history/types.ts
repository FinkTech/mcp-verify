/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { Report } from "../mcp-server/entities/validation.types";

/**
 * Represents a saved scan in history
 */
export interface ScanHistory {
  /** Unique scan identifier (e.g., scan_20250121_abc123) */
  scan_id: string;

  /** ISO timestamp when scan was performed */
  timestamp: string;

  /** Server name being scanned */
  server_name: string;

  /** Server version (if available) */
  version?: string;

  /** Security score (0-100) */
  security_score: number;

  /** Quality score (0-100) */
  quality_score: number;

  /** Protocol compliance score (0-100) */
  protocol_score: number;

  /** Total findings count */
  total_findings: number;

  /** Critical findings count */
  critical_count: number;

  /** High severity findings count */
  high_count: number;

  /** Medium severity findings count */
  medium_count: number;

  /** Low severity findings count */
  low_count: number;

  /** Whether this scan is marked as baseline */
  baseline: boolean;

  /** Optional git commit hash */
  git_commit?: string;

  /** Optional git branch name */
  git_branch?: string;

  /** Full validation report */
  report: Report;
}

/**
 * Comparison between two scans (regression detection)
 */
export interface RegressionReport {
  /** Current scan ID */
  current_scan: string;

  /** Baseline scan ID */
  baseline_scan: string;

  /** Current scan data */
  current: ScanHistory;

  /** Baseline scan data */
  baseline: ScanHistory;

  /** Whether security degradation was detected */
  degradation_detected: boolean;

  /** New findings (not in baseline) */
  new_issues: Array<{
    severity: string;
    message: string;
    component: string;
    ruleCode?: string;
  }>;

  /** Resolved findings (in baseline but not in current) */
  resolved_issues: Array<{
    severity: string;
    message: string;
    component: string;
    ruleCode?: string;
  }>;

  /** Score changes */
  score_change: {
    security: { before: number; after: number; delta: number };
    quality: { before: number; after: number; delta: number };
    protocol: { before: number; after: number; delta: number };
  };

  /** Findings count changes */
  findings_change: {
    total: { before: number; after: number; delta: number };
    critical: { before: number; after: number; delta: number };
    high: { before: number; after: number; delta: number };
    medium: { before: number; after: number; delta: number };
    low: { before: number; after: number; delta: number };
  };

  /** Overall recommendation */
  recommendation: "safe_to_deploy" | "review_required" | "blocking_issues";

  /** Human-readable summary */
  summary: string;

  /** Severity of the degradation */
  degradation_severity: "none" | "info" | "warning" | "blocking";
}

/**
 * Options for comparing scans
 */
export interface CompareOptions {
  /** Whether to include full findings details */
  includeDetails?: boolean;

  /** Minimum severity to consider (e.g., 'high' ignores medium/low changes) */
  minSeverity?: "critical" | "high" | "medium" | "low";

  /** Score degradation threshold to trigger warning (default: 10) */
  scoreThreshold?: number;
}

/**
 * Storage configuration
 */
export interface StorageConfig {
  /** Base directory for scan history (default: .mcp-verify/history) */
  baseDir?: string;

  /** Maximum number of scans to keep (default: 100) */
  maxScans?: number;

  /** Whether to compress old scans (default: false) */
  compress?: boolean;
}
