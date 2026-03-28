/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Timing Detector — v2.1 "Baseline-Protected"
 *
 * Detects time-based injection vulnerabilities (Blind SQLi, Blind Command
 * Injection, ReDoS) with three major improvements over v1:
 *
 *   1. Protected Baseline
 *      Anomalous responses are EXCLUDED from the rolling baseline.
 *      The baseline represents only "clean" traffic, so a flood of successful
 *      SLEEP injections never elevates the average and hides the attack.
 *
 *   2. Obfuscation-Aware Payload Recognition
 *      Payloads are normalised (URL-decoded, comment-stripped) before pattern
 *      matching, so variants like SLEEP[comment](5) or %53LEEP(5) are correctly
 *      classified as time-based and trigger the consistent-delay check.
 *
 *   3. Consecutive Streak Confirmation
 *      The detector tracks consecutive anomalies. Three or more anomalies in a
 *      row (without a clean response in between) escalate confidence to HIGH or
 *      CRITICAL, confirming a sustained injection rather than a fluke.
 *
 *   4. Engine Hint Integration
 *      When the FuzzerEngine passes an `EngineHint`, the detector uses the
 *      pre-computed `timing_anomaly` signal as corroborating evidence and
 *      the Engine's rolling baseline as a secondary reference.
 *
 * CWE-208: Observable Timing Discrepancy
 * CWE-89:  SQL Injection (time-based)
 * CWE-78:  OS Command Injection (time-based)
 */

import type {
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
  DetectionConfidence,
  DetectionSeverity,
} from './detector.interface';

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface TimingSample {
  readonly responseTimeMs: number;
  readonly payload: string;
  readonly timestamp: number;
  readonly isError: boolean;
  /** True when this sample was classified as anomalous and excluded from baseline. */
  readonly isAnomalous: boolean;
}

interface TimingAnomaly {
  readonly type: 'slow' | 'very-slow' | 'timeout-like' | 'consistent-delay';
  readonly ratio: number;
  readonly description: string;
  readonly severity: DetectionSeverity;
}

interface BaselineStats {
  readonly mean:   number;
  readonly stdDev: number;
  readonly median: number;
  readonly max:    number;
  /** The value actually used for ratio calculations (median or mean per config). */
  readonly active: number;
  /** How many clean (non-anomalous) samples contributed. */
  readonly cleanSamples: number;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface TimingConfig {
  /** Minimum clean samples needed before anomaly analysis begins (default: 5) */
  minSamples?: number;
  /** Ratio threshold for slow response (default: 3× baseline) */
  slowThreshold?: number;
  /** Ratio threshold for very-slow response (default: 5× baseline) */
  verySlowThreshold?: number;
  /** Absolute ms threshold to flag as timeout-like (default: 10 000ms) */
  timeoutThreshold?: number;
  /** Enable consistent-delay check for time-based payloads (default: true) */
  detectConsistentDelay?: boolean;
  /** Fallback expected delay when none can be extracted from payload (default: 5 000ms) */
  expectedDelayMs?: number;
  /** Tolerance around the expected delay in ms (default: 1 500ms) */
  delayTolerance?: number;
  /** Initial samples to skip for cold-start compensation (default: 3) */
  warmupSamples?: number;
  /** Maximum clean samples in the rolling baseline window (default: 30) */
  windowSize?: number;
  /** Use median instead of mean as the baseline reference (default: true) */
  useMedian?: boolean;
  /**
   * Consecutive anomaly streak required to escalate confidence to HIGH/CRITICAL.
   * Default: 3
   */
  confirmationStreak?: number;
  /**
   * Ratio above which a sample is considered anomalous and excluded from the
   * protected baseline (default: 2.5× — slightly below slowThreshold so
   * borderline cases are still excluded).
   */
  anomalyExclusionRatio?: number;
}

// ---------------------------------------------------------------------------
// Obfuscation-Aware Pattern Matching
// ---------------------------------------------------------------------------

/**
 * Normalise a payload string before pattern matching so obfuscated variants
 * are recognised:
 *   - URL-decode (single and double pass to catch double-encoding)
 *   - Strip SQL comments (`/* ... * /`, `--`, `#`)
 *   - Collapse whitespace variants (tabs, newlines, multiple spaces)
 *   - Upper-case for case-insensitive matching
 */
function normalisePayload(raw: string): string {
  let s = raw;

  // Double URL decode (%2553 → %53 → S etc.)
  try { s = decodeURIComponent(s); } catch { /* keep as-is */ }
  try { s = decodeURIComponent(s); } catch { /* keep as-is */ }

  // Strip SQL block comments (/**/)
  s = s.replace(/\/\*.*?\*\//gs, ' ');

  // Strip SQL line comments (-- ..., # ...)
  s = s.replace(/--[^\n]*/g, ' ').replace(/#[^\n]*/g, ' ');

  // Collapse whitespace
  s = s.replace(/\s+/g, ' ').trim();

  return s.toUpperCase();
}

/**
 * Patterns matched against the NORMALISED payload.
 * Each entry captures the delay value in group 1 (or group 2 for WAITFOR).
 */
const TIME_BASED_PATTERNS: ReadonlyArray<{
  pattern:  RegExp;
  /** Index of the capture group containing the delay (seconds). */
  delayGroup: number;
  /** Multiply group value by this to get milliseconds. */
  multiplierMs: number;
  cweId: string;
}> = [
  // MySQL SLEEP(N)
  {
    pattern:      /\bSLEEP\s*\(\s*(\d+(?:\.\d+)?)\s*\)/,
    delayGroup:   1,
    multiplierMs: 1_000,
    cweId:        'CWE-89',
  },
  // MSSQL WAITFOR DELAY 'H:M:S'
  {
    pattern:      /\bWAITFOR\s+DELAY\s+'(\d{1,2}):(\d{2}):(\d{2})'/,
    delayGroup:   1, // special-cased below
    multiplierMs: 0, // computed separately
    cweId:        'CWE-89',
  },
  // PostgreSQL pg_sleep(N)
  {
    pattern:      /\bPG_SLEEP\s*\(\s*(\d+(?:\.\d+)?)\s*\)/,
    delayGroup:   1,
    multiplierMs: 1_000,
    cweId:        'CWE-89',
  },
  // Oracle DBMS_LOCK.SLEEP(N)
  {
    pattern:      /\bDBMS_LOCK\.SLEEP\s*\(\s*(\d+(?:\.\d+)?)\s*\)/,
    delayGroup:   1,
    multiplierMs: 1_000,
    cweId:        'CWE-89',
  },
  // Unix: sleep N
  {
    pattern:      /\bSLEEP\s+(\d+)/,
    delayGroup:   1,
    multiplierMs: 1_000,
    cweId:        'CWE-78',
  },
  // Windows: timeout /T N
  {
    pattern:      /\bTIMEOUT\s+\/T\s+(\d+)/,
    delayGroup:   1,
    multiplierMs: 1_000,
    cweId:        'CWE-78',
  },
  // Ping-based timing: ping -c N / ping -n N
  {
    pattern:      /\bPING\s+-[CN]\s+(\d+)/,
    delayGroup:   1,
    multiplierMs: 1_000,
    cweId:        'CWE-78',
  },
];

interface TimeBasedMatch {
  readonly expectedDelayMs: number;
  readonly cweId: string;
}

/** Returns the expected delay in ms if the payload is time-based, else null. */
function matchTimeBasedPayload(raw: string): TimeBasedMatch | null {
  const normalised = normalisePayload(raw);

  for (const entry of TIME_BASED_PATTERNS) {
    const m = normalised.match(entry.pattern);
    if (!m) continue;

    // Special-case: WAITFOR DELAY 'H:M:S'
    if (/WAITFOR/.test(entry.pattern.source) && m[1] && m[2] && m[3]) {
      const ms = (parseInt(m[1], 10) * 3_600 +
                  parseInt(m[2], 10) * 60   +
                  parseInt(m[3], 10)) * 1_000;
      return { expectedDelayMs: Math.min(ms, 30_000), cweId: entry.cweId };
    }

    const raw_val = parseFloat(m[entry.delayGroup] ?? '0');
    if (isNaN(raw_val)) continue;

    return {
      expectedDelayMs: Math.min(raw_val * entry.multiplierMs, 30_000),
      cweId:           entry.cweId,
    };
  }

  return null;
}

/** Determine CWE from payload category or payload content. */
function resolveCwe(payload: string, category?: string): string {
  if (category === 'cmd-injection') return 'CWE-78';
  if (category === 'sqli')          return 'CWE-89';
  const m = matchTimeBasedPayload(payload);
  return m?.cweId ?? 'CWE-208';
}

// ---------------------------------------------------------------------------
// Per-tool state
// ---------------------------------------------------------------------------

interface ToolState {
  /** ALL samples (clean and anomalous), for debugging and getStats(). */
  allSamples: TimingSample[];
  /**
   * Clean baseline samples only.
   * Anomalous responses are NEVER written here — this is the fix for
   * "baseline poisoning" where a flood of successful attacks raises the average.
   */
  cleanSamples: TimingSample[];
  /** List of all detected anomalies in arrival order. */
  anomalies: TimingAnomaly[];
  /**
   * Number of anomalies detected IN A ROW without a clean response in between.
   * Reset to 0 whenever a non-anomalous response is observed.
   */
  consecutiveStreak: number;
  /** Total clean responses seen (used for warmup gating). */
  cleanCount: number;
}

// ---------------------------------------------------------------------------
// TimingDetector v2.1
// ---------------------------------------------------------------------------

export class TimingDetector implements IVulnerabilityDetector {
  readonly id          = 'timing';
  readonly name        = 'Timing Attack Detector';
  readonly description = 'Detects time-based injection (Blind SQLi, Blind Cmd Injection, ReDoS). CWE-208/89/78';
  readonly categories  = ['timing', 'blind-injection', 'sqli', 'cmd-injection', 'redos'];
  readonly enabledByDefault = true;

  private readonly cfg: Required<TimingConfig>;
  private readonly state: Map<string, ToolState> = new Map();

  constructor(config: TimingConfig = {}) {
    this.cfg = {
      minSamples:           config.minSamples           ?? 5,
      slowThreshold:        config.slowThreshold        ?? 3,
      verySlowThreshold:    config.verySlowThreshold    ?? 5,
      timeoutThreshold:     config.timeoutThreshold     ?? 10_000,
      detectConsistentDelay: config.detectConsistentDelay ?? true,
      expectedDelayMs:      config.expectedDelayMs      ?? 5_000,
      delayTolerance:       config.delayTolerance       ?? 1_500,
      warmupSamples:        config.warmupSamples        ?? 3,
      windowSize:           config.windowSize           ?? 30,
      useMedian:            config.useMedian            ?? true,
      confirmationStreak:   config.confirmationStreak   ?? 3,
      anomalyExclusionRatio: config.anomalyExclusionRatio ?? 2.5,
    };
  }

  isApplicable(_category: string): boolean {
    // Run on all responses to maintain a universal baseline
    return true;
  }

  // -------------------------------------------------------------------------
  // Main detection entry point
  // -------------------------------------------------------------------------

  detect(context: DetectorContext): DetectionResult {
    const { toolName, responseTimeMs, isError, engineHint } = context;

    const payloadStr = typeof context.payload === 'string'
      ? context.payload
      : JSON.stringify(context.payload);

    const ts = this.getOrCreateToolState(toolName);

    // ── Compute protected baseline (before recording this sample) ───────────
    const stats = this.computeProtectedBaseline(ts);

    // ── Classify this response ───────────────────────────────────────────────
    const isWarmingUp = ts.cleanCount < this.cfg.warmupSamples + this.cfg.minSamples;

    if (isWarmingUp) {
      // During warm-up we accept all non-anomalous samples unconditionally
      ts.cleanSamples.push(this.makeSample(responseTimeMs, payloadStr, isError, false));
      ts.allSamples.push(ts.cleanSamples[ts.cleanSamples.length - 1]);
      if (!isError) ts.cleanCount++;
      return this.notDetected();
    }

    if (!stats) {
      return this.notDetected();
    }

    // ── Detect anomaly ───────────────────────────────────────────────────────
    const timeBased = matchTimeBasedPayload(payloadStr);
    const anomaly   = this.detectAnomaly(responseTimeMs, stats, payloadStr, timeBased, engineHint);

    // ── Protected baseline update ────────────────────────────────────────────
    // The key fix: only non-anomalous responses feed the clean baseline.
    const ratio      = stats.active > 0 ? responseTimeMs / stats.active : 0;
    const isAnomalous = anomaly !== null || ratio >= this.cfg.anomalyExclusionRatio;

    const sample = this.makeSample(responseTimeMs, payloadStr, isError, isAnomalous);
    ts.allSamples.push(sample);

    if (!isAnomalous && !isError) {
      ts.cleanSamples.push(sample);
      // Enforce window size on clean samples only
      if (ts.cleanSamples.length > this.cfg.warmupSamples + this.cfg.windowSize) {
        ts.cleanSamples.splice(0, 1);
      }
      ts.cleanCount++;
      ts.consecutiveStreak = 0; // clean response resets the streak
    }

    // ── Build detection result ───────────────────────────────────────────────
    if (!anomaly) {
      return this.notDetected();
    }

    ts.anomalies.push(anomaly);
    ts.consecutiveStreak++;

    // Escalate confidence based on consecutive streak and anomaly type
    const finding = this.escalateConfidence(anomaly, ts, payloadStr, timeBased, engineHint);

    return {
      detectorId:        this.id,
      detected:          true,
      vulnerabilityType: finding.vulnerabilityType,
      severity:          finding.severity,
      confidence:        finding.confidence,
      description:       finding.description,
      evidence: {
        payload:         context.payload,
        response:        context.response,
        matchedPatterns: finding.matchedPatterns,
      },
      remediation:  this.buildRemediation(anomaly.type, payloadStr, timeBased),
      cweId:        resolveCwe(payloadStr, engineHint?.originalCategory),
      owaspCategory: 'A03:2021-Injection',
    };
  }

  // -------------------------------------------------------------------------
  // Protected baseline computation
  // -------------------------------------------------------------------------

  /**
   * Build stats from CLEAN samples only (anomalous responses excluded).
   * Returns null if not enough clean samples have been collected yet.
   */
  private computeProtectedBaseline(ts: ToolState): BaselineStats | null {
    // Skip warmup samples, take last windowSize
    const afterWarmup = ts.cleanSamples.slice(this.cfg.warmupSamples);
    const windowed    = afterWarmup.slice(-this.cfg.windowSize);
    const data        = windowed.filter(s => !s.isError).map(s => s.responseTimeMs);

    if (data.length < this.cfg.minSamples) return null;

    return this.calcStats(data);
  }

  // -------------------------------------------------------------------------
  // Anomaly detection
  // -------------------------------------------------------------------------

  private detectAnomaly(
    responseTimeMs: number,
    stats: BaselineStats,
    payload: string,
    timeBased: TimeBasedMatch | null,
    hint?: DetectorContext['engineHint']
  ): TimingAnomaly | null {

    const ratio = stats.active > 0 ? responseTimeMs / stats.active : 0;

    // Jitter protection: don't flag anomalies on ultra-fast responses (e.g. 1ms -> 3ms)
    // because network/OS jitter makes these ratios unreliable.
    const minDuration = 200;

    // ── 1. Absolute timeout threshold ───────────────────────────────────────
    if (responseTimeMs >= this.cfg.timeoutThreshold) {
      return {
        type:        'timeout-like',
        ratio,
        description: `Response time (${responseTimeMs}ms) exceeds timeout threshold (${this.cfg.timeoutThreshold}ms)`,
        severity:    'high',
      };
    }

    // ── 2. Consistent delay matching a time-based payload ───────────────────
    // Checked BEFORE the generic ratio checks because it provides the highest
    // confidence signal and should be reported with the most specific type.
    if (this.cfg.detectConsistentDelay && timeBased) {
      const expectedMs  = timeBased.expectedDelayMs || this.cfg.expectedDelayMs;
      const actualDelay = responseTimeMs - stats.active;
      const delta       = Math.abs(actualDelay - expectedMs);

      if (delta <= this.cfg.delayTolerance) {
        return {
          type:        'consistent-delay',
          ratio,
          description: `Delay of ~${actualDelay.toFixed(0)}ms matches injected delay of ${expectedMs}ms (Δ${delta.toFixed(0)}ms, tolerance ${this.cfg.delayTolerance}ms)`,
          severity:    'critical',
        };
      }
    }

    // ── 3. Very-slow threshold ───────────────────────────────────────────────
    if (ratio >= this.cfg.verySlowThreshold && responseTimeMs > minDuration) {
      return {
        type:        'very-slow',
        ratio,
        description: `Response ${ratio.toFixed(1)}× slower than protected baseline (${responseTimeMs}ms vs ${stats.active.toFixed(0)}ms)`,
        severity:    'high',
      };
    }

    // ── 4. Slow threshold ────────────────────────────────────────────────────
    if (ratio >= this.cfg.slowThreshold && responseTimeMs > minDuration) {
      return {
        type:        'slow',
        ratio,
        description: `Response ${ratio.toFixed(1)}× slower than protected baseline (${responseTimeMs}ms vs ${stats.active.toFixed(0)}ms)`,
        severity:    'medium',
      };
    }

    // ── 5. Engine hint corroboration ─────────────────────────────────────────
    // If the Engine already flagged a timing_anomaly but our ratio-based checks
    // didn't fire (e.g. baseline is stale), trust the Engine and emit low-confidence.
    if (hint?.isAnomaly && hint.anomalyReasons?.includes('timing_anomaly')) {
      return {
        type:        'slow',
        ratio,
        description: `Engine flagged timing anomaly (${responseTimeMs}ms, engine baseline ~${hint.engineBaselineMs?.toFixed(0) ?? '?'}ms)`,
        severity:    'low',
      };
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // Confidence escalation via consecutive streak
  // -------------------------------------------------------------------------

  private escalateConfidence(
    anomaly:   TimingAnomaly,
    ts:        ToolState,
    payload:   string,
    timeBased: TimeBasedMatch | null,
    hint?:     DetectorContext['engineHint']
  ): {
    vulnerabilityType: string;
    severity:          DetectionSeverity;
    confidence:        DetectionConfidence;
    description:       string;
    matchedPatterns:   string[];
  } {
    const streak   = ts.consecutiveStreak;
    const required = this.cfg.confirmationStreak;

    // Engine hint: mutation payloads from timing-probe strategy provide
    // independent corroboration even with streak < required
    const engineCorroborates =
      hint?.isMutation === true &&
      (hint.mutationStrategy === 'timing-probe' || hint.mutationStrategy === 'sql-depth') &&
      hint.anomalyReasons?.includes('timing_anomaly') === true;

    // ── Definite: consistent-delay + (streak >= required OR engine confirms)
    if (anomaly.type === 'consistent-delay') {
      const confirmed = streak >= required || engineCorroborates;
      return {
        vulnerabilityType: 'Time-Based Injection (Confirmed)',
        severity:          'critical',
        confidence:        confirmed ? 'definite' : 'high',
        description:       confirmed
          ? `✅ Blind time-based injection CONFIRMED: ${anomaly.description}. ` +
            `${streak} consecutive anomalies${engineCorroborates ? ' + Engine corroboration' : ''}.`
          : `🔴 Strong timing signal: ${anomaly.description}. Streak: ${streak}/${required}.`,
        matchedPatterns: [anomaly.type, timeBased ? 'time-based-payload' : 'timing-ratio'],
      };
    }

    // ── High: streak >= required threshold
    if (streak >= required) {
      const isTimingMutation = hint?.mutationStrategy === 'timing-probe';
      return {
        vulnerabilityType: timeBased ? 'Time-Based Injection' : 'Persistent Timing Anomaly',
        severity:          streak >= required * 2 ? 'critical' : 'high',
        confidence:        'high',
        description:       `⚠️  ${streak} consecutive timing anomalies — likely sustained injection. ` +
                           anomaly.description +
                           (isTimingMutation ? ' [Confirmed by mutation probe]' : ''),
        matchedPatterns: [anomaly.type, `streak-${streak}`],
      };
    }

    // ── Medium: engine corroborates or payload is time-based but streak low
    if (engineCorroborates || (timeBased && streak >= 2)) {
      return {
        vulnerabilityType: 'Timing Anomaly (Probable Injection)',
        severity:          'medium',
        confidence:        'medium',
        description:       `⚡ Timing anomaly: ${anomaly.description}. ` +
                           (engineCorroborates ? 'Engine mutation confirms.' : `Streak: ${streak}.`),
        matchedPatterns: [anomaly.type],
      };
    }

    // ── Low: single anomaly, no corroboration
    return {
      vulnerabilityType: 'Timing Anomaly',
      severity:          anomaly.severity === 'critical' ? 'high' : anomaly.severity,
      confidence:        'low',
      description:       `🟡 Single timing anomaly: ${anomaly.description}. ` +
                         `Awaiting ${required - streak} more consecutive anomalies for confirmation.`,
      matchedPatterns: [anomaly.type],
    };
  }

  // -------------------------------------------------------------------------
  // Stats helpers
  // -------------------------------------------------------------------------

  private calcStats(times: number[]): BaselineStats {
    const n = times.length;
    if (n === 0) return { mean: 0, stdDev: 0, median: 0, max: 0, active: 0, cleanSamples: 0 };

    const sorted = [...times].sort((a, b) => a - b);
    const mean   = times.reduce((a, b) => a + b, 0) / n;
    const median = n % 2 === 0
      ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2
      : sorted[Math.floor(n / 2)];
    const variance = times.reduce((s, t) => s + (t - mean) ** 2, 0) / n;
    const stdDev   = Math.sqrt(variance);
    const max      = sorted[n - 1];
    const active   = this.cfg.useMedian ? median : mean;

    return { mean, stdDev, median, max, active, cleanSamples: n };
  }

  // -------------------------------------------------------------------------
  // State helpers
  // -------------------------------------------------------------------------

  private getOrCreateToolState(toolName: string): ToolState {
    if (!this.state.has(toolName)) {
      this.state.set(toolName, {
        allSamples:        [],
        cleanSamples:      [],
        anomalies:         [],
        consecutiveStreak: 0,
        cleanCount:        0,
      });
    }
    return this.state.get(toolName)!;
  }

  private makeSample(
    responseTimeMs: number,
    payload: string,
    isError: boolean,
    isAnomalous: boolean
  ): TimingSample {
    return { responseTimeMs, payload, timestamp: Date.now(), isError, isAnomalous };
  }

  private notDetected(): DetectionResult {
    return {
      detectorId:        this.id,
      detected:          false,
      vulnerabilityType: 'Timing Attack',
      severity:          'low',
      confidence:        'low',
      description:       'No timing anomaly detected',
      evidence:          { payload: '', response: null },
    };
  }

  // -------------------------------------------------------------------------
  // Remediation
  // -------------------------------------------------------------------------

  private buildRemediation(
    anomalyType: string,
    payload: string,
    timeBased: TimeBasedMatch | null
  ): string {
    if (anomalyType === 'consistent-delay') {
      if (timeBased?.cweId === 'CWE-89') {
        return 'Use parameterized queries / prepared statements. Never concatenate user-supplied ' +
               'values into SQL strings. Apply allowlist validation on all filter parameters.';
      }
      if (timeBased?.cweId === 'CWE-78') {
        return 'Avoid passing user input to shell commands. Use subprocess APIs with argument arrays ' +
               '(not shell interpolation). Validate all inputs against a strict allowlist.';
      }
    }

    return 'Investigate timing discrepancies. Ensure all database queries use parameterized ' +
           'statements and all system-command inputs are strictly validated before use.';
  }

  // -------------------------------------------------------------------------
  // Public utilities
  // -------------------------------------------------------------------------

  /** Reset all per-tool state — call between fuzzing sessions. */
  reset(): void {
    this.state.clear();
  }

  /** Inspect internal state for a specific tool (for tests and dashboards). */
  getStats(toolName: string): {
    totalSamples:       number;
    cleanSamples:       number;
    anomalousSamples:   number;
    consecutiveStreak:  number;
    anomalies:          number;
    baseline?: BaselineStats;
  } | null {
    const ts = this.state.get(toolName);
    if (!ts) return null;

    const anomalousSamples = ts.allSamples.filter(s => s.isAnomalous).length;
    const baseline         = this.computeProtectedBaseline(ts) ?? undefined;

    return {
      totalSamples:      ts.allSamples.length,
      cleanSamples:      ts.cleanSamples.length,
      anomalousSamples,
      consecutiveStreak: ts.consecutiveStreak,
      anomalies:         ts.anomalies.length,
      baseline,
    };
  }

  getConfig(): Required<TimingConfig> {
    return { ...this.cfg };
  }
}
