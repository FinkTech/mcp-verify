/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Error Detector — v1.0
 *
 * Detects information-disclosure vulnerabilities that occur when the server
 * leaks internal error details in its response. Common triggers:
 *
 *   - Stack traces in JSON / HTML responses
 *   - Database error messages (SQL syntax errors, connection strings)
 *   - Internal file paths, class names, or framework version strings
 *   - Verbose error objects returned by unhandled exceptions
 *
 * This detector is specifically designed to complement the Smart Fuzzer's
 * `error_pattern_match` feedback-loop signal and the `MutationEngine`'s
 * `quote-variation` strategy, which are the most common triggers for
 * server-side information leakage.
 *
 * CWE-209: Generation of Error Message Containing Sensitive Information
 * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 * CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere
 */

import type {
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
  DetectionSeverity,
  DetectionConfidence,
} from "./detector.interface";

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

interface ErrorPattern {
  /** Regex applied to the serialised response body */
  readonly pattern: RegExp;
  readonly type: string;
  readonly severity: DetectionSeverity;
  readonly confidence: DetectionConfidence;
  readonly description: string;
  readonly cweId: string;
  readonly remediation: string;
}

/**
 * All patterns are matched against the full JSON-serialised response string.
 * More specific / higher-confidence patterns are listed first so the first
 * match provides the most accurate classification.
 */
const ERROR_PATTERNS: ReadonlyArray<ErrorPattern> = [
  // ── Stack traces ─────────────────────────────────────────────────────────

  {
    pattern: /at\s+\w[\w$.]*\s*\((?:[^)]*:\d+:\d+)\)/,
    type: "Stack Trace Leak",
    severity: "high",
    confidence: "definite",
    description:
      "Server response contains a JavaScript/Node.js stack trace with file paths and line numbers.",
    cweId: "CWE-209",
    remediation:
      "Disable verbose error output in production. Return a generic error ID instead of the full exception. " +
      "Use a global error handler (Express `errorHandler`, Fastify `setErrorHandler`) that strips stack frames.",
  },
  {
    pattern:
      /(?:Exception|Traceback|Caused by)[:\s].*(?:\n\s+at\s|\n\s+File\s)/,
    type: "Stack Trace Leak (Multi-line)",
    severity: "high",
    confidence: "definite",
    description:
      "Multi-line stack trace detected in response (Java, Python, or .NET format).",
    cweId: "CWE-209",
    remediation:
      "Configure exception handlers to log errors server-side and return opaque error codes to clients.",
  },

  // ── SQL error messages ───────────────────────────────────────────────────

  {
    pattern: /(?:SQL syntax|you have an error in your SQL syntax)/i,
    type: "SQL Syntax Error Leak",
    severity: "critical",
    confidence: "definite",
    description:
      "MySQL SQL syntax error message leaked in response — confirms injection point is active.",
    cweId: "CWE-89",
    remediation:
      "Use parameterized queries. Disable MySQL `sql_mode` verbose errors. " +
      "Catch database exceptions and return a generic message.",
  },
  {
    pattern: /ORA-\d{5}:/,
    type: "Oracle DB Error Leak",
    severity: "critical",
    confidence: "definite",
    description:
      "Oracle database error code leaked (ORA-XXXXX) — confirms direct SQL error propagation.",
    cweId: "CWE-89",
    remediation:
      "Wrap all DB calls in exception handlers. Return generic errors to the client.",
  },
  {
    pattern: /\bpg_exec\b|\bpsql:\s*ERROR:/i,
    type: "PostgreSQL Error Leak",
    severity: "critical",
    confidence: "definite",
    description: "PostgreSQL error message leaked in response.",
    cweId: "CWE-89",
    remediation:
      "Catch psycopg2 / pg errors server-side. Do not propagate `e.message` to responses.",
  },
  {
    pattern: /Microsoft\s+OLE\s+DB\s+Provider|Unclosed\s+quotation\s+mark/i,
    type: "MSSQL Error Leak",
    severity: "critical",
    confidence: "definite",
    description: "Microsoft SQL Server error message leaked in response.",
    cweId: "CWE-89",
    remediation:
      "Use parameterized queries with SqlCommand. Disable verbose errors in production IIS/ASP.NET.",
  },
  {
    pattern: /SQLITE_ERROR|no such table:|near ".*": syntax error/i,
    type: "SQLite Error Leak",
    severity: "high",
    confidence: "definite",
    description: "SQLite error message leaked in response.",
    cweId: "CWE-89",
    remediation: "Catch sqlite3 exceptions and return a generic error code.",
  },

  // ── Internal file paths ──────────────────────────────────────────────────

  {
    pattern:
      /(?:\/(?:home|usr|var|etc|opt|root|srv|app|src)\/[\w./\-]+|[A-Za-z]:\\[\w\\.\- ]+)\.\w{2,5}/,
    type: "Internal Path Disclosure",
    severity: "medium",
    confidence: "high",
    description:
      "Absolute file system path exposed in response (Unix or Windows format).",
    cweId: "CWE-497",
    remediation:
      "Sanitize error messages to remove file path information before returning them to clients.",
  },

  // ── Framework / runtime version disclosure ───────────────────────────────

  {
    pattern: /(?:Express|Fastify|Koa|Hapi|Nest)(?:JS)?\s+v?\d+\.\d+\.\d+/i,
    type: "Framework Version Disclosure",
    severity: "low",
    confidence: "high",
    description: "Web framework name and version string leaked in response.",
    cweId: "CWE-200",
    remediation:
      "Remove `X-Powered-By` headers and version strings from error responses.",
  },
  {
    pattern: /Node\.js\s+v\d+\.\d+\.\d+/i,
    type: "Runtime Version Disclosure",
    severity: "low",
    confidence: "high",
    description: "Node.js runtime version leaked in response.",
    cweId: "CWE-200",
    remediation:
      "Do not include runtime version info in error responses or headers.",
  },

  // ── Unhandled exception objects ──────────────────────────────────────────

  {
    pattern: /"(?:stack|stacktrace|trace)":\s*"[^"]{30,}"/i,
    type: "Exception Object Serialised",
    severity: "high",
    confidence: "high",
    description:
      "Error object with `stack` or `trace` field serialised directly into JSON response.",
    cweId: "CWE-209",
    remediation:
      "Use a response serialiser that strips `stack`, `trace`, and `code` fields from Error objects.",
  },
  {
    pattern:
      /"(?:message|error)":\s*"[^"]*(?:ENOENT|ECONNREFUSED|ETIMEDOUT|EPERM|EACCES)[^"]*"/i,
    type: "System Error Code Leak",
    severity: "medium",
    confidence: "high",
    description:
      "Node.js system error code (ENOENT, ECONNREFUSED, etc.) leaked in JSON response.",
    cweId: "CWE-209",
    remediation:
      "Map internal error codes to user-friendly messages before returning responses.",
  },

  // ── Secret / credential patterns ─────────────────────────────────────────

  {
    pattern:
      /(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\s*[:=]\s*["']?[^\s"',;]{8,}/i,
    type: "Credential Leak",
    severity: "critical",
    confidence: "medium",
    description:
      "Potential credential, secret, or API key value leaked in response.",
    cweId: "CWE-200",
    remediation:
      "Audit all error handlers to ensure secrets and environment variables are never serialised. " +
      "Rotate any exposed credentials immediately.",
  },
];

// ---------------------------------------------------------------------------
// ErrorDetector
// ---------------------------------------------------------------------------

export interface ErrorDetectorConfig {
  /**
   * If true, also scan request errors (isError: true) in addition to
   * successful responses. Default: true.
   */
  scanErrors?: boolean;
  /**
   * Minimum response body size in bytes to trigger scanning (avoids
   * processing trivial "ok" responses). Default: 10 bytes.
   */
  minBodySize?: number;
  /**
   * Categories for which this detector is applicable.
   * Default: all categories (runs on every payload).
   */
  applicableCategories?: string[];
}

export class ErrorDetector implements IVulnerabilityDetector {
  readonly id = "error-disclosure";
  readonly name = "Error & Information Disclosure Detector";
  readonly description =
    "Detects stack traces, SQL error messages, path disclosure, and credential leaks. CWE-209/200/497";
  readonly categories = [
    "sqli",
    "cmd-injection",
    "xss",
    "path-traversal",
    "ssti",
    "schema-confusion",
    "json-rpc",
  ];
  readonly enabledByDefault = true;

  private readonly cfg: Required<ErrorDetectorConfig>;

  constructor(config: ErrorDetectorConfig = {}) {
    this.cfg = {
      scanErrors: config.scanErrors ?? true,
      minBodySize: config.minBodySize ?? 10,
      applicableCategories: config.applicableCategories ?? [],
    };
  }

  isApplicable(category: string): boolean {
    if (this.cfg.applicableCategories.length === 0) return true;
    return this.cfg.applicableCategories.includes(category);
  }

  detect(context: DetectorContext): DetectionResult {
    // Optionally skip error responses (isError=true) if configured
    if (context.isError && !this.cfg.scanErrors) {
      return this.notDetected();
    }

    // Serialise the full response (or error) to a single string for pattern scanning
    const responseBody = this.serialiseResponse(context.response);
    const errorBody =
      context.isError && context.error ? context.error.message : "";
    const body = `${responseBody}\n${errorBody}`;

    if (body.trim().length < this.cfg.minBodySize) {
      return this.notDetected();
    }

    // Scan against all patterns — use the first (highest-priority) match
    for (const ep of ERROR_PATTERNS) {
      if (!ep.pattern.test(body)) continue;

      const payloadStr =
        typeof context.payload === "string"
          ? context.payload
          : JSON.stringify(context.payload);

      // Boost confidence if Engine already flagged error_pattern_match
      const hint = context.engineHint;
      const engineCorroborates =
        hint?.anomalyReasons?.includes("error_pattern_match") === true;
      const confidence: DetectionConfidence =
        engineCorroborates && ep.confidence !== "definite"
          ? this.upgradeConfidence(ep.confidence)
          : ep.confidence;

      return {
        detectorId: this.id,
        detected: true,
        vulnerabilityType: ep.type,
        severity: ep.severity,
        confidence,
        description:
          ep.description +
          (engineCorroborates
            ? " [Engine corroboration: error_pattern_match]"
            : ""),
        evidence: {
          payload: context.payload,
          response: context.response,
          matchedPatterns: [ep.pattern.source.slice(0, 80)],
        },
        remediation: ep.remediation,
        cweId: ep.cweId,
        owaspCategory: this.resolveOwasp(ep.cweId),
      };
    }

    return this.notDetected();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private serialiseResponse(response: unknown): string {
    if (response === null || response === undefined) return "";
    if (typeof response === "string") return response;
    try {
      return JSON.stringify(response);
    } catch {
      return String(response);
    }
  }

  private upgradeConfidence(current: DetectionConfidence): DetectionConfidence {
    const ladder: DetectionConfidence[] = ["low", "medium", "high", "definite"];
    const idx = ladder.indexOf(current);
    return idx < ladder.length - 1 ? ladder[idx + 1] : current;
  }

  private resolveOwasp(cweId: string): string {
    switch (cweId) {
      case "CWE-89":
        return "A03:2021-Injection";
      case "CWE-78":
        return "A03:2021-Injection";
      case "CWE-209":
      case "CWE-200":
      case "CWE-497":
        return "A05:2021-Security Misconfiguration";
      default:
        return "A05:2021-Security Misconfiguration";
    }
  }

  private notDetected(): DetectionResult {
    return {
      detectorId: this.id,
      detected: false,
      vulnerabilityType: "Error Disclosure",
      severity: "low",
      confidence: "low",
      description: "No error disclosure patterns detected in response",
      evidence: { payload: "", response: null },
    };
  }
}
