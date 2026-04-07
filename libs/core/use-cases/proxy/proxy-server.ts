/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * McpProxyServer
 *
 * Pure network engine for the MCP Security Gateway.
 *
 * Design principle: this class is intentionally "silent" — it never writes to
 * stdout/stderr directly. All observable activity is surfaced via typed 'audit'
 * events so that any consumer (CLI, Web Dashboard, test harness, …) can react
 * without ever touching this file.
 */

import { EventEmitter } from "node:events";
import * as http from "http";
import * as crypto from "crypto";
import { t } from "@mcp-verify/shared";
import {
  ITransport,
  HttpTransport,
  StdioTransport,
} from "../../domain/transport";
import type { ProxyConfig, IGuardrail, InterceptResult } from "./proxy.types";
import { createScopedLogger } from "../../infrastructure/logging/logger";
import type {
  JsonValue,
  JsonRpcMessage,
  JsonObject,
  ToolCallParams,
} from "../../domain/shared/common.types";
import { isToolCall } from "../../domain/shared/common.types";
import { SecurityScanner } from "../../domain/security/security-scanner";
import { DEFAULT_CONFIG } from "../../domain/config/config.types";
import type {
  SecurityFinding,
  DiscoveryResult,
} from "../../domain/mcp-server/entities/validation.types";

// ---------------------------------------------------------------------------
// Public types – exported so consumers can strongly-type their event listeners
// ---------------------------------------------------------------------------

/** Discriminated union of every observable moment in the proxy lifecycle. */
export type AuditEventType =
  | "start"
  | "request"
  | "block"
  | "response"
  | "error"
  | "security-analysis"
  | "rate-limit-backoff"
  | "panic-mode-activated";

/** Fields present in every audit event. */
interface BaseAuditEvent {
  /** UTC instant at which the event occurred. */
  timestamp: Date;
  /** JSON-RPC message id, when available (null for notifications). */
  messageId?: string | number | null;
}

export interface StartAuditEvent extends BaseAuditEvent {
  type: "start";
  port: number;
  targetUrl: string;
}

export interface RequestAuditEvent extends BaseAuditEvent {
  type: "request";
  /** JSON-RPC method name (e.g. "tools/call", "resources/read"). */
  method: string;
  params: unknown;
}

export interface BlockAuditEvent extends BaseAuditEvent {
  type: "block";
  method: string;
  /** Human-readable reason provided by the blocking guardrail. */
  reason: string;
}

export interface ResponseAuditEvent extends BaseAuditEvent {
  type: "response";
  method: string;
  result: unknown;
}

export interface ErrorAuditEvent extends BaseAuditEvent {
  type: "error";
  method?: string;
  /** Original Error object – preserves stack traces for programmatic inspection. */
  cause: Error;
}

export interface SecurityAnalysisAuditEvent extends BaseAuditEvent {
  type: "security-analysis";
  method: string;
  /** Defense layer that performed the analysis (1=Fast, 2=Suspicious, 3=LLM) */
  layer: number;
  /** Analysis result: 'passed' or 'blocked' */
  result: "passed" | "blocked";
  /** Latency in milliseconds */
  latencyMs: number;
  /** Findings if blocked */
  findings?: SecurityFinding[];
}

export interface RateLimitBackoffAuditEvent extends BaseAuditEvent {
  type: "rate-limit-backoff";
  /** Backoff message with strike information */
  message: string;
}

export interface PanicModeAuditEvent extends BaseAuditEvent {
  type: "panic-mode-activated";
  /** Panic mode activation message */
  message: string;
}

/**
 * Sealed union of all possible audit payloads.
 * Consumers discriminate on the `type` field for exhaustive switch handling.
 */
export type ProxyAuditEvent =
  | StartAuditEvent
  | RequestAuditEvent
  | BlockAuditEvent
  | ResponseAuditEvent
  | ErrorAuditEvent
  | SecurityAnalysisAuditEvent
  | RateLimitBackoffAuditEvent
  | PanicModeAuditEvent;

// ---------------------------------------------------------------------------
// Typed EventEmitter declaration
// ---------------------------------------------------------------------------

/**
 * Strongly-typed event map for McpProxyServer.
 * Extending this interface keeps every emit() and on() call consistent.
 */
export interface McpProxyServerEvents {
  audit: (event: ProxyAuditEvent) => void;
}

// ---------------------------------------------------------------------------
// Custom error classes – thrown by start() so callers can handle them clearly
// without relying on string matching
// ---------------------------------------------------------------------------

/** Thrown when the configured port is already bound by another process. */
export class PortInUseError extends Error {
  constructor(public readonly port: number) {
    super(`Port ${port} is already in use.`);
    this.name = "PortInUseError";
  }
}

// ---------------------------------------------------------------------------
// McpProxyServer
// ---------------------------------------------------------------------------

export class McpProxyServer extends EventEmitter {
  private server: http.Server;
  private upstream: ITransport;
  private guardrails: IGuardrail[] = [];
  private clients: Set<http.ServerResponse> = new Set();
  private config: ProxyConfig;

  /**
   * Internal structured logger – kept only for low-level transport / SSE
   * lifecycle traces. These are NOT user-facing and must never replace audit
   * events for business-logic observability.
   */
  private logger = createScopedLogger("McpProxyServer");

  // ─────────────────────────────────────────────────────────────────────────────
  // Security Gateway: 3-Layer Defense Architecture
  // ─────────────────────────────────────────────────────────────────────────────

  /** Integrated security scanner (60 rules across 3 layers) */
  private scanner: SecurityScanner;

  /** Enable Layer 3 (LLM-based) deep analysis (opt-in, token-consuming) */
  private enableDeepAnalysis: boolean = false;

  /** Rule result cache for Layer 1 (TTL: 60s, max 1000 entries) */
  private ruleCache = new Map<
    string,
    { findings: SecurityFinding[]; timestamp: number }
  >();

  /** Panic stop state per client (Map<clientId, state>) */
  private rateLimitState = new Map<
    string,
    {
      strikes: number;
      inBackoff: boolean;
      blockedUntil: number;
      panicMode: boolean;
    }
  >();

  constructor(config: ProxyConfig) {
    super();
    this.config = config;

    // Initialize SecurityScanner ONCE (no memory leaks)
    this.scanner = new SecurityScanner(config.securityConfig ?? DEFAULT_CONFIG);

    // Enable LLM-based analysis if flag is set
    this.enableDeepAnalysis = Boolean(config.deepAnalysis);

    // Initialize upstream transport based on the target URL scheme
    if (config.targetUrl.startsWith("http")) {
      this.upstream = HttpTransport.create(config.targetUrl);
    } else {
      // Treat the target as a shell command: split into executable + args
      const parts = config.targetUrl.trim().split(/\s+/);
      const command = parts[0];
      const args = parts.slice(1);

      if (config.lang) {
        args.push("--lang", config.lang);
      }

      this.upstream = StdioTransport.create(command, args);
    }

    this.server = http.createServer((req, res) => this.handleRequest(req, res));
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  addGuardrail(guardrail: IGuardrail): void {
    this.guardrails.push(guardrail);
  }

  async start(): Promise<void> {
    await this.upstream.connect();

    return new Promise<void>((resolve, reject) => {
      // Surface fatal startup errors as a rejected promise.
      // Using reject (not emit) because 'audit' listeners are typically
      // attached after start() is called, so an emitted event would be lost.
      this.server.on("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "EADDRINUSE") {
          reject(new PortInUseError(this.config.port));
        } else {
          reject(err);
        }
      });

      this.server.listen(this.config.port, () => {
        // Notify all observers that the proxy is live and accepting connections
        this.emitAudit<StartAuditEvent>({
          type: "start",
          timestamp: new Date(),
          port: this.config.port,
          targetUrl: this.config.targetUrl,
        });
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    this.server.close();
    this.upstream.close();

    // Clean up guardrails that may have timers or other resources
    for (const guardrail of this.guardrails) {
      // Check if guardrail has a destroy method (e.g., RateLimiter)
      if (
        "destroy" in guardrail &&
        typeof (guardrail as any).destroy === "function"
      ) {
        (guardrail as any).destroy();
      }
    }
  }

  // -------------------------------------------------------------------------
  // Private: typed emit helper
  // -------------------------------------------------------------------------

  /**
   * Wraps EventEmitter.emit with the 'audit' channel.
   * The generic parameter T is inferred from the payload so call sites
   * never need explicit casts.
   */
  private emitAudit<T extends ProxyAuditEvent>(event: T): void {
    this.emit("audit", event);
  }

  // -------------------------------------------------------------------------
  // Private: HTTP routing
  // -------------------------------------------------------------------------

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    // Permissive CORS headers for local development
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(200);
      res.end();
      return;
    }

    // Route 1 – SSE subscription endpoint (clients listen for server messages)
    if (req.url === "/sse" && req.method === "GET") {
      this.handleSseConnection(req, res);
      return;
    }

    // Route 2 – JSON-RPC message endpoint (clients send commands)
    if (req.url === "/message" && req.method === "POST") {
      await this.handleMessagePost(req, res);
      return;
    }

    res.writeHead(404);
    res.end(t("not_found"));
  }

  // -------------------------------------------------------------------------
  // Private: SSE connection lifecycle
  // -------------------------------------------------------------------------

  private handleSseConnection(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): void {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });

    // Send the client the message endpoint URL so it knows where to POST
    res.write(
      `event: endpoint\ndata: http://localhost:${this.config.port}/message\n\n`,
    );

    this.clients.add(res);
    this.logger.debug(t("client_connected_sse")); // internal wiring trace only

    req.on("close", () => {
      this.clients.delete(res);
      this.logger.debug(t("client_disconnected_sse"));
    });
  }

  // -------------------------------------------------------------------------
  // Private: JSON-RPC interception + upstream forwarding
  // -------------------------------------------------------------------------

  private handleMessagePost(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    return new Promise((resolve) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", async () => {
        try {
          const message = JSON.parse(body);

          // ── Step 1: emit REQUEST ─────────────────────────────────────────
          this.emitAudit<RequestAuditEvent>({
            type: "request",
            timestamp: new Date(),
            messageId: message.id ?? null,
            method: message.method,
            params: message.params,
          });

          // ── Step 1.5: PANIC STOP - check backoff/panic mode ─────────────
          const clientId = this.getClientId(req);
          const panicCheck = this.checkPanicStop(clientId);
          if (panicCheck.blocked) {
            const clientState = this.rateLimitState.get(clientId);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id: message.id,
                error: {
                  code: panicCheck.errorCode,
                  message: panicCheck.message,
                  data: {
                    reason: panicCheck.reason,
                    clientId,
                    blockedUntil: clientState
                      ? new Date(clientState.blockedUntil).toISOString()
                      : null,
                    remainingSeconds: clientState
                      ? Math.ceil(
                          (clientState.blockedUntil - Date.now()) / 1000,
                        )
                      : 0,
                    strikes: clientState?.strikes ?? 0,
                    panicMode: clientState?.panicMode ?? false,
                  },
                },
              }),
            );
            resolve();
            return;
          }

          // ── Step 2: run the guardrail pipeline ──────────────────────────
          const decision = this.runGuardrails(message, "request");

          if (decision.action === "block") {
            // Emit BLOCK before writing the HTTP response so listeners
            // receive the event even if they inspect timing
            this.emitAudit<BlockAuditEvent>({
              type: "block",
              timestamp: new Date(),
              messageId: message.id ?? null,
              method: message.method,
              reason: decision.reason ?? t("unknown_reason"),
            });

            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id: message.id,
                error: {
                  code: -32000,
                  message: `${t("blocked_by_guardrail")}: ${decision.reason}`,
                },
              }),
            );
            resolve();
            return;
          }

          // Use the guardrail-modified message if it was mutated, otherwise
          // forward the original payload
          const payload = decision.modifiedMessage ?? message;

          // ── Step 2.5: run 3-layer security analysis ──────────────────────
          const securityDecision = await this.runSecurityAnalysis(payload);

          if (securityDecision.action === "block") {
            // Emit BLOCK with security-specific metadata
            this.emitAudit<BlockAuditEvent>({
              type: "block",
              timestamp: new Date(),
              messageId: message.id ?? null,
              method: message.method,
              reason: securityDecision.reason ?? t("unknown_reason"),
            });

            // Generate explainable blocking response with rule details
            const finding = securityDecision.findings?.[0];
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id: message.id,
                error: {
                  code: securityDecision.errorCode ?? -32000,
                  message: `${t("blocked_by_guardrail")}: ${securityDecision.reason}`,
                  data: finding
                    ? {
                        ruleId: finding.ruleCode,
                        severity: finding.severity,
                        category: (finding as any).category ?? "Security",
                        remediation:
                          finding.remediation ??
                          "Consult security documentation for remediation guidance",
                        cwe: (finding as any).cwe,
                        owasp: (finding as any).owasp,
                        layer: securityDecision.layer,
                        latencyMs: securityDecision.latencyMs,
                        timestamp: new Date().toISOString(),
                      }
                    : undefined,
                },
              }),
            );
            resolve();
            return;
          }

          // ── Step 3: forward to upstream ─────────────────────────────────
          try {
            // NOTE: transport.send() follows a synchronous request/response model.
            // For a future v1.0 async mode, upstream SSE notifications should be
            // relayed to connected clients. See V0.5 simplification note.
            const result = await this.upstream.send(payload);

            // Emit RESPONSE with the upstream result
            this.emitAudit<ResponseAuditEvent>({
              type: "response",
              timestamp: new Date(),
              messageId: message.id ?? null,
              method: message.method,
              result,
            });

            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id: message.id,
                result,
              }),
            );
          } catch (upstreamError: unknown) {
            const cause =
              upstreamError instanceof Error
                ? upstreamError
                : new Error(String(upstreamError));

            // ── PHASE 2: Detect HTTP 429 and trigger strike system ───────
            if (this.is429Error(upstreamError)) {
              this.handleRateLimitStrike(clientId);
            }

            // Emit ERROR so observers can log, alert, or trigger circuit-breakers
            this.emitAudit<ErrorAuditEvent>({
              type: "error",
              timestamp: new Date(),
              messageId: message.id ?? null,
              method: message.method,
              cause,
            });

            res.writeHead(500);
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id: message.id,
                error: { code: -32603, message: cause.message },
              }),
            );
          }
        } catch {
          // Malformed JSON — no meaningful audit context to emit
          res.writeHead(400);
          res.end(t("proxy_invalid_json"));
        }

        resolve();
      });
    });
  }

  // -------------------------------------------------------------------------
  // Private: guardrail pipeline
  // -------------------------------------------------------------------------

  private runGuardrails(
    message: JsonValue,
    type: "request" | "response",
  ): InterceptResult {
    for (const guard of this.guardrails) {
      const result =
        type === "request"
          ? guard.inspectRequest(message)
          : guard.inspectResponse(message);

      // Short-circuit on the first guardrail that modifies or blocks
      if (result.action === "block" || result.action === "modify") {
        return result;
      }
    }
    return { action: "allow" };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Private: 3-Layer Security Analysis
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Runs security analysis in 3 progressive layers.
   * Early exit at first critical finding (fast fail).
   *
   * LAYER 1 (Fast Rules): Pattern matching, <10ms target
   * LAYER 2 (Suspicious Rules): Semantic analysis, <50ms target (only for suspicious tools)
   * LAYER 3 (LLM Rules): Deep intent analysis, opt-in only (token-consuming)
   *
   * @param message - JSON-RPC message to analyze
   * @returns {Promise<InterceptResult>} - block or allow with metadata
   */
  private async runSecurityAnalysis(
    message: JsonRpcMessage,
  ): Promise<InterceptResult> {
    const startTime = Date.now();

    // ── LAYER 1: Fast Rules (<10ms) - Pattern Matching ──────────────────────
    const layer1Findings = await this.runFastRulesWithCache(message);
    const criticalL1 = layer1Findings.filter(
      (f) => f.severity === "critical" || f.severity === "high",
    );

    if (criticalL1.length > 0) {
      const elapsed = Date.now() - startTime;

      // Emit security analysis audit event
      this.emitAudit<SecurityAnalysisAuditEvent>({
        type: "security-analysis",
        timestamp: new Date(),
        messageId: message.id ?? null,
        method: message.method,
        layer: 1,
        result: "blocked",
        latencyMs: elapsed,
        findings: criticalL1,
      });

      return {
        action: "block",
        reason: `${criticalL1[0].ruleCode}: ${criticalL1[0].message}`,
        findings: criticalL1,
        layer: 1,
        latencyMs: elapsed,
        errorCode: -32001, // Custom code for Layer 1 block
      };
    }

    // ── LAYER 2: Suspicious Rules (<50ms) - Semantic Analysis ──────────────
    // Only run if tool is suspicious (execute_*, delete_*, admin_*, etc.)
    if (this.isSuspiciousTool(message)) {
      const layer2Findings = await this.runSuspiciousRules(message);
      const criticalL2 = layer2Findings.filter(
        (f) => f.severity === "critical" || f.severity === "high",
      );

      if (criticalL2.length > 0) {
        const elapsed = Date.now() - startTime;

        this.emitAudit<SecurityAnalysisAuditEvent>({
          type: "security-analysis",
          timestamp: new Date(),
          messageId: message.id ?? null,
          method: message.method,
          layer: 2,
          result: "blocked",
          latencyMs: elapsed,
          findings: criticalL2,
        });

        return {
          action: "block",
          reason: `${criticalL2[0].ruleCode}: ${criticalL2[0].message}`,
          findings: criticalL2,
          layer: 2,
          latencyMs: elapsed,
          errorCode: -32002, // Custom code for Layer 2 block
        };
      }
    }

    // ── LAYER 3: LLM-Based Rules (OPT-IN) - Deep Semantic Intent ──────────
    if (this.enableDeepAnalysis && this.requiresDeepAnalysis(message)) {
      const layer3Findings = await this.runLLMRules(message);
      const criticalL3 = layer3Findings.filter(
        (f) => f.severity === "critical" || f.severity === "high",
      );

      if (criticalL3.length > 0) {
        const elapsed = Date.now() - startTime;

        this.emitAudit<SecurityAnalysisAuditEvent>({
          type: "security-analysis",
          timestamp: new Date(),
          messageId: message.id ?? null,
          method: message.method,
          layer: 3,
          result: "blocked",
          latencyMs: elapsed,
          findings: criticalL3,
        });

        return {
          action: "block",
          reason: `${criticalL3[0].ruleCode} (Deep Analysis): ${criticalL3[0].message}`,
          findings: criticalL3,
          layer: 3,
          latencyMs: elapsed,
          errorCode: -32003, // Custom code for Layer 3 block
        };
      }
    }

    const elapsed = Date.now() - startTime;

    // Emit passed audit event
    this.emitAudit<SecurityAnalysisAuditEvent>({
      type: "security-analysis",
      timestamp: new Date(),
      messageId: message.id ?? null,
      method: message.method,
      layer: 0, // All layers passed
      result: "passed",
      latencyMs: elapsed,
    });

    return {
      action: "allow",
      latencyMs: elapsed,
    };
  }

  /**
   * Layer 1: Fast pattern-based rules (target <10ms).
   * Uses runtime pattern detection on actual parameter values.
   *
   * Fast Rule Set (25 rules): SEC-001 to SEC-021 (OWASP + MCP core patterns)
   */
  private async runFastRules(
    message: JsonRpcMessage,
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    if (!isToolCall(message)) {
      return findings; // Only analyze tool calls
    }

    const toolName = message.params.name;
    const args = message.params.arguments ?? {};

    // Runtime pattern detection (fast, <10ms)
    findings.push(...this.detectSQLInjection(toolName, args));
    findings.push(...this.detectCommandInjection(toolName, args));
    findings.push(...this.detectSSRF(toolName, args));
    findings.push(...this.detectPromptInjection(toolName, args));
    findings.push(...this.detectPathTraversal(toolName, args));

    return findings;
  }

  /**
   * Runtime SQL Injection detection (SEC-001)
   * Detects SQL injection patterns in parameter values
   */
  private detectSQLInjection(
    toolName: string,
    args: JsonObject,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // SQL keywords in tool name
    const sqlKeywords = [
      "sql",
      "query",
      "database",
      "db",
      "mysql",
      "postgres",
      "select",
    ];
    const isSQLTool = sqlKeywords.some((kw) =>
      toolName.toLowerCase().includes(kw),
    );

    if (!isSQLTool) return findings;

    // Check all string arguments for SQL injection patterns
    const sqlPatterns = [
      /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/i, // OR 1=1, AND 1=1
      /--/, // SQL comment
      /\/\*/, // Block comment start
      /\bUNION\b.*\bSELECT\b/i, // UNION SELECT
      /;\s*(DROP|DELETE|UPDATE|INSERT)\b/i, // Dangerous commands after semicolon
      /\bEXEC\b|\bEXECUTE\b/i, // Execute dynamic SQL
      /xp_|sp_cmdshell/i, // SQL Server extended procedures
    ];

    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        for (const pattern of sqlPatterns) {
          if (pattern.test(value)) {
            findings.push({
              ruleCode: "SEC-001",
              severity: "critical",
              message: `SQL injection pattern detected in parameter '${key}'`,
              component: `tool:${toolName}`,
              location: { type: "tool", name: toolName, parameter: key },
              evidence: {
                parameter: key,
                value: value.substring(0, 100), // Truncate for safety
                pattern: pattern.source,
              },
              remediation:
                "Use parameterized queries with placeholders. Never concatenate user input into SQL strings.",
            });
            break; // One finding per parameter
          }
        }
      }
    }

    return findings;
  }

  /**
   * Runtime Command Injection detection (SEC-002)
   * Detects shell command injection patterns
   */
  private detectCommandInjection(
    toolName: string,
    args: JsonObject,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check for shell metacharacters in ANY string parameter
    const cmdPatterns = [
      /[;&|`$]/, // Shell metacharacters
      /\$\(/, // Command substitution
      /\|\||\&\&/, // Logical operators
    ];

    // Check for dangerous commands
    const dangerousCommands =
      /\b(rm|del|format|mkfs|dd|fdisk)\b.*[-\/](rf|r|f|force)/i;

    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        // Check shell metacharacters
        for (const pattern of cmdPatterns) {
          if (pattern.test(value)) {
            findings.push({
              ruleCode: "SEC-002",
              severity: "critical",
              message: `Command injection pattern detected in parameter '${key}'`,
              component: `tool:${toolName}`,
              location: { type: "tool", name: toolName, parameter: key },
              evidence: {
                parameter: key,
                value: value.substring(0, 100),
                pattern: pattern.source,
              },
              remediation:
                "Use safe command execution APIs with argument arrays. Avoid shell=true.",
            });
            break;
          }
        }

        // Check dangerous commands
        if (dangerousCommands.test(value)) {
          findings.push({
            ruleCode: "SEC-002",
            severity: "critical",
            message: `Dangerous command detected in parameter '${key}': ${value.substring(0, 50)}`,
            component: `tool:${toolName}`,
            location: { type: "tool", name: toolName, parameter: key },
            evidence: { parameter: key, value: value.substring(0, 100) },
            remediation:
              "Remove dangerous file system commands. Use safe, scoped operations.",
          });
        }
      }
    }

    return findings;
  }

  /**
   * Runtime SSRF detection (SEC-003)
   * Detects internal IPs and localhost references
   */
  private detectSSRF(toolName: string, args: JsonObject): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const urlKeywords = ["url", "uri", "endpoint", "fetch", "request", "http"];
    const isURLTool = urlKeywords.some((kw) =>
      toolName.toLowerCase().includes(kw),
    );

    if (!isURLTool) return findings;

    const ssrfPatterns = [
      /localhost|127\.0\.0\.1|0\.0\.0\.0/i,
      /192\.168\.\d+\.\d+/,
      /10\.\d+\.\d+\.\d+/,
      /172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+/,
      /::1|::ffff:127\.0\.0\.1/i,
    ];

    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        for (const pattern of ssrfPatterns) {
          if (pattern.test(value)) {
            findings.push({
              ruleCode: "SEC-003",
              severity: "high",
              message: `SSRF vulnerability: Internal IP/hostname detected in parameter '${key}'`,
              component: `tool:${toolName}`,
              location: { type: "tool", name: toolName, parameter: key },
              evidence: { parameter: key, value: value.substring(0, 100) },
              remediation:
                "Validate and whitelist allowed external URLs. Block internal IPs.",
            });
            break;
          }
        }
      }
    }

    return findings;
  }

  /**
   * Runtime Prompt Injection detection (SEC-013)
   * Detects prompt injection attempts
   */
  private detectPromptInjection(
    toolName: string,
    args: JsonObject,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const promptKeywords = [
      "prompt",
      "generate",
      "llm",
      "ai",
      "chat",
      "completion",
    ];
    const isPromptTool = promptKeywords.some((kw) =>
      toolName.toLowerCase().includes(kw),
    );

    if (!isPromptTool) return findings;

    const injectionPatterns = [
      /ignore\s+(previous|prior|above)\s+instructions?/i,
      /disregard\s+(previous|prior|all)\s+instructions?/i,
      /forget\s+your\s+instructions?/i,
      /system:\s*you\s+are/i,
      /reveal\s+your\s+(system\s+)?prompt/i,
    ];

    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        for (const pattern of injectionPatterns) {
          if (pattern.test(value)) {
            findings.push({
              ruleCode: "SEC-013",
              severity: "critical",
              message: `Prompt injection attempt detected in parameter '${key}'`,
              component: `tool:${toolName}`,
              location: { type: "tool", name: toolName, parameter: key },
              evidence: { parameter: key, pattern: pattern.source },
              remediation:
                "Sanitize user input before inserting into prompts. Use delimiters and content filtering.",
            });
            break;
          }
        }
      }
    }

    return findings;
  }

  /**
   * Runtime Path Traversal detection (SEC-004)
   * Detects path traversal attempts
   */
  private detectPathTraversal(
    toolName: string,
    args: JsonObject,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const fileKeywords = ["file", "path", "read", "write", "open", "load"];
    const isFileTool = fileKeywords.some((kw) =>
      toolName.toLowerCase().includes(kw),
    );

    if (!isFileTool) return findings;

    const traversalPatterns = [
      /\.\.[\/\\]/, // ../ or ..\
      /\/etc\/passwd/, // Unix sensitive file
      /C:\\Windows/i, // Windows system directory
    ];

    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        for (const pattern of traversalPatterns) {
          if (pattern.test(value)) {
            findings.push({
              ruleCode: "SEC-004",
              severity: "high",
              message: `Path traversal attempt detected in parameter '${key}'`,
              component: `tool:${toolName}`,
              location: { type: "tool", name: toolName, parameter: key },
              evidence: { parameter: key, value: value.substring(0, 100) },
              remediation:
                "Validate file paths against whitelist. Use path.resolve() and reject paths outside allowed directories.",
            });
            break;
          }
        }
      }
    }

    return findings;
  }

  /**
   * Layer 1 with caching: Fast rules with result caching (TTL: 60s).
   * Key: SHA-256 hash of (method + params).
   */
  private async runFastRulesWithCache(
    message: JsonRpcMessage,
  ): Promise<SecurityFinding[]> {
    const cacheKey = this.hashMessage(message);
    const cached = this.ruleCache.get(cacheKey);

    // Cache hit: return cached findings if within TTL
    if (cached && Date.now() - cached.timestamp < 60_000) {
      return cached.findings;
    }

    // Cache miss: run rules and cache result
    const findings = await this.runFastRules(message);
    this.ruleCache.set(cacheKey, { findings, timestamp: Date.now() });

    // LRU eviction: limit cache size to 1000 entries
    if (this.ruleCache.size > 1000) {
      const oldestKey = this.ruleCache.keys().next().value;
      if (oldestKey) {
        this.ruleCache.delete(oldestKey);
      }
    }

    return findings;
  }

  /**
   * Layer 2: Semantic/business logic rules (target <50ms).
   * Only runs for "suspicious" tools (execute_*, delete_*, admin_*, etc.)
   *
   * Suspicious Rule Set (20 rules): SEC-014, SEC-015, SEC-017, SEC-020, etc.
   */
  private async runSuspiciousRules(
    message: JsonRpcMessage,
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    if (!isToolCall(message)) {
      return findings;
    }

    const toolName = message.params.name;
    const args = message.params.arguments ?? {};

    // Runtime semantic analysis (target <50ms)
    findings.push(...this.detectExcessiveAgency(toolName, args));
    findings.push(...this.detectMissingAuthentication(toolName, args));

    return findings;
  }

  /**
   * Runtime Excessive Agency detection (SEC-023)
   * Detects destructive operations without confirmation
   */
  private detectExcessiveAgency(
    toolName: string,
    args: JsonObject,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const destructiveKeywords = [
      "delete",
      "destroy",
      "drop",
      "remove",
      "erase",
      "wipe",
      "purge",
    ];
    const isDestructiveTool = destructiveKeywords.some((kw) =>
      toolName.toLowerCase().includes(kw),
    );

    if (!isDestructiveTool) return findings;

    // Check for NEGATIVE confirmation patterns (skip, bypass, force)
    const hasNegativeConfirmation = Object.entries(args).some(
      ([key, value]) => {
        const keyLower = key.toLowerCase();
        return (
          (keyLower.includes("skip") ||
            keyLower.includes("bypass") ||
            keyLower.includes("force")) &&
          value === true
        );
      },
    );

    // Check for POSITIVE confirmation (confirm, verified, acknowledged)
    const hasPositiveConfirmation = Object.entries(args).some(
      ([key, value]) => {
        const keyLower = key.toLowerCase();
        return (
          (keyLower === "confirm" ||
            keyLower === "confirmation" ||
            keyLower === "verified" ||
            keyLower === "acknowledged") &&
          value === true
        );
      },
    );

    // Block if: (1) has negative confirmation OR (2) lacks positive confirmation
    const shouldBlock = hasNegativeConfirmation || !hasPositiveConfirmation;

    if (shouldBlock) {
      findings.push({
        ruleCode: "SEC-023",
        severity: "high",
        message: `Destructive operation '${toolName}' lacks proper confirmation mechanism`,
        component: `tool:${toolName}`,
        location: { type: "tool", name: toolName },
        evidence: {
          toolName,
          hasPositiveConfirmation,
          hasNegativeConfirmation,
          destructiveAction: true,
        },
        remediation:
          'Add a required confirmation parameter (e.g., "confirm": true) for destructive operations. Remove skip/bypass flags.',
      });
    }

    return findings;
  }

  /**
   * Runtime Missing Authentication detection (SEC-015)
   * Detects tools that should require authentication
   */
  private detectMissingAuthentication(
    toolName: string,
    args: JsonObject,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const sensitiveKeywords = [
      "admin",
      "delete",
      "update",
      "create",
      "modify",
      "configure",
    ];
    const isSensitiveTool = sensitiveKeywords.some((kw) =>
      toolName.toLowerCase().includes(kw),
    );

    if (!isSensitiveTool) return findings;

    // Check if there's an auth/token/credential parameter
    const hasAuth = Object.keys(args).some(
      (key) =>
        key.toLowerCase().includes("auth") ||
        key.toLowerCase().includes("token") ||
        key.toLowerCase().includes("key") ||
        key.toLowerCase().includes("credential"),
    );

    if (!hasAuth) {
      findings.push({
        ruleCode: "SEC-015",
        severity: "high",
        message: `Sensitive operation '${toolName}' does not implement authentication mechanism`,
        component: `tool:${toolName}`,
        location: { type: "tool", name: toolName },
        evidence: {
          toolName,
          sensitiveOperation: true,
          hasAuthParameter: false,
        },
        remediation:
          'Add authentication parameters (e.g., "authToken", "apiKey") for sensitive operations.',
      });
    }

    return findings;
  }

  /**
   * Layer 3: LLM-based rules (opt-in, token-consuming).
   * Requires LLM API call for deep semantic intent analysis.
   *
   * STATUS: Layer 1 & 2 are ACTIVE. Layer 3 (AI Semantic Analysis) is planned for a future update.
   * The architecture is ready to receive Layer 3, but the intent analysis engine is pending.
   */
  private async runLLMRules(
    message: JsonRpcMessage,
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Note: LLM analysis is expensive and opt-in.
    // For now, return empty findings as this layer is planned for a future release.
    // Future: Implement LLM-based intent analysis engine.

    return findings;
  }

  /**
   * Determines if a tool invocation is "suspicious" and requires Layer 2 analysis.
   * Heuristics: tool name contains dangerous keywords.
   */
  private isSuspiciousTool(message: JsonRpcMessage): boolean {
    if (!isToolCall(message)) return false;

    const toolName = message.params.name;
    const suspiciousKeywords = [
      "execute",
      "exec",
      "run",
      "eval",
      "delete",
      "destroy",
      "drop",
      "admin",
      "root",
      "sudo",
      "shell",
      "bash",
      "cmd",
      "powershell",
      "install",
      "download",
      "upload",
      "write",
      "create",
      "modify",
      "kill",
      "terminate",
      "restart",
      "shutdown",
      "reboot",
    ];

    return suspiciousKeywords.some((kw) => toolName.toLowerCase().includes(kw));
  }

  /**
   * Determines if a message requires Layer 3 (LLM) deep analysis.
   * Heuristics: complex multi-agent coordination, plugin loading, etc.
   */
  private requiresDeepAnalysis(message: JsonRpcMessage): boolean {
    if (!isToolCall(message)) return false;

    const toolName = message.params.name;
    const deepAnalysisKeywords = [
      "agent",
      "swarm",
      "coordinate",
      "orchestrat",
      "plugin",
      "load",
      "inject",
      "poison",
      "spoof",
      "hijack",
      "backdoor",
      "exfiltrat",
    ];

    return deepAnalysisKeywords.some((kw) =>
      toolName.toLowerCase().includes(kw),
    );
  }

  /**
   * Generates SHA-256 hash of message for caching.
   * Key: hash(method + JSON.stringify(params))
   */
  private hashMessage(message: JsonRpcMessage): string {
    const content = `${message.method}:${JSON.stringify(message.params ?? {})}`;
    return crypto.createHash("sha256").update(content).digest("hex");
  }

  // =========================================================================
  // PHASE 2: PANIC STOP - 3-Strike System with Backoff
  // =========================================================================

  /**
   * Extract client identifier from HTTP request.
   * Priority: x-client-id header > x-forwarded-for > remoteAddress > 'default-client'
   */
  private getClientId(req: http.IncomingMessage): string {
    // Priority 1: x-client-id header
    const clientIdHeader = req.headers["x-client-id"];
    if (clientIdHeader) {
      return Array.isArray(clientIdHeader) ? clientIdHeader[0] : clientIdHeader;
    }

    // Priority 2: x-forwarded-for (take first IP if multiple)
    const forwardedFor = req.headers["x-forwarded-for"];
    if (forwardedFor) {
      const ip = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
      return ip.split(",")[0].trim();
    }

    // Priority 3: remoteAddress
    if (req.socket.remoteAddress) {
      return req.socket.remoteAddress;
    }

    // Fallback: default-client
    return "default-client";
  }

  /**
   * Check if a specific client is in backoff or panic mode.
   * Returns blocking information if requests should be rejected.
   */
  private checkPanicStop(clientId: string): {
    blocked: boolean;
    errorCode?: number;
    message?: string;
    reason?: string;
  } {
    // Get client-specific state (if doesn't exist, client has no strikes)
    const state = this.rateLimitState.get(clientId);
    if (!state) {
      return { blocked: false };
    }

    const now = Date.now();

    // If panic mode is active for this client, block indefinitely
    if (state.panicMode) {
      return {
        blocked: true,
        errorCode: -32004,
        message: `Proxy is in PANIC MODE for client ${clientId} due to repeated rate limit violations`,
        reason: "panic_mode",
      };
    }

    // If in backoff and time hasn't expired, block request
    if (state.inBackoff && now < state.blockedUntil) {
      return {
        blocked: true,
        errorCode: -32005,
        message: `Rate limit backoff active for client ${clientId} (Strike ${state.strikes}/3)`,
        reason: "rate_limit_backoff",
      };
    }

    // If backoff expired, exit backoff mode
    if (state.inBackoff && now >= state.blockedUntil) {
      state.inBackoff = false;
      state.blockedUntil = 0;
      // Note: strikes are NOT reset - they persist until server restart
    }

    return { blocked: false };
  }

  /**
   * Handle HTTP 429 detection from upstream for a specific client.
   * Implements 3-strike backoff escalation:
   * - Strike 1: 30 second backoff
   * - Strike 2: 60 second backoff
   * - Strike 3: PANIC MODE (permanent block until restart)
   */
  private handleRateLimitStrike(clientId: string): void {
    // Get or create state for this client
    let state = this.rateLimitState.get(clientId);
    if (!state) {
      state = {
        strikes: 0,
        inBackoff: false,
        blockedUntil: 0,
        panicMode: false,
      };
      this.rateLimitState.set(clientId, state);
    }

    state.strikes++;

    if (state.strikes === 1) {
      // Strike 1: 30 second backoff
      state.inBackoff = true;
      state.blockedUntil = Date.now() + 30_000;

      this.emitAudit<RateLimitBackoffAuditEvent>({
        type: "rate-limit-backoff",
        timestamp: new Date(),
        message: `Strike 1/3 for client ${clientId}: Entering 30 second backoff due to HTTP 429`,
      });
    } else if (state.strikes === 2) {
      // Strike 2: 60 second backoff
      state.inBackoff = true;
      state.blockedUntil = Date.now() + 60_000;

      this.emitAudit<RateLimitBackoffAuditEvent>({
        type: "rate-limit-backoff",
        timestamp: new Date(),
        message: `Strike 2/3 for client ${clientId}: Entering 60 second backoff due to HTTP 429`,
      });
    } else if (state.strikes >= 3) {
      // Strike 3: PANIC MODE for this client
      state.panicMode = true;
      state.inBackoff = false;
      state.blockedUntil = 0;

      this.emitAudit<PanicModeAuditEvent>({
        type: "panic-mode-activated",
        timestamp: new Date(),
        message: `Strike 3/3 for client ${clientId}: PANIC MODE activated. Client blocked until proxy restart.`,
      });
    }
  }

  /**
   * Detect HTTP 429 (Too Many Requests) in upstream error.
   * Some transports may wrap 429 in error messages or error objects.
   */
  private is429Error(error: unknown): boolean {
    if (!error) return false;

    const errorStr = String(error).toLowerCase();
    const errorMsg = error instanceof Error ? error.message.toLowerCase() : "";

    // Check for common 429 patterns
    return (
      errorStr.includes("429") ||
      errorStr.includes("too many requests") ||
      errorStr.includes("rate limit") ||
      errorMsg.includes("429") ||
      errorMsg.includes("too many requests") ||
      errorMsg.includes("rate limit")
    );
  }
}
