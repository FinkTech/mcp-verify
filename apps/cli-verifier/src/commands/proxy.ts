/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Proxy Command
 *
 * Security gateway proxy with guardrails for MCP servers.
 *
 * This module owns 100% of the UI rendering for the proxy.
 * McpProxyServer is treated as a "silent engine": it emits structured
 * audit events, and this file is the sole consumer that decides how to
 * display them to the user via chalk + i18n.
 */

import chalk from "chalk";
import fs from "fs";
import path from "path";
import inquirer from "inquirer";
import readline from "readline";
import {
  McpProxyServer,
  PortInUseError,
  type ProxyAuditEvent,
  type StartAuditEvent,
  type RequestAuditEvent,
  type BlockAuditEvent,
  type ResponseAuditEvent,
  type ErrorAuditEvent,
} from "@mcp-verify/core/use-cases/proxy/proxy-server";
import {
  SensitiveCommandBlocker,
  PIIRedactor,
  RateLimiter,
  InputSanitizer,
  HttpsEnforcer,
} from "@mcp-verify/core";
import { t, getCurrentLanguage } from "@mcp-verify/shared";
import { registerCleanup } from "../utils/cleanup-handlers";

// ---------------------------------------------------------------------------
// Audit event formatter
// ---------------------------------------------------------------------------

/**
 * Formats a timestamp as HH:MM:SS in local time.
 * Kept as a pure helper so it can be unit-tested independently.
 */
function formatTime(date: Date): string {
  return date.toLocaleTimeString("en-GB", { hour12: false }); // HH:MM:SS
}

/**
 * Formats an audit event into a plain-text string for file logging.
 * Does not use chalk/ANSI colors.
 */
function formatAuditEvent(event: ProxyAuditEvent): string {
  const time = `[${formatTime(event.timestamp)}]`;
  let message = "";

  switch (event.type) {
    case "start": {
      const e = event as StartAuditEvent;
      message = `START: Proxy active on port ${e.port} -> targeting ${e.targetUrl}`;
      break;
    }
    case "request": {
      const e = event as RequestAuditEvent;
      const id = e.messageId != null ? ` #${e.messageId}` : "";
      message = `REQ${id}: ${e.method}`;
      break;
    }
    case "block": {
      const e = event as BlockAuditEvent;
      const id = e.messageId != null ? ` #${e.messageId}` : "";
      message = `BLOCK${id}: ${e.method} - REASON: ${e.reason}`;
      break;
    }
    case "response": {
      const e = event as ResponseAuditEvent;
      const id = e.messageId != null ? ` #${e.messageId}` : "";
      message = `RES${id}: ${e.method}`;
      break;
    }
    case "error": {
      const e = event as ErrorAuditEvent;
      const id = e.messageId != null ? ` #${e.messageId}` : "";
      const method = e.method ? ` ${e.method}` : "";
      message = `ERROR${id}${method}: ${e.cause.message}`;
      break;
    }
    case "security-analysis": {
      const e = event as any;
      message = `SECURITY: ${e.message}`;
      break;
    }
    case "rate-limit-backoff": {
      const e = event as any;
      message = `BACKOFF: ${e.message}`;
      break;
    }
    case "panic-mode-activated": {
      const e = event as any;
      message = `PANIC: ${e.message}`;
      break;
    }
  }

  return `${time} ${message}`;
}

/**
 * Renders a ProxyAuditEvent to the terminal in a visually consistent,
 * professional format using chalk for colour and t() for i18n strings.
 */
function renderAuditEvent(event: ProxyAuditEvent): void {
  const time = chalk.gray(`[${formatTime(event.timestamp)}]`);

  switch (event.type) {
    // ── Server started ──────────────────────────────────────────────────────
    case "start": {
      const e = event as StartAuditEvent;
      console.log(
        `${time} ${chalk.bold.green("🛡️  " + t("proxy_active"))} ` +
          `${chalk.cyan(`http://localhost:${e.port}/sse`)}`,
      );
      console.log(
        `${time} ${chalk.gray("➡️  " + t("redirecting_to"))} ${chalk.green(e.targetUrl)}`,
      );
      break;
    }

    // ── Incoming request ────────────────────────────────────────────────────
    case "request": {
      const e = event as RequestAuditEvent;
      const idTag = e.messageId != null ? chalk.gray(` #${e.messageId}`) : "";
      console.log(
        `${time} ${chalk.bold.blue("📥 " + t("request_log"))}${idTag} ` +
          `${chalk.white(e.method)}`,
      );
      break;
    }

    // ── Request blocked by a guardrail ─────────────────────────────────────
    case "block": {
      const e = event as BlockAuditEvent;
      const idTag = e.messageId != null ? chalk.gray(` #${e.messageId}`) : "";
      console.log(
        `${time} ${chalk.bold.red("🚫 " + t("blocked_log"))}${idTag} ` +
          `${chalk.white(e.method)} — ${chalk.yellow(e.reason)}`,
      );
      break;
    }

    // ── Upstream response received ──────────────────────────────────────────
    case "response": {
      const e = event as ResponseAuditEvent;
      const idTag = e.messageId != null ? chalk.gray(` #${e.messageId}`) : "";
      console.log(
        `${time} ${chalk.bold.green("📤 " + t("response_log"))}${idTag} ` +
          `${chalk.white(e.method)}`,
      );
      break;
    }

    // ── Processing or connection error ──────────────────────────────────────
    case "error": {
      const e = event as ErrorAuditEvent;
      const idTag = e.messageId != null ? chalk.gray(` #${e.messageId}`) : "";
      const methodTag = e.method ? ` ${chalk.white(e.method)}` : "";
      console.error(
        `${time} ${chalk.bold.red("❌ " + t("upstream_error"))}${idTag}${methodTag}`,
      );
      console.error(`       ${chalk.red(e.cause.message)}`);
      break;
    }

    // ── Security analysis completed ─────────────────────────────────────────
    case "security-analysis": {
      const e = event as any; // SecurityAnalysisAuditEvent
      console.log(
        `${time} ${chalk.bold.magenta("🔒 Security Analysis")} ` +
          `${chalk.gray(`(${e.message})`)}`,
      );
      break;
    }

    // ── Rate limit backoff activated ────────────────────────────────────────
    case "rate-limit-backoff": {
      const e = event as any; // RateLimitBackoffAuditEvent
      console.log(
        `${time} ${chalk.bold.yellow("⏱️  Rate Limit Backoff")} ` +
          `${chalk.yellow(e.message)}`,
      );
      break;
    }

    // ── Panic mode activated ────────────────────────────────────────────────
    case "panic-mode-activated": {
      const e = event as any; // PanicModeAuditEvent
      console.log(
        `${time} ${chalk.bold.red("🚨 PANIC MODE")} ` +
          `${chalk.red(e.message)}`,
      );
      break;
    }

    // TypeScript exhaustiveness guard — will cause a compile error if a new
    // AuditEventType is added to the union without a matching case here.
    default: {
      const _exhaustive: never = event;
      console.warn("Unhandled audit event type:", _exhaustive);
    }
  }
}

// ---------------------------------------------------------------------------
// Banner helpers
// ---------------------------------------------------------------------------

function printBanner(target: string, port: number): void {
  console.clear();
  console.log(
    chalk.cyan(
      "  __  __   _____  _____     _____   _____    ____  __   __ __     __\n" +
        " |  \\/  | / ____||  __ \\   |  __ \\ |  __ \\  / __ \\ \\ \\ / / \\ \\   / /\n" +
        " | \\  / || |     | |__) |  | |__) || |__) || |  | | \\ V /   \\ \\_/ / \n" +
        " | |\\/| || |     |  ___/   |  ___/ |  _  / | |  | |  > <     \\   /  \n" +
        " | |  | || |____ | |       | |     | | \\ \\ | |__| | / . \\     | |   \n" +
        " |_|  |_| \\_____||_|       |_|     |_|  \\_\\ \\____/ /_/ \\_\\    |_|   \n",
    ),
  );
  console.log(chalk.bold.white("  " + t("runtime_security_gateway")));
  console.log(
    chalk.gray("  ────────────────────────────────────────────────────────"),
  );
  console.log(`  ${t("target_label")}:   ${chalk.green(target)}`);
  console.log(
    `  ${t("listen_label")}:   ${chalk.cyan(`http://localhost:${port}/sse`)}`,
  );
  console.log(
    chalk.gray("  ────────────────────────────────────────────────────────"),
  );
  console.log(chalk.bold.white("  " + t("active_guardrails")));
  console.log(chalk.green(t("guardrail_sensitive_blocker")));
  console.log(chalk.green(t("guardrail_pii_redaction")));
  console.log(chalk.green(t("guardrail_rate_limiting")));
  console.log(chalk.green(t("guardrail_input_sanitization")));
  console.log(chalk.green(t("guardrail_https_enforcement")));
  console.log(
    chalk.gray("  ────────────────────────────────────────────────────────"),
  );
  console.log(chalk.yellow("  " + t("logs_appear_below")));
  console.log(
    chalk.bold.cyan(
      "  → " +
        (t("press_q_to_exit") || "Press [Q] to stop proxy and save session"),
    ),
  );
  console.log("");
}

// ---------------------------------------------------------------------------
// Main action
// ---------------------------------------------------------------------------

export async function runProxyAction(
  target: string,
  options: Record<string, unknown>,
): Promise<number> {
  // Check disclaimer before proceeding
  const { checkDisclaimer } = await import("../utils/disclaimer-manager");
  const accepted = await checkDisclaimer("proxy");

  if (!accepted) {
    console.log(chalk.yellow(t("disclaimer_aborted")));
    return 0;
  }

  const port = parseInt(String(options.port ?? "8080"), 10);
  const logFilePath = options.logFile ? String(options.logFile) : null;
  const sessionEvents: ProxyAuditEvent[] = [];

  if (logFilePath) {
    try {
      const dir = path.dirname(logFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(
        logFilePath,
        `--- MCP PROXY LOG START: ${new Date().toISOString()} ---\n\n`,
        "utf8",
      );
      console.log(chalk.blue(`  📝 Logging to: ${chalk.white(logFilePath)}`));
    } catch (err) {
      console.error(
        chalk.red(
          `  ✗ Could not initialize log file: ${(err as Error).message}`,
        ),
      );
    }
  }

  const config = {
    targetUrl: target,
    port,
    blockCritical: true,
    maskPii: false,
    lang: getCurrentLanguage(),
  };

  const proxy = new McpProxyServer(config);

  // Add all security guardrails (v1.0)
  const guardrails = [
    new SensitiveCommandBlocker(), // Block dangerous shell commands
    new PIIRedactor(), // Redact SSNs, credit cards, etc.
    new RateLimiter(), // Prevent abuse (60 req/min default)
    new InputSanitizer(), // Sanitize SQL/command injection
    new HttpsEnforcer(), // Enforce HTTPS-only upstream calls
  ];
  guardrails.forEach((g) => proxy.addGuardrail(g));

  // ── Subscribe to audit events
  proxy.on("audit", (event: ProxyAuditEvent) => {
    // 1. Memory accumulation for optional save at end
    sessionEvents.push(event);

    // 2. Terminal rendering
    renderAuditEvent(event);

    // 3. Continuous file logging (if --log-file is set)
    if (logFilePath) {
      try {
        const logLine = formatAuditEvent(event) + "\n";
        fs.appendFileSync(logFilePath, logLine, "utf8");
      } catch {
        // Silent failure for logging to avoid crashing the proxy
      }
    }
  });

  // Print the static banner (config summary, active guardrails list)
  printBanner(target, port);

  // Start the proxy — may throw PortInUseError or generic network errors
  try {
    await proxy.start();
  } catch (err) {
    if (err instanceof PortInUseError) {
      console.error(
        `\n  ${chalk.red("❌")} ${t("proxy_port_in_use")}: ${chalk.bold(String(err.port))}`,
      );
      console.error(`     ${chalk.gray(t("proxy_port_tip"))}\n`);
    } else {
      console.error(chalk.red("\n  ❌ Fatal error:"), err);
    }
    return 1;
  }

  // Register graceful shutdown handler
  const cleanup = async () => {
    await proxy.stop();
    if (logFilePath) {
      try {
        fs.appendFileSync(
          logFilePath,
          `\n--- MCP PROXY LOG END: ${new Date().toISOString()} ---\n`,
          "utf8",
        );
      } catch {}
    }
  };
  registerCleanup(cleanup);

  /**
   * Helper to handle interactive session save at the end
   */
  const handleSessionSave = async () => {
    if (sessionEvents.length === 0) return;

    console.log(chalk.bold.white(`\n  📊 ${t("proxy_session_ended")}`));

    // 1. Clear Y/n confirmation
    const { shouldSave } = await inquirer.prompt([
      {
        type: "confirm",
        name: "shouldSave",
        message: t("proxy_save_question"),
        default: true,
      },
    ]);

    if (!shouldSave) return;

    // 2. Format selection
    const { format } = await inquirer.prompt([
      {
        type: "list",
        name: "format",
        message: t("proxy_save_format_question") || "Select export format:",
        choices: [
          { name: t("proxy_save_txt"), value: "txt" },
          { name: t("proxy_save_json"), value: "json" },
          { name: t("proxy_save_md") || "Save as .md (Markdown)", value: "md" },
        ],
      },
    ]);

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const defaultName = `proxy-session-${timestamp}.${format}`;

    const { filename } = await inquirer.prompt([
      {
        type: "input",
        name: "filename",
        message: t("proxy_filename_prompt"),
        default: defaultName,
      },
    ]);

    const outputDir = "./reports/proxy";
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    const finalPath = path.join(outputDir, filename);

    try {
      if (format === "json") {
        fs.writeFileSync(
          finalPath,
          JSON.stringify(sessionEvents, null, 2),
          "utf8",
        );
      } else if (format === "md") {
        const mdHeader = `# MCP Proxy Session Log\n\n> Target: ${target}\n> Date: ${new Date().toLocaleString()}\n\n---\n\n`;
        const textContent = sessionEvents
          .map(
            (e) =>
              `\`${formatTime(e.timestamp)}\` **${e.type.toUpperCase()}**: ${formatAuditEvent(e).split(": ").slice(1).join(": ")}`,
          )
          .join("\n\n");
        fs.writeFileSync(finalPath, mdHeader + textContent, "utf8");
      } else {
        const textContent = sessionEvents
          .map((e) => formatAuditEvent(e))
          .join("\n");
        fs.writeFileSync(finalPath, textContent, "utf8");
      }
      console.log(
        chalk.green(
          `\n  ✓ ${t("comparison_saved_at").replace("{path}", "")} ${chalk.white(finalPath)}\n`,
        ),
      );
    } catch (err) {
      console.error(
        chalk.red(`\n  ✗ ${t("error")}: ${(err as Error).message}\n`),
      );
    }
  };

  // Handle optional auto-stop timeout
  const timeoutMs = options.timeout ? parseInt(String(options.timeout), 10) : 0;
  if (timeoutMs > 0) {
    console.log(chalk.gray(t("proxy_auto_stopping", { ms: timeoutMs })));
    return new Promise<number>((resolve) => {
      setTimeout(async () => {
        await cleanup();
        await handleSessionSave();
        console.log(chalk.yellow(`\n✅ ${t("goodbye")}`));
        resolve(0);
      }, timeoutMs);
    });
  }

  // Flag to prevent race conditions during shutdown
  let isStopping = false;

  // Keep the process alive indefinitely until 'q' is pressed or SIGINT received
  return new Promise<number>((resolve) => {
    // Setup keypress listener
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding("utf8");

      const onKeypress = async (data: string) => {
        if (isStopping) return;

        // 'q' or 'Q' or Ctrl+C (\u0003)
        if (data === "q" || data === "Q" || data === "\u0003") {
          isStopping = true;

          // CRITICAL: Cleanup stdin state BEFORE any other operation
          process.stdin.removeListener("data", onKeypress);
          process.stdin.setRawMode(false);
          // Pause stdin to flush any pending keys that might interfere with Inquirer
          process.stdin.pause();

          await cleanup();

          // Re-resume for Inquirer
          process.stdin.resume();
          await handleSessionSave();
          resolve(0);
        }
        // Implicitly: every other key is ignored and not echoed (thanks to rawMode)
      };

      process.stdin.on("data", onKeypress);
    } else {
      // Fallback for non-TTY environments
      process.once("SIGINT", async () => {
        if (isStopping) return;
        isStopping = true;
        await cleanup();
        resolve(0);
      });
    }

    // Handle optional auto-stop timeout
    const timeoutMs = options.timeout
      ? parseInt(String(options.timeout), 10)
      : 0;
    if (timeoutMs > 0) {
      setTimeout(async () => {
        if (isStopping) return;
        isStopping = true;

        if (process.stdin.isTTY) {
          process.stdin.setRawMode(false);
          process.stdin.pause();
        }

        await cleanup();
        if (process.stdin.isTTY) process.stdin.resume();
        await handleSessionSave();
        resolve(0);
      }, timeoutMs);
    }
  });
}
