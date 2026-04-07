/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Transport Factory
 *
 * Factory for creating HTTP, SSE, or STDIO transports based on target and options.
 *
 * NOTE: SSE (Server-Sent Events) is handled by HttpTransport internally using EventSource.
 * There is no separate SseTransport class - HttpTransport detects and uses SSE automatically.
 */

import { HttpTransport, StdioTransport, ITransport } from "@mcp-verify/core";
import { SmartLauncher, t } from "@mcp-verify/shared";
import { DenoSandbox } from "@mcp-verify/core/infrastructure/sandbox/deno-sandbox";
import chalk from "chalk";

export interface TransportOptions {
  transportType?: "http" | "sse" | "stdio"; // 'sse' is an alias for 'http' (both use HttpTransport)
  envVars?: Record<string, string>;
  sandbox?: DenoSandbox;
  verbose?: boolean;
  timeout?: number;
  lang?: string;
  headers?: Record<string, string>;
}

/**
 * Create a transport based on target URL/command and options
 * @param target URL (http://, https://) or command path
 * @param options Transport options
 * @returns Configured ITransport instance
 */
export function createTransport(
  target: string,
  options: TransportOptions = {},
): ITransport {
  const {
    transportType = "stdio",
    envVars = {},
    sandbox,
    verbose = false,
    timeout = 10000,
    lang,
    headers = {},
  } = options;

  let transport: ITransport;

  // Both 'http' and 'sse' use HttpTransport (SSE is handled internally via EventSource)
  if (transportType === "http" || transportType === "sse") {
    transport = HttpTransport.create(target, timeout, headers);

    if (verbose && transportType === "sse") {
      console.log(
        chalk.gray(`\n> ${t("detected_transport")}: SSE (Server-Sent Events)`),
      );
    }
  } else {
    // Try to detect runtime automatically
    const detection = SmartLauncher.detect(target);

    if (detection) {
      const args = [...detection.args];
      transport = StdioTransport.create(
        detection.command,
        args,
        timeout,
        envVars,
        sandbox,
      );
      if (verbose) {
        console.log(
          chalk.gray(
            `\n> ${t("detected_runtime")}: ${detection.command} ${args.join(" ")}`,
          ),
        );
      }
    } else {
      // ✅ FIX: Parse command and args from target string with quote support
      // Matches arguments that are either quoted strings or non-whitespace sequences
      const parts = target.match(/[^\s"]+|"([^"]*)"/g) || [];

      // Remove quotes from parts if present
      const cleanParts = parts.map((p) =>
        p.startsWith('"') && p.endsWith('"') ? p.slice(1, -1) : p,
      );

      if (cleanParts.length === 0) {
        throw new Error(t("invalid_command_format"));
      }

      const command = cleanParts[0];
      const args = cleanParts.slice(1);

      transport = StdioTransport.create(
        command,
        args,
        timeout,
        envVars,
        sandbox,
      );

      if (verbose) {
        console.log(chalk.gray(`\n> Fallback: ${command} ${args.join(" ")}`));
      }
    }
  }

  return transport;
}

/**
 * Determine transport type from target string intelligently
 * @param target URL or command path
 * @returns 'http', 'sse', or 'stdio'
 */
export function detectTransportType(target: string): "http" | "sse" | "stdio" {
  // Check if it's an HTTP/HTTPS URL
  if (target.startsWith("http://") || target.startsWith("https://")) {
    // Detect SSE endpoints by common patterns
    const ssePatterns = [
      "/sse",
      "/events",
      "/stream",
      "/event-stream",
      "/sse/",
      "/events/",
      "/stream/",
      "/event-stream/",
    ];

    const lowerTarget = target.toLowerCase();
    const isSSE = ssePatterns.some(
      (pattern) =>
        lowerTarget.endsWith(pattern) ||
        lowerTarget.includes(pattern + "?") ||
        lowerTarget.includes(pattern + "#"),
    );

    return isSSE ? "sse" : "http";
  }

  // Not HTTP/HTTPS = STDIO
  return "stdio";
}

/**
 * Validate target format
 * @param target URL or command path
 * @returns true if valid
 */
export function isValidTarget(target: string): boolean {
  if (!target || target.trim().length === 0) {
    return false;
  }

  // Check if it's a valid HTTP/HTTPS URL (supports both regular HTTP and SSE)
  if (target.startsWith("http://") || target.startsWith("https://")) {
    try {
      new URL(target);
      return true;
    } catch {
      return false;
    }
  }

  // For STDIO, just check it's not empty
  return true;
}
