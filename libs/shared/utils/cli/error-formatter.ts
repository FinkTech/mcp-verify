/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Error Formatter
 *
 * Error Formatter
 *
 * Categorizes errors and generates useful messages without noisy stacktraces.
 * Provides contextual tips based on the error type.
 */

import { t } from "./i18n-helper";

export interface FormattedError {
  title: string;
  message: string;
  tips: string[];
  technicalDetails?: string;
}

export type ErrorCategory =
  | "connection"
  | "dns"
  | "protocol"
  | "auth"
  | "timeout"
  | "unknown";

interface ErrorContext {
  command?: string;
  target?: string;
}

/**
 * Categorizes an error based on its message and properties
 */
function categorizeError(error: Error | unknown): ErrorCategory {
  const errorMessage = (
    error instanceof Error ? error.message : String(error)
  ).toLowerCase();
  const errorCode = (error as NodeJS.ErrnoException).code;

  // Connection errors
  if (
    errorCode === "ECONNREFUSED" ||
    errorMessage.includes("connection refused")
  ) {
    return "connection";
  }

  // DNS errors
  if (
    errorCode === "ENOTFOUND" ||
    errorMessage.includes("not found") ||
    errorMessage.includes("getaddrinfo")
  ) {
    return "dns";
  }

  // Timeout errors
  if (
    errorCode === "ETIMEDOUT" ||
    errorMessage.includes("timeout") ||
    errorMessage.includes("timed out")
  ) {
    return "timeout";
  }

  // Protocol/parsing errors
  if (
    errorMessage.includes("json") ||
    errorMessage.includes("parse") ||
    errorMessage.includes("jsonrpc")
  ) {
    return "protocol";
  }

  // Auth errors
  if (
    errorMessage.includes("401") ||
    errorMessage.includes("403") ||
    errorMessage.includes("unauthorized")
  ) {
    return "auth";
  }

  return "unknown";
}

/**
 * Generates useful tips based on the error category
 */
function generateTips(
  category: ErrorCategory,
  context?: ErrorContext,
): string[] {
  const target = context?.target || "the server";
  const command = context?.command || "mcp-verify";

  switch (category) {
    case "connection":
      return [
        t("tip_check_process_generic"),
        t("tip_verify_port"),
        `${t("try_prefix")} ${command} doctor ${target}`,
      ];

    case "dns":
      return [
        `${t("tip_verify_url")} ${target}`,
        t("tip_verify_dns_generic", {
          host: target.replace(/^https?:\/\//, "").split(":")[0],
        }),
        t("tip_use_ip"),
      ];

    case "timeout":
      return [
        t("tip_slow_server"),
        t("tip_increase_timeout_30"),
        t("tip_check_logs"),
      ];

    case "protocol":
      return [
        t("tip_protocol_mismatch"),
        t("tip_verify_mcp_server"),
        t("tip_check_logs"),
        t("tip_use_verbose_raw"),
      ];

    case "auth":
      return [
        t("tip_auth_creds"),
        t("tip_verify_tokens"),
        t("tip_check_permissions"),
      ];

    case "unknown":
      return [
        t("tip_verbose"),
        `${t("try_prefix")} ${command} doctor ${target}`,
        `${t("common_solutions")}: mcp-verify examples`,
      ];
  }
}

/**
 * Formats an error into a user-friendly message
 *
 * @param error - The error to format
 * @param context - Additional context (command, target)
 * @param verbose - If true, includes technical details
 * @returns Formatted error with title, message and tips
 */
export function formatError(
  error: Error | unknown,
  context?: ErrorContext,
  verbose = false,
): FormattedError {
  const category = categorizeError(error);
  const errorMessage = error instanceof Error ? error.message : String(error);
  const errorStack = error instanceof Error ? error.stack : undefined;

  let title: string;
  let message: string;

  switch (category) {
    case "connection":
      title = t("err_conn_title");
      message = t("err_conn_msg", {
        target: context?.target ? ` at ${context.target}` : "",
      });
      break;

    case "dns":
      title = t("err_dns_title");
      message = t("err_dns_msg", {
        target: context?.target ? `: ${context.target}` : "",
      });
      break;

    case "timeout":
      title = t("err_timeout_title");
      message = t("err_timeout_msg", {
        target: context?.target ? ` (${context.target})` : "",
      });
      break;

    case "protocol":
      title = t("err_protocol_title");
      message = `${t("err_protocol_msg")}\n${errorMessage}`;
      break;

    case "auth":
      title = t("err_auth_title");
      message = t("err_auth_msg");
      break;

    case "unknown":
    default:
      title = context?.command
        ? t("err_cmd_failed", { command: context.command })
        : t("err_unknown_title");
      message = errorMessage;
      break;
  }

  const tips = generateTips(category, context);

  const formatted: FormattedError = {
    title,
    message,
    tips,
  };

  // Only include technical details if verbose=true
  if (verbose && errorStack) {
    formatted.technicalDetails = errorStack;
  }

  return formatted;
}
