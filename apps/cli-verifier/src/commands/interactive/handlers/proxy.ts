/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Proxy Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from "readline";
import chalk from "chalk";
import { runProxyAction } from "../../proxy";
import { ShellParser } from "../parser";
import type { ShellSession } from "../session";
import { resolveTarget } from "./shared";

export async function handleProxy(
  args: string[],
  session: ShellSession,
  rl: readline.Interface,
): Promise<void> {
  const flags = ShellParser.extractFlags(args);
  const positionals = ShellParser.extractPositionals(args);

  // Check for help request
  if (
    positionals.includes("help") ||
    positionals.includes("h") ||
    flags["help"]
  ) {
    showProxyHelp();
    return;
  }

  const target = await resolveTarget(
    args,
    session,
    rl,
    'proxy "node server.js" --port 9000',
  );
  if (!target) return;

  session.setTarget(target);
  const options: Record<string, string | true> = {
    port: "9000",
    lang: session.state.lang,
    ...flags,
  };

  console.log("");
  await runProxyAction(target, options);
  console.log("");
}

function showProxyHelp(): void {
  console.log(chalk.bold.white("\n  🛡️  Security Proxy Help:\n"));
  console.log(
    `    ${chalk.cyan("proxy <target>")}           Starts a security gateway between client and server`,
  );
  console.log("");
  console.log(chalk.white("    Options:"));
  console.log(
    `      ${chalk.yellow("--port <number>")}       Port to listen on (default: 9000)`,
  );
  console.log(
    `      ${chalk.yellow("--log-file <path>")}     Save session logs to a file`,
  );
  console.log(
    `      ${chalk.yellow("--timeout <ms>")}        Auto-stop proxy after X milliseconds`,
  );
  console.log("");
  console.log(chalk.white("    Guardrails Active:"));
  console.log("      • Sensitive Command Blocker (Blocks shell injection)");
  console.log("      • PII Redactor (Masks sensitive data like SSN, Keys)");
  console.log("      • Rate Limiter (Prevents DoS/Abuse)");
  console.log("      • Input Sanitizer (SQL/Command clean-up)");
  console.log("      • HTTPS Enforcer (Forces secure upstream calls)");
  console.log("");
  console.log(chalk.dim("    Usage Example:"));
  console.log(
    chalk.gray(
      '      proxy "node server.js" --port 8080 --log-file audit.log\n',
    ),
  );
}
