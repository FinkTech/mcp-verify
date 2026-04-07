/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Utility functions for Interactive Shell
 *
 * Extracted from interactive.ts - Sections 6, 7, 12, 14
 *
 * Functions:
 * - withRedirect: Output redirection wrapper
 * - buildPrompt: Dynamic prompt generation
 * - showSessionSummary: Exit summary
 * - openUrl: Cross-platform URL launcher
 * - levenshteinDistance: String similarity
 * - getSimilarCommands: Command suggestions
 */

import fs from "fs";
import path from "path";
import chalk from "chalk";
import { spawn } from "child_process";
import { t } from "@mcp-verify/shared";
import { PersistenceManager } from "./persistence";
import type { ParseResult } from "./types";
import type { ShellSession } from "./session";
import { PRIMARY_COMMANDS } from "./completer";

/**
 * Executes `action()` with captured stdout/stderr if redirection exists.
 * Restores console.log/error/warn even if the action throws an exception.
 * Removes ANSI codes from text written to file.
 */
export async function withRedirect<T>(
  parsed: ParseResult,
  action: () => Promise<T>,
): Promise<T> {
  if (!parsed.redirectTo) return action();

  const captured: string[] = [];
  const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
  const origLog = console.log.bind(console);
  const origError = console.error.bind(console);
  const origWarn = console.warn.bind(console);
  const capture = (...args: unknown[]) =>
    captured.push(args.map((a) => stripAnsi(String(a))).join(" "));

  console.log = capture;
  console.error = capture;
  console.warn = capture;

  let result: T;
  try {
    result = await action();
  } finally {
    console.log = origLog;
    console.error = origError;
    console.warn = origWarn;
  }

  try {
    PersistenceManager.writeOutput(
      parsed.redirectTo,
      captured.join("\n"),
      parsed.redirectAppend,
    );
    const op = parsed.redirectAppend ? ">>" : ">";
    origLog(
      chalk.green(
        `  ✓ Output redirected: ${op} ${chalk.white(parsed.redirectTo)}` +
          chalk.dim(` (${captured.length} lines)\n`),
      ),
    );
  } catch (e) {
    origError(
      chalk.red(
        `  ✗ Redirect failed: ${e instanceof Error ? e.message : String(e)}\n`,
      ),
    );
  }

  return result!;
}

/**
 * Builds dynamic prompt with workspace + context + profile + target
 */
export function buildPrompt(session: ShellSession): string {
  const { workspace } = session.state;
  const context = session.getActiveContext();
  const contextName = session.state.activeContextName;
  const profileName = context.profile.name;

  const wsPart = workspace ? chalk.dim.yellow(`[${workspace}] `) : "";

  // Show context:profile if not default, otherwise just profile
  const contextPart =
    contextName !== "default"
      ? chalk.dim.cyan(`(${contextName}:${profileName}) `)
      : chalk.dim.cyan(`(${profileName}) `);

  const tPart = context.target
    ? chalk.dim(
        `${context.target.length > 30 ? "…" + context.target.slice(-28) : context.target} `,
      )
    : "";

  return (
    wsPart +
    chalk.bold.green("mcp-verify ") +
    contextPart +
    tPart +
    chalk.bold.green("> ")
  );
}

/**
 * Shows session summary on exit
 */
export function showSessionSummary(session: ShellSession): void {
  const { history, target, startedAt } = session.state;

  const now = new Date();
  const elapsedMs = now.getTime() - startedAt.getTime();
  const seconds = Math.floor(elapsedMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  const formattedTime = `${minutes}m ${remainingSeconds}s`;

  console.log(
    chalk.bold.white("\n  ── Session Summary ─────────────────────────\n"),
  );
  console.log(`  ${chalk.gray("Duration:")}   ${chalk.cyan(formattedTime)}`);
  console.log(
    `  ${chalk.gray("Commands:")}   ${chalk.cyan(String(history.length))}`,
  );
  if (target) {
    console.log(`  ${chalk.gray("Target:")}     ${chalk.cyan(target)}`);
  }
  const paths = PersistenceManager.getPaths();
  console.log(chalk.dim(`\n  History saved → ${paths.historyFile}`));
  console.log(chalk.gray(`\n  ${t("goodbye")}\n`));
}

/**
 * Opens URL in default browser (cross-platform)
 */
export function openUrl(url: string): void {
  try {
    new URL(url);
  } catch {
    console.log(chalk.red(`\n  Invalid URL: ${url}\n`));
    return;
  }

  console.log(chalk.gray(`\n  ${t("opening")}: ${chalk.cyan(url)}\n`));

  const [cmd, ...spawnArgs] =
    process.platform === "win32"
      ? ["cmd", "/c", "start", "", url]
      : process.platform === "darwin"
        ? ["open", url]
        : ["xdg-open", url];

  const child = spawn(cmd, spawnArgs, {
    shell: false,
    stdio: "ignore",
    detached: true,
  });
  child.on("error", () =>
    console.log(
      chalk.yellow(
        `  Could not open browser. Visit manually: ${chalk.cyan(url)}\n`,
      ),
    ),
  );
  child.unref();
}

/**
 * Calculates Levenshtein distance between two strings
 */
export function levenshteinDistance(a: string, b: string): number {
  let prev = Array.from({ length: a.length + 1 }, (_, i) => i);
  for (let j = 1; j <= b.length; j++) {
    const curr = [j, ...new Array<number>(a.length).fill(0)];
    for (let i = 1; i <= a.length; i++) {
      curr[i] =
        a[i - 1] === b[j - 1]
          ? prev[i - 1]
          : 1 + Math.min(prev[i - 1], prev[i], curr[i - 1]);
    }
    prev = curr;
  }
  return prev[a.length];
}

/**
 * Returns similar commands using Levenshtein distance
 */
export function getSimilarCommands(input: string): string[] {
  const lc = input.toLowerCase();
  return (PRIMARY_COMMANDS as string[])
    .map((c) => ({ c, d: levenshteinDistance(lc, c) }))
    .filter(({ d }) => d <= 2)
    .sort((a, b) => a.d - b.d)
    .map(({ c }) => c);
}
