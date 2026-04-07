/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Command Router & Dispatcher
 *
 * Extracted from interactive.ts - Section 9
 */

import readline from "readline";
import chalk from "chalk";
import { spawn } from "child_process";
import { t } from "@mcp-verify/shared";
import { ASCII_ART } from "@mcp-verify/core/domain/reporting/assets";

// Version hardcoded for bundle compatibility
const packageJson = { version: "1.0.0" };

import type { ShellSession } from "./session";
import { PersistenceManager } from "./persistence";

// Import all handlers
import { handleValidate } from "./handlers/validate";
import { handleFuzz } from "./handlers/fuzz";
import { handleDoctor } from "./handlers/doctor";
import { handleStress } from "./handlers/stress";
import { handleDashboard } from "./handlers/dashboard";
import { handlePlay } from "./handlers/play";
import { handleProxy } from "./handlers/proxy";
import { handleMock } from "./handlers/mock";
import { handleInit } from "./handlers/init";
import { handleFingerprint } from "./handlers/fingerprint";
import { handleInspect } from "./handlers/inspect";
import { handleExamples } from "./handlers/examples";
import {
  handleSet,
  handleTargetChange,
  handleLanguageChange,
  handleConfig,
  showHistory,
} from "./handlers/session";
import { showHelp, showAbout } from "./handlers/info";
import { handleContextClone } from "./handlers/context-clone";
import {
  handleContextList,
  handleContextSwitch,
  handleContextCreate,
  handleContextDelete,
} from "../handlers/context-handlers";
import { handleProfileCommand } from "../handlers/profile-handlers";
import { handleStatus } from "../handlers/status-handler";

// ============================================================================
// ─── Primary Commands List (for autocomplete and suggestions) ───────────────
// ============================================================================

const PRIMARY_COMMANDS: readonly string[] = [
  "validate",
  "fuzz",
  "doctor",
  "stress",
  "dashboard",
  "play",
  "proxy",
  "mock",
  "init",
  "fingerprint",
  "inspect",
  "examples",
  "history",
  "config",
  "context",
  "profile",
  "status",
  "target",
  "set",
  "lang",
  "help",
  "about",
  "exit",
];

// ============================================================================
// ─── Main Dispatcher ────────────────────────────────────────────────────────
// ============================================================================

export async function dispatch(
  cmd: string,
  args: string[],
  session: ShellSession,
  rl: readline.Interface,
): Promise<void> {
  switch (cmd) {
    // Security tools
    case "validate":
    case "v":
      await handleValidate(args, session, rl);
      break;
    case "fuzz":
    case "f":
      await handleFuzz(args, session, rl);
      break;
    case "doctor":
    case "d":
      await handleDoctor(args, session, rl);
      break;
    case "stress":
    case "s":
      await handleStress(args, session, rl);
      break;
    case "dashboard":
      await handleDashboard(args, session, rl);
      break;
    case "play":
      await handlePlay(args, session, rl);
      break;
    case "proxy":
      await handleProxy(args, session, rl);
      break;
    case "mock":
    case "m":
      await handleMock(args);
      break;
    case "init":
      await handleInit(args);
      break;
    case "fingerprint":
    case "stack":
      await handleFingerprint(args, session, rl);
      break;
    case "inspect":
    case "ls":
      await handleInspect(args, session, rl);
      break;
    case "examples":
    case "ex":
      await handleExamples();
      break;

    // Session management
    case "set":
      handleSet(args, session);
      break;
    case "target":
      handleTargetChange(args, session);
      break;
    case "lang":
    case "language":
      handleLanguageChange(args, session);
      break;
    case "config":
    case "cfg":
      handleConfig(session);
      break;
    case "history":
      showHistory(session, args);
      break;

    // Multi-context workspace
    case "context":
      await handleContextDispatch(args, session);
      break;
    case "profile":
      handleProfileCommand(args, session);
      break;
    case "status":
      await handleStatus(session);
      break;

    // Info
    case "about":
      showAbout();
      break;
    case "version":
      console.log(chalk.cyan(ASCII_ART.version(packageJson.version)));
      break;
    case "help":
    case "h":
      showHelp();
      break;

    // Links
    case "github":
    case "gh":
      openUrl("https://github.com/FinkTech/mcp-verify");
      break;
    case "linkedin":
    case "li":
      openUrl("https://linkedin.com/in/ariel-fink");
      break;
    case "website":
    case "web":
      openUrl("https://github.com/FinkTech/mcp-verify");
      break;

    // Shell utilities
    case "clear":
    case "cls":
      console.clear();
      console.log(chalk.bold.cyan(`\n  ${t("interactive_shell")}\n`));
      break;

    case "exit":
    case "quit":
    case "q":
      showSessionSummary(session);
      process.exit(0);
      break;

    default: {
      console.log(
        chalk.red(`  ${t("interactive_unknown_command")}: ${chalk.white(cmd)}`),
      );
      const suggestions = getSimilarCommands(cmd);
      if (suggestions.length) {
        console.log(
          chalk.yellow("  Did you mean: ") +
            chalk.cyan(suggestions.slice(0, 3).join(", ")) +
            "?",
        );
      }
      console.log(
        chalk.dim(`  Type ${chalk.white("help")} to list all commands.\n`),
      );
    }
  }
}

// ============================================================================
// ─── Context Command Sub-Dispatcher ─────────────────────────────────────────
// ============================================================================

async function handleContextDispatch(
  args: string[],
  session: ShellSession,
): Promise<void> {
  if (args.length === 0) {
    showContextHelp();
    return;
  }

  const [subcommand, ...rest] = args;

  switch (subcommand) {
    case "list":
      handleContextList(session);
      break;

    case "switch":
      handleContextSwitch(rest, session);
      break;

    case "create":
      handleContextCreate(rest, session);
      break;

    case "clone":
      handleContextClone(rest, session);
      break;

    case "delete":
      handleContextDelete(rest, session);
      break;

    default:
      console.log(chalk.red(`✗ Unknown context subcommand: ${subcommand}`));
      showContextHelp();
  }
}

function showContextHelp(): void {
  console.log(chalk.bold.white("\n  Context Commands:\n"));
  console.log(
    `    ${chalk.cyan("context list")}                            List all contexts`,
  );
  console.log(
    `    ${chalk.cyan("context switch <name>")}                   Switch to a context`,
  );
  console.log(
    `    ${chalk.cyan("context create <name>")}                   Create a new context`,
  );
  console.log(
    `    ${chalk.cyan("context clone <source> <new_name>")}      Clone an existing context`,
  );
  console.log(
    `    ${chalk.cyan("context delete <name>")}                   Delete a context`,
  );
  console.log(chalk.dim("\n  Clone examples:"));
  console.log(chalk.dim("    context clone dev staging"));
  console.log(
    chalk.dim(
      '    context clone dev prod --target "http://prod.example.com"\n',
    ),
  );
}

// ============================================================================
// ─── Utility Functions ──────────────────────────────────────────────────────
// ============================================================================

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

function openUrl(url: string): void {
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

function levenshteinDistance(a: string, b: string): number {
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

function getSimilarCommands(input: string): string[] {
  const lc = input.toLowerCase();
  return (PRIMARY_COMMANDS as string[])
    .map((c) => ({ c, d: levenshteinDistance(lc, c) }))
    .filter(({ d }) => d <= 2)
    .sort((a, b) => a.d - b.d)
    .map(({ c }) => c);
}
