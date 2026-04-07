/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Session Management Handlers
 *
 * Extracted from interactive.ts - Section 11
 */

import fs from "fs";
import chalk from "chalk";
import { t, saveLanguagePreference } from "@mcp-verify/shared";
import { ShellParser } from "../parser";
import { PersistenceManager } from "../persistence";
import type { Language } from "../types";
import type { ShellSession } from "../session";
import { validateTargetWithFeedback } from "./shared";

export function handleSet(args: string[], session: ShellSession): void {
  if (args.length < 2) {
    console.log(chalk.yellow(`  ${t("interactive_set_usage")}`));
    console.log(chalk.dim(`  ${t("interactive_set_keys")}\n`));
    return;
  }

  const [key, ...rest] = args;
  const value = rest.join(" ");

  switch (key) {
    case "target":
      session.setTarget(value);
      console.log(
        chalk.green(`  ✓ ${t("interactive_target")}: ${chalk.white(value)}\n`),
      );
      break;
    case "lang":
    case "language":
      applyLanguageChange(value, session);
      break;
    default:
      // Store arbitrary config (e.g. validate.output)
      session.getActiveContext().config[key] = value;
      console.log(
        chalk.green(
          `  ✓ ${t("interactive_config_set")}: ${chalk.white(key)} = ${chalk.white(value)}\n`,
        ),
      );
  }
}

export function handleTargetChange(
  args: string[],
  session: ShellSession,
): void {
  if (args.length === 0) {
    const currentTarget =
      session.state.target ?? chalk.dim(t("interactive_not_set"));
    console.log(
      chalk.bold.white(
        `\n  ${t("interactive_current_target")}: ${chalk.cyan(currentTarget)}`,
      ),
    );
    console.log(chalk.dim(`  ${t("interactive_target_usage")}`));
    console.log(chalk.dim(`  ${t("target_examples_title")}`));
    console.log(chalk.dim(`    ${t("target_example_node")}`));
    console.log(chalk.dim(`    ${t("target_example_http")}`));
    console.log(chalk.dim(`    ${t("target_example_npx")}\n`));
    return;
  }
  const value = args.join(" ");

  // Validate and show detection feedback
  const detection = validateTargetWithFeedback(value);

  session.setTarget(value);

  if (detection.valid) {
    console.log(
      chalk.green(`  ✓ ${t("interactive_target")}: ${chalk.white(value)}`),
    );
    console.log(chalk.gray(`    ${detection.message}\n`));
  } else {
    console.log(
      chalk.yellow(
        `  ⚠️  ${t("interactive_target_set_warning")}: ${chalk.white(value)}`,
      ),
    );
    console.log(chalk.yellow(`    ${detection.message}`));
    console.log(chalk.dim(`    ${t("target_validation_will_likely_fail")}\n`));
  }
}

export function handleLanguageChange(
  args: string[],
  session: ShellSession,
): void {
  if (args.length === 0) {
    console.log(
      chalk.bold.white(
        `\n  ${t("interactive_current_language")}: ${chalk.cyan(session.state.lang)}`,
      ),
    );
    console.log(chalk.dim(`  ${t("interactive_lang_usage")}\n`));
    return;
  }
  applyLanguageChange(args[0], session);
}

function applyLanguageChange(value: string, session: ShellSession): void {
  const lang = value.toLowerCase();
  if (lang !== "en" && lang !== "es") {
    console.log(chalk.red(`  ${t("interactive_invalid_language")}: ${lang}`));
    console.log(chalk.dim(`  ${t("interactive_available_langs")}\n`));
    return;
  }
  session.setLanguage(lang as Language);
  saveLanguagePreference(lang as Language);
  console.log(
    chalk.green(`  ✓ ${t("interactive_lang_success")}: ${chalk.white(lang)}\n`),
  );
}

export function handleConfig(session: ShellSession): void {
  const { target, lang, history, workspace, startedAt } = session.state;

  const now = new Date();
  const elapsedMs = now.getTime() - startedAt.getTime();
  const seconds = Math.floor(elapsedMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  const formattedTime = `${minutes}m ${remainingSeconds}s`;

  console.log(chalk.bold.white(`\n  ${t("interactive_config_title")}:\n`));
  console.log(
    `  ${chalk.gray(t("interactive_workspace"))}   ${chalk.cyan(workspace ?? chalk.dim(t("interactive_none")))}`,
  );
  console.log(
    `  ${chalk.gray(t("interactive_language"))}    ${chalk.cyan(lang)}`,
  );

  // SECURITY: Redact target if it contains secrets
  const safeTarget = target
    ? session.redactSecrets(target)
    : chalk.dim(t("interactive_not_set"));
  console.log(
    `  ${chalk.gray(t("interactive_target"))}      ${chalk.cyan(safeTarget)}`,
  );

  // SECURITY: Redact config before displaying
  const redactedConfig = session.redactConfig(session.state.config);
  const extras = Object.entries(redactedConfig);
  if (extras.length > 0) {
    console.log(chalk.bold.white(`\n  ${t("interactive_config")}:`));
    for (const [k, v] of extras) {
      console.log(`  ${chalk.gray(k + ":")} ${chalk.cyan(String(v))}`);
    }
  }

  console.log(
    `\n  ${chalk.gray(t("interactive_commands"))}    ${chalk.cyan(String(history.length))} ${t("interactive_this_session")}`,
  );
  console.log(
    `  ${chalk.gray(t("interactive_elapsed"))}     ${chalk.cyan(formattedTime)}`,
  );
  console.log(
    `  ${chalk.gray(t("interactive_started"))}     ${chalk.cyan(startedAt.toLocaleTimeString())}`,
  );
  console.log("");
  const paths = PersistenceManager.getPaths();
  console.log(
    `  ${chalk.gray(t("interactive_history_file"))} ${chalk.dim(paths.historyFile)}`,
  );
  const sessionExists = fs.existsSync(paths.sessionFile);
  console.log(
    `  ${chalk.gray(t("interactive_session_file"))} ${chalk.dim(paths.sessionFile)} ` +
      (sessionExists
        ? chalk.green(t("interactive_active"))
        : chalk.dim(t("interactive_not_saved"))),
  );
  console.log("");
}

export function showHistory(session: ShellSession, args: string[]): void {
  const flags = ShellParser.extractFlags(args);

  // --clear: clear history
  if (flags["clear"] === true) {
    try {
      const paths = PersistenceManager.getPaths();
      fs.writeFileSync(paths.historyFile, "[]", "utf8");
      session.state.history.length = 0;
      console.log(chalk.green(`  ✓ ${t("interactive_history_cleared")}\n`));
    } catch {
      console.log(chalk.red(`  ✗ ${t("interactive_history_clear_failed")}\n`));
    }
    return;
  }

  // Merge persistent history + current session
  const persisted = PersistenceManager.loadHistory();
  const sessionOnly = session.state.history.filter(
    (h) => !persisted.includes(h),
  );
  const all = [...persisted, ...sessionOnly];

  const maxShown =
    typeof flags["last"] === "string"
      ? Math.max(1, parseInt(flags["last"], 10) || 25)
      : 25;

  const slice = all.slice(-maxShown);
  const offset = all.length - slice.length;

  console.log(
    chalk.bold.white(
      `\n  ${t("interactive_history_title")} (${all.length} ${t("interactive_history_total")}):\n`,
    ),
  );

  if (slice.length === 0) {
    console.log(chalk.dim(`  ${t("interactive_no_history")}\n`));
    return;
  }

  slice.forEach((cmd, i) => {
    const n = String(offset + i + 1).padStart(4);
    console.log(`  ${chalk.gray(n)}  ${chalk.cyan(cmd)}`);
  });

  if (all.length > maxShown && !flags["last"]) {
    console.log(
      chalk.dim(
        `\n  … ${all.length - maxShown} ${t("interactive_history_more")}\n`,
      ),
    );
  } else {
    console.log("");
  }
}
