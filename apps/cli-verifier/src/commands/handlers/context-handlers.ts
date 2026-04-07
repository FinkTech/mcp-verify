/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Context Command Handlers
 *
 * Handlers for multi-context workspace commands:
 * - context list: Display all contexts
 * - context switch <name>: Switch to a different context
 * - context create <name> [--copy]: Create a new context
 * - context delete <name>: Delete a context
 */

import chalk from "chalk";
import type { ShellSession } from "../interactive/session";

/**
 * Display list of all contexts
 * Shows active context with ● marker, inactive with ○
 *
 * Format:
 * Contexts (3):
 * ● dev        node server.js                           balanced
 * ○ staging    https://staging.example.com/mcp          aggressive
 * ○ prod       https://prod.example.com/mcp             light
 */
export function handleContextList(session: ShellSession): void {
  const contexts = session.listContexts().sort();
  const active = session.state.activeContextName;

  console.log(chalk.bold.white(`\n  Contexts (${contexts.length}):\n`));

  for (const name of contexts) {
    const context = session.state.contexts[name];
    const isActive = name === active;

    // Marker: ● for active, ○ for inactive
    const marker = isActive ? chalk.green("●") : chalk.dim("○");

    // Context name: bold green if active, cyan if inactive
    const nameDisplay = isActive
      ? chalk.green.bold(name.padEnd(12))
      : chalk.cyan(name.padEnd(12));

    // Target: truncate if too long
    const targetRaw = context.target ?? chalk.dim("(not set)");
    const targetDisplay =
      typeof targetRaw === "string" && targetRaw.length > 40
        ? targetRaw.substring(0, 37) + "..."
        : targetRaw;
    const targetPadded = String(targetDisplay).padEnd(40);

    // Profile name
    const profileDisplay = chalk.yellow(context.profile.name);

    console.log(
      `  ${marker} ${nameDisplay}  ${targetPadded}  ${profileDisplay}`,
    );
  }

  console.log(); // Empty line at end
}

/**
 * Switch to a different context
 *
 * @param args - Command arguments [context-name]
 * @param session - Shell session
 */
export function handleContextSwitch(
  args: string[],
  session: ShellSession,
): void {
  if (args.length === 0) {
    console.log(chalk.red("✗ Error: Context name required"));
    console.log(chalk.dim("  Usage: context switch <name>"));
    return;
  }

  const targetName = args[0];

  // Check if already active
  if (targetName === session.state.activeContextName) {
    console.log(chalk.yellow(`⚠ Already on context: ${targetName}`));
    return;
  }

  // Attempt to switch
  const success = session.switchContext(targetName);

  if (success) {
    const context = session.getActiveContext();
    const targetDisplay = context.target
      ? chalk.cyan(context.target)
      : chalk.dim("(not set)");
    const profileDisplay = chalk.yellow(context.profile.name);

    console.log(
      chalk.green(`✓ Switched to context: ${chalk.bold(targetName)}`),
    );
    console.log(chalk.dim(`  Target:  ${targetDisplay}`));
    console.log(chalk.dim(`  Profile: ${profileDisplay}`));
  } else {
    console.log(chalk.red(`✗ Context not found: ${targetName}`));
    console.log(chalk.dim('  Use "context list" to see available contexts'));
  }
}

/**
 * Create a new context
 *
 * @param args - Command arguments [context-name, ...flags]
 * @param session - Shell session
 */
export function handleContextCreate(
  args: string[],
  session: ShellSession,
): void {
  if (args.length === 0) {
    console.log(chalk.red("✗ Error: Context name required"));
    console.log(chalk.dim("  Usage: context create <name> [--copy]"));
    console.log(
      chalk.dim("         --copy: Copy settings from active context"),
    );
    return;
  }

  const targetName = args[0];

  // Check for --copy flag
  const copyFromActive = args.includes("--copy");

  // Attempt to create
  const success = session.createContext(targetName, copyFromActive);

  if (success) {
    const context = session.state.contexts[targetName];
    const profileDisplay = chalk.yellow(context.profile.name);

    console.log(chalk.green(`✓ Created context: ${chalk.bold(targetName)}`));
    console.log(chalk.dim(`  Profile: ${profileDisplay}`));

    if (copyFromActive) {
      console.log(
        chalk.dim(`  (Copied from: ${session.state.activeContextName})`),
      );
    }

    console.log(
      chalk.dim(`\n  Switch to it with: context switch ${targetName}`),
    );
  } else {
    console.log(chalk.red(`✗ Context already exists: ${targetName}`));
    console.log(chalk.dim('  Use "context switch" to switch to it'));
  }
}

/**
 * Delete a context
 *
 * @param args - Command arguments [context-name]
 * @param session - Shell session
 */
export function handleContextDelete(
  args: string[],
  session: ShellSession,
): void {
  if (args.length === 0) {
    console.log(chalk.red("✗ Error: Context name required"));
    console.log(chalk.dim("  Usage: context delete <name>"));
    return;
  }

  const targetName = args[0];

  // Check if trying to delete active context
  if (targetName === session.state.activeContextName) {
    console.log(chalk.red("✗ Cannot delete active context"));
    console.log(chalk.dim("  Switch to another context first"));
    return;
  }

  // Attempt to delete
  const success = session.deleteContext(targetName);

  if (success) {
    console.log(chalk.green(`✓ Deleted context: ${chalk.bold(targetName)}`));
  } else {
    console.log(chalk.red(`✗ Context not found: ${targetName}`));
    console.log(chalk.dim('  Use "context list" to see available contexts'));
  }
}
