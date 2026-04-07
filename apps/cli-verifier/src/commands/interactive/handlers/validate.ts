/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Validate Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from "readline";
import chalk from "chalk";
import { t } from "@mcp-verify/shared";
import { runValidationAction } from "../../validate";
import { ShellParser } from "../parser";
import type { ShellSession } from "../session";
import { resolveTarget, mergeOptions } from "./shared";

export async function handleValidate(
  args: string[],
  session: ShellSession,
  rl: readline.Interface,
): Promise<void> {
  const target = await resolveTarget(
    args,
    session,
    rl,
    'validate "node server.js"',
  );
  if (!target) return;

  session.setTarget(target);
  const flags = ShellParser.extractFlags(args);
  const merged = mergeOptions("validate", session, flags);

  // Apply security profile settings
  const context = session.getActiveContext();
  const profile = context.profile;

  const options: Record<string, unknown> = {
    server: target,
    output: "./reports",
    lang: session.state.lang,

    // Apply profile validation settings
    minSecurityScore: profile.validation.minSecurityScore,
    failOnCritical: profile.validation.failOnCritical,
    failOnHigh: profile.validation.failOnHigh,

    // Merged options and flags override profile
    ...merged,
  };

  console.log(
    chalk.dim(
      `  ${t("interactive_using_profile")}: ${chalk.yellow(profile.name)}`,
    ),
  );
  console.log("");
  await runValidationAction(target, options);
  console.log("");
}
