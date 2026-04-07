/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Fuzz Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from "readline";
import chalk from "chalk";
import { runFuzzAction } from "../../fuzz";
import { ShellParser } from "../parser";
import type { ShellSession } from "../session";
import { resolveTarget, mergeOptions } from "./shared";

export async function handleFuzz(
  args: string[],
  session: ShellSession,
  rl: readline.Interface,
): Promise<void> {
  const target = await resolveTarget(
    args,
    session,
    rl,
    'fuzz "node server.js" --tool "Echo Tool"',
  );
  if (!target) return;

  session.setTarget(target);
  const flags = ShellParser.extractFlags(args);
  const merged = mergeOptions("fuzz", session, flags);

  // Apply security profile settings
  const context = session.getActiveContext();
  const profile = context.profile;

  const options: Record<string, unknown> = {
    transport: "http",
    concurrency: "1",
    timeout: "5000",
    lang: session.state.lang,

    // Apply profile settings
    maxPayloadsPerTool: String(profile.fuzzing.maxPayloadsPerTool),
    useMutations: profile.fuzzing.useMutations,
    mutationsPerPayload: profile.fuzzing.mutationsPerPayload,
    enableFeedbackLoop: profile.fuzzing.enableFeedbackLoop,

    enablePromptInjection: profile.generators.enablePromptInjection,
    enableClassicPayloads: profile.generators.enableClassicPayloads,
    enablePrototypePollution: profile.generators.enablePrototypePollution,
    enableJwtAttacks: profile.generators.enableJwtAttacks,

    enableTimingDetection: profile.detectors.enableTimingDetection,
    timingAnomalyMultiplier: profile.detectors.timingAnomalyMultiplier,
    enableErrorDetection: profile.detectors.enableErrorDetection,

    // Merged options and flags override profile
    ...merged,
  };

  console.log(chalk.dim(`  Using profile: ${chalk.yellow(profile.name)}`));
  console.log("");
  await runFuzzAction(target, options);
  console.log("");
}
