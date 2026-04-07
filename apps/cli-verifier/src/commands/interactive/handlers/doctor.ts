/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Doctor Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import readline from "readline";
import { runDoctorAction } from "../../doctor";
import { ShellParser } from "../parser";
import type { ShellSession } from "../session";
import { resolveTarget } from "./shared";

export async function handleDoctor(
  args: string[],
  session: ShellSession,
  rl: readline.Interface,
): Promise<void> {
  const flags = ShellParser.extractFlags(args);
  // --server flag takes precedence over the first positional argument
  const target =
    (typeof flags["server"] === "string" ? flags["server"] : undefined) ??
    (await resolveTarget(args, session, rl, 'doctor "node server.js"'));
  if (!target) return;

  session.setTarget(target);

  const options: Record<string, string | true> = {
    server: target,
    lang: session.state.lang,
    ...flags,
  };

  console.log("");
  await runDoctorAction(target, options);
  console.log("");
}
