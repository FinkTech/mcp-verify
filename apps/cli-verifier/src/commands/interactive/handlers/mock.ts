/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Mock Command Handler
 *
 * Extracted from interactive.ts - Section 10
 */

import { getCurrentLanguage } from "@mcp-verify/shared";
import { runMockAction } from "../../mock";
import { ShellParser } from "../parser";
import type { Language } from "../types";

export async function handleMock(args: string[]): Promise<void> {
  const flags = ShellParser.extractFlags(args);

  const options: Record<string, string | true> = {
    port: "3000",
    lang: getCurrentLanguage() as Language,
    ...flags,
  };

  console.log("");
  await runMockAction(options);
  console.log("");
}
