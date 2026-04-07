/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ContextCompleter — Three-level contextual TAB autocomplete.
 *
 * Level 1   — no space yet              → complete command name
 * Level 2   — partial/full `--` flag    → complete command flags
 * Level 2.5 — after `--tool` flag       → complete available tool names (dynamic)
 * Level 3   — looks like a path         → list filesystem entries
 */

import fs from "fs";
import path from "path";

import { ShellParser } from "./parser";
import type { ShellSession } from "./session";

// ── Command → available flags ────────────────────────────────────────────────

export const COMMAND_FLAGS: Readonly<Record<string, string[]>> = {
  validate: [
    "--output",
    "--format",
    "--transport",
    "--html",
    "--sandbox",
    "--fuzz",
    "--lang",
    "--rules",
    "--exclude-rules",
    "--min-severity",
    "--llm",
    "--save",
    "--verbose",
    "--save-baseline",
    "--compare-baseline",
    "--fail-on-degradation",
    "--allowed-score-drop",
  ],
  fuzz: [
    "--tool",
    "--transport",
    "--concurrency",
    "--timeout",
    "--rate-limit",
    "--param",
    "--generators",
    "--detectors",
    "--stop-on-first",
    "--fingerprint",
    "--verbose",
    "--output",
    "--format",
    "--header",
  ],
  doctor: [
    "--transport",
    "--watch",
    "--verbose",
    "--html",
    "--md",
    "--json",
    "--output",
    "--show-history",
    "--fix-integrity",
    "--clean-history",
  ],
  stress: ["--transport", "--users", "--duration", "--verbose"],
  dashboard: ["--transport", "--port", "--timeout"],
  play: ["--port", "--transport", "--list-only"],
  proxy: ["--port", "--timeout", "--log-file"],
  mock: ["--port", "--timeout"],
  init: ["--dir", "--name", "--template"],
  fingerprint: ["--transport"],
  inspect: ["--transport"],
  set: ["target", "lang"],
  lang: ["en", "es"],
  history: ["--last", "--clear"],
  context: ["list", "switch", "create", "clone", "delete"],
  profile: ["set", "save", "list", "show"],
  status: [],
  config: [],
  target: [],
};

// ── Primary command list (shown in help) ─────────────────────────────────────

export const PRIMARY_COMMANDS: readonly string[] = [
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
  "about",
  "lang",
  "set",
  "target",
  "clear",
  "help",
  "exit",
];

// ── All commands including aliases ───────────────────────────────────────────

export const ALL_COMMANDS: readonly string[] = [
  ...PRIMARY_COMMANDS,
  "v",
  "f",
  "d",
  "s",
  "m",
  "ex",
  "cfg",
  "language",
  "version",
  "stack",
  "ls",
  "github",
  "gh",
  "linkedin",
  "li",
  "website",
  "web",
  "cls",
  "h",
  "quit",
  "q",
];

// ── Completer ────────────────────────────────────────────────────────────────

export class ContextCompleter {
  /**
   * readline-compatible completer function.
   * Returns `[completions, originalLine]` as required by readline.
   */
  static complete(line: string, session?: ShellSession): [string[], string] {
    const trimmed = line.trimStart();

    // Level 1: complete command name (no space yet)
    if (!trimmed.includes(" ")) {
      const hits = (ALL_COMMANDS as string[]).filter((c) =>
        c.startsWith(trimmed),
      );
      return [hits.length ? hits : (ALL_COMMANDS as string[]), line];
    }

    const tokens = ShellParser.tokenise(trimmed);
    const cmd = ContextCompleter.resolveAlias(tokens[0].toLowerCase());
    const partial = line.endsWith(" ") ? "" : (tokens[tokens.length - 1] ?? "");
    const startingNewArg = line.endsWith(" ");

    // Level 2: complete flags
    const availableFlags = COMMAND_FLAGS[cmd] ?? [];
    if (
      partial.startsWith("--") ||
      (startingNewArg && availableFlags.length > 0)
    ) {
      const hits = availableFlags.filter((f) => f.startsWith(partial));
      const completions = (hits.length ? hits : availableFlags).map((f) =>
        startingNewArg
          ? line + f
          : line.slice(0, line.lastIndexOf(partial)) + f,
      );
      return [completions, line];
    }

    // Level 2.5: dynamic tool-name completion after --tool
    const prevToken = tokens.length >= 2 ? tokens[tokens.length - 2] : "";
    if (prevToken === "--tool" && session?.state.availableTools) {
      const toolHits = session.state.availableTools.filter((toolName) =>
        toolName.toLowerCase().startsWith(partial.toLowerCase()),
      );
      const completions = toolHits.map((toolName) =>
        startingNewArg
          ? line + toolName
          : line.slice(0, line.lastIndexOf(partial)) + toolName,
      );
      return [
        completions.length
          ? completions
          : session.state.availableTools.slice(0, 10),
        line,
      ];
    }

    // Level 3: filesystem path completion
    const looksLikePath =
      partial.startsWith("/") ||
      partial.startsWith("./") ||
      partial.startsWith("../") ||
      partial.includes(path.sep);

    if (
      looksLikePath ||
      (startingNewArg && ContextCompleter.commandExpectsPath(cmd))
    ) {
      const fsHits = ContextCompleter.completePath(partial);
      const completions = fsHits.map((p) =>
        startingNewArg
          ? line + p
          : line.slice(0, line.lastIndexOf(partial)) + p,
      );
      return [completions, line];
    }

    return [[], line];
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private static resolveAlias(alias: string): string {
    const map: Record<string, string> = {
      v: "validate",
      f: "fuzz",
      d: "doctor",
      s: "stress",
      m: "mock",
      ex: "examples",
      cfg: "config",
      h: "help",
      q: "exit",
      quit: "exit",
      cls: "clear",
      stack: "fingerprint",
      ls: "inspect",
    };
    return map[alias] ?? alias;
  }

  private static commandExpectsPath(cmd: string): boolean {
    return [
      "validate",
      "fuzz",
      "doctor",
      "stress",
      "dashboard",
      "play",
      "proxy",
      "init",
      "fingerprint",
      "inspect",
    ].includes(cmd);
  }

  /** Lists filesystem entries matching the given prefix. Capped at 20 results. */
  private static completePath(prefix: string): string[] {
    try {
      const dir = prefix ? path.dirname(prefix) : ".";
      const base = prefix ? path.basename(prefix) : "";
      const target = path.resolve(dir);
      if (!fs.existsSync(target)) return [];
      return fs
        .readdirSync(target, { withFileTypes: true })
        .filter((e) => e.name.startsWith(base))
        .map((e) => {
          const full = dir === "." ? e.name : path.join(dir, e.name);
          return e.isDirectory() ? full + path.sep : full;
        })
        .slice(0, 20);
    } catch {
      return [];
    }
  }
}
