/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ShellParser — POSIX-lite command line parser
 *
 * Supports:
 *   ✓ Double and single quotes  "node server.js"  'my tool'
 *   ✓ Internal escaping         "it\"s fine"
 *   ✓ Overwrite redirection     > output.txt
 *   ✓ Append redirection        >> output.txt
 *   ✓ Fused redirection         cmd>out.txt  (no spaces)
 *
 * Does NOT support (deliberate restriction):
 *   ✗ Pipes  |
 *   ✗ Input redirection  <
 *   ✗ Variable expansion  $VAR
 */

/**
 * Result of ShellParser.parse(): clean token list + optional redirection target.
 */
export interface ParseResult {
  tokens: string[];
  redirectTo: string | undefined;
  redirectAppend: boolean;
}

export class ShellParser {
  /**
   * Entry point: tokenises the full input line and separates any redirection.
   *
   * @example
   *   ShellParser.parse('fuzz "node s.js" --tool "Echo" > out.txt')
   *   // { tokens: ['fuzz','node s.js','--tool','Echo'], redirectTo: 'out.txt', redirectAppend: false }
   */
  static parse(input: string): ParseResult {
    const raw = ShellParser.tokenise(input);
    return ShellParser.extractRedirect(raw);
  }

  /**
   * Tokenises the input, respecting single/double quotes and escape sequences.
   * Produces one token per logical argument.
   */
  static tokenise(input: string): string[] {
    const tokens: string[] = [];
    let buf = "";
    let i = 0;
    let inQuote: '"' | "'" | null = null;

    while (i < input.length) {
      const ch = input[i];
      const next = input[i + 1];

      if (inQuote) {
        if (ch === "\\" && next === inQuote) {
          buf += inQuote;
          i += 2; // escaped closing quote
        } else if (ch === inQuote) {
          inQuote = null;
          i++; // closing quote — end of segment
        } else {
          buf += ch;
          i++;
        }
      } else if (ch === '"' || ch === "'") {
        inQuote = ch;
        i++; // open quoted segment
      } else if (ch === " " || ch === "\t") {
        if (buf.length) {
          tokens.push(buf);
          buf = "";
        }
        i++;
      } else {
        buf += ch;
        i++;
      }
    }

    if (buf.length) tokens.push(buf);
    return tokens;
  }

  /**
   * Scans the token array for redirection operators (`>` / `>>`) in both
   * separated form (`cmd > file`) and fused form (`cmd>file`).
   */
  private static extractRedirect(tokens: string[]): ParseResult {
    const clean: string[] = [];
    let redirectTo: string | undefined = undefined;
    let redirectAppend = false;

    let i = 0;
    while (i < tokens.length) {
      const tok = tokens[i];

      // ─ Standalone operator ─────────────────────────────────────────────
      if (tok === ">>" || tok === ">") {
        const dest = tokens[i + 1];
        if (!dest)
          throw new Error(`Redirect '${tok}' needs a destination file`);
        redirectAppend = tok === ">>";
        redirectTo = dest;
        i += 2;
        continue;
      }

      // ─ Fused operator  (e.g.  cmd>>file.txt  or  cmd>file.txt) ────────
      const fused = tok.match(/^(.*?)(>>?)(.+)$/);
      if (fused) {
        if (fused[1]) clean.push(fused[1]); // part before '>'
        redirectAppend = fused[2] === ">>";
        redirectTo = fused[3];
        i++;
        continue;
      }

      clean.push(tok);
      i++;
    }

    return { tokens: clean, redirectTo, redirectAppend };
  }

  // ── Flag / positional helpers ─────────────────────────────────────────────

  /**
   * Extracts `--flag [value]` pairs from a token array.
   * Returns a strict `Record<string, string | true>` — no `any`.
   */
  static extractFlags(tokens: string[]): Record<string, string | true> {
    const flags: Record<string, string | true> = {};

    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (!tok.startsWith("--")) continue;
      const key = tok.slice(2);
      if (!key) continue;

      const next = tokens[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    }

    return flags;
  }

  /**
   * Returns only the positional tokens (non-flag, non-flag-value items).
   */
  static extractPositionals(tokens: string[]): string[] {
    const pos: string[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (tok.startsWith("--")) {
        const next = tokens[i + 1];
        if (next && !next.startsWith("--")) i++; // skip flag value
      } else {
        pos.push(tok);
      }
    }
    return pos;
  }
}
