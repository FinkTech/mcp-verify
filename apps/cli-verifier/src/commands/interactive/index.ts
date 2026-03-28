/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Interactive Mode - Main Entry Point
 *
 * Extracted from interactive.ts - Section 8
 *
 * Starts the interactive REPL with:
 * - Multi-context workspace session
 * - Persistent history across sessions
 * - Contextual TAB completion
 * - Output redirection (>, >>)
 * - Dynamic prompt with workspace + target
 */

import readline from 'readline';
import path from 'path';
import chalk from 'chalk';
import { t } from '@mcp-verify/shared';

import { ShellSession } from './session';
import { ShellParser } from './parser';
import { PersistenceManager } from './persistence';
import { ContextCompleter } from './completer';
import { buildPrompt, withRedirect } from './utils';
import { dispatch, showSessionSummary } from './router';
import type { ParseResult } from './types';

// ============================================================================
// ─── Main Entry Point ───────────────────────────────────────────────────────
// ============================================================================

export function startInteractiveMode(): void {
  // ── 1. Detect and load workspace session ────────────────────────────────
  const workspaceSession = PersistenceManager.loadWorkspaceSession();
  const session          = new ShellSession();

  // ── 1.5. Load available tools if target is configured ───────────────────
  if (session.state.target) {
    session.fetchAvailableTools().catch(() => {
      // Silent failure - autocompletion will work without tools
    });
  }

  // ── 2. Welcome banner ────────────────────────────────────────────────
  console.log(chalk.bold.cyan(`\n  ${t('interactive_shell')}`));

  if (workspaceSession) {
    console.log(
      chalk.green('  ✓ Workspace loaded') +
      chalk.dim(` — ${path.basename(process.cwd())}`) +
      (workspaceSession.target ? chalk.dim(` — target: ${workspaceSession.target}`) : '')
    );
  }

  console.log(chalk.gray(`  ${t('interactive_type_help')}`));
  console.log(chalk.dim(`  ${t('interactive_tab_hint')}\n`));

  // ── 3. Create readline with contextual completer ─────────────────────────────
  const rl = readline.createInterface({
    input:     process.stdin,
    output:    process.stdout,
    prompt:    buildPrompt(session),
    completer: (line: string) => ContextCompleter.complete(line, session),
  });

  // Inject persistent history → enables ↑↓ navigation between sessions
  PersistenceManager.hydrateReadlineHistory(rl);

  rl.setPrompt(buildPrompt(session));
  rl.prompt();

  // ── 4. Input loop ───────────────────────────────────────────────────────
  rl.on('line', async (raw: string) => {
    const input = raw.trim();

    if (!input) {
      rl.setPrompt(buildPrompt(session));
      rl.prompt();
      return;
    }

    session.recordCommand(input);

    // Parse with quote + redirection support
    let parsed: ParseResult;
    try {
      parsed = ShellParser.parse(input);
    } catch (e) {
      console.error(chalk.red(`\n  ✗ Parse error: ${e instanceof Error ? e.message : String(e)}\n`));
      rl.setPrompt(buildPrompt(session));
      rl.prompt();
      return;
    }

    const [command, ...rest] = parsed.tokens;
    if (!command) {
      rl.setPrompt(buildPrompt(session));
      rl.prompt();
      return;
    }

    // The try here is the REPL's security barrier — it must never crash
    try {
      // CRITICAL UX FIX: Completely pause and mute readline during command execution.
      // This prevents "yes/no" answers to sub-prompts (like disclaimers) from being
      // misinterpreted as new shell commands.
      rl.pause();

      // Temporarily remove line listeners to ensure Inquirer has exclusive access to stdin
      const listeners = rl.listeners('line');
      rl.removeAllListeners('line');

      await withRedirect(parsed, () => dispatch(command.toLowerCase(), rest, session, rl));

      // Restore listeners after command completion
      listeners.forEach(l => rl.on('line', l as any));
    } catch (err) {
      console.error(chalk.red(`\n  ✗ ${err instanceof Error ? err.message : String(err)}\n`));
    } finally {
      // Always resume and reprompt
      rl.resume();
      rl.setPrompt(buildPrompt(session));
      rl.prompt();
    }
  });

  // ── 5. Exit via Ctrl+C or Ctrl+D ────────────────────────────────────────────
  rl.on('close', () => {
    showSessionSummary(session);
    process.exit(0);
  });
}

// ============================================================================
// ─── Exports for Testing ────────────────────────────────────────────────────
// ============================================================================

export { ShellParser, ContextCompleter, PersistenceManager, ShellSession };
