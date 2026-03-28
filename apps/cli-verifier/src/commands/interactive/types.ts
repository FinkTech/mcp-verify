/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Type definitions for Interactive Shell v1.0
 *
 * Extracted from interactive.ts - Section 1
 */

export type Language = 'en' | 'es';

/**
 * Mutable in-memory state of the active session.
 * Enhanced for multi-context workspace system (v1.0)
 */
export interface SessionState {
  // ── Multi-Context Fields (v1.0) ──────────────────────────────────────
  /** Name of the active context (e.g., 'dev', 'staging', 'default') */
  activeContextName: string;

  /** Map of context name → context data */
  contexts: Record<string, import('../types/workspace-context').WorkspaceContext>;

  /** Global user configuration from ~/.mcp-verify/config.json */
  globalConfig: import('../types/global-config').GlobalConfig;

  /** Environment variables loaded from .env (session-scoped) */
  environment: import('../types/environment-vars').EnvironmentVars | undefined;

  // ── Legacy Compatibility Fields ──────────────────────────────────────
  // These fields point to the active context for backward compatibility
  target:    string | undefined;
  lang:      Language;
  config:    Record<string, unknown>; // user-defined defaults

  // ── Session Metadata ─────────────────────────────────────────────────
  history:   string[];          // commands executed this session
  workspace: string | undefined; // name of the working directory
  startedAt: Date;
  availableTools?: string[];    // cached tool names from tools/list
}

/**
 * Format of the .mcp-verify/session.json file persisted in the workspace.
 */
export interface WorkspaceSession {
  target?:  string;
  lang?:    Language;
  config?:  Record<string, unknown>;
  savedAt?: string;
}

/**
 * Result of ShellParser: clean tokens + extracted redirection.
 */
export interface ParseResult {
  tokens:         string[];
  redirectTo:     string | undefined;
  redirectAppend: boolean;
}
