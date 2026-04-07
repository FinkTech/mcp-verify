/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * PersistenceManager — All file-system I/O for the interactive shell.
 *
 * Responsibilities:
 *   - Global command history  (~/.mcp-verify/history.json)
 *   - Workspace session file  (.mcp-verify/session.json)
 *   - Multi-context workspace data (v1.0 format)
 *   - Atomic write pattern for crash-safe saves
 *   - Output redirection to disk
 */

import fs from "fs";
import os from "os";
import path from "path";
import readline from "readline";

import { ConfigLoader } from "@mcp-verify/core";
import {
  WorkspaceSession,
  WorkspaceContexts,
  LegacyWorkspaceSession,
} from "../types/workspace-context";
import { migrateSessionFile } from "../managers/migration";

export class PersistenceManager {
  // ── Path helpers ─────────────────────────────────────────────────────────

  /**
   * Computes all relevant file-system paths from the current configuration.
   * Called lazily so config is already loaded at call time.
   */
  static getPaths() {
    const cfg = ConfigLoader.get().workspace;
    const workspaceDir = cfg.directory;
    const sessionFileName = cfg.sessionFile;

    return {
      globalDir: path.join(os.homedir(), ".mcp-verify"),
      historyFile: path.join(os.homedir(), ".mcp-verify", "history.json"),
      localDir: path.join(process.cwd(), workspaceDir),
      sessionFile: path.join(process.cwd(), workspaceDir, sessionFileName),
    };
  }

  private static getHistoryLimit(): number {
    return ConfigLoader.get().workspace.historyLimit;
  }

  private static isEnabled(): boolean {
    return ConfigLoader.get().workspace.persistenceEnabled;
  }

  // ── History ──────────────────────────────────────────────────────────────

  /** Loads the global command history from disk. */
  static loadHistory(): string[] {
    if (!PersistenceManager.isEnabled()) return [];
    try {
      const paths = PersistenceManager.getPaths();
      if (!fs.existsSync(paths.historyFile)) return [];
      const raw = fs.readFileSync(paths.historyFile, "utf8");
      const data = JSON.parse(raw) as unknown;
      if (!Array.isArray(data)) return [];
      return (data as unknown[])
        .filter((e): e is string => typeof e === "string")
        .slice(-PersistenceManager.getHistoryLimit());
    } catch {
      return [];
    }
  }

  /**
   * Appends one entry to the on-disk history.
   * Applies HISTCONTROL=ignoredups — consecutive duplicates are dropped.
   */
  static appendHistory(entry: string): void {
    if (!PersistenceManager.isEnabled()) return;
    try {
      const paths = PersistenceManager.getPaths();
      PersistenceManager.ensureDir(paths.globalDir);
      const existing = PersistenceManager.loadHistory();
      if (existing[existing.length - 1] === entry) return; // ignoredups
      const updated = [...existing, entry].slice(
        -PersistenceManager.getHistoryLimit(),
      );
      fs.writeFileSync(
        paths.historyFile,
        JSON.stringify(updated, null, 2),
        "utf8",
      );
    } catch {
      /* silent */
    }
  }

  /**
   * Injects persistent history into a readline interface so ↑/↓ navigation
   * works across sessions.
   */
  static hydrateReadlineHistory(rl: readline.Interface): void {
    const history = PersistenceManager.loadHistory();
    // readline stores history in LIFO order internally
    (rl as readline.Interface & { history: string[] }).history = [
      ...history,
    ].reverse();
  }

  // ── Workspace session (legacy) ───────────────────────────────────────────

  /** Reads the legacy session file (flat target/lang/config). */
  static loadWorkspaceSession(): WorkspaceSession | undefined {
    if (!PersistenceManager.isEnabled()) return undefined;
    try {
      const paths = PersistenceManager.getPaths();
      if (!fs.existsSync(paths.sessionFile)) return undefined;
      const raw = fs.readFileSync(paths.sessionFile, "utf8");
      const data = JSON.parse(raw) as unknown;
      if (typeof data !== "object" || data === null) return undefined;
      return data as WorkspaceSession;
    } catch {
      return undefined;
    }
  }

  /** Writes legacy session state to disk (non-atomic, legacy path only). */
  static saveWorkspaceSession(state: {
    target?: string;
    lang: string;
    config: Record<string, unknown>;
  }): void {
    if (!PersistenceManager.isEnabled()) return;
    try {
      const paths = PersistenceManager.getPaths();
      PersistenceManager.ensureDir(paths.localDir);
      const payload: WorkspaceSession = {
        target: state.target,
        lang: state.lang as "en" | "es",
        config: state.config,
        savedAt: new Date().toISOString(),
      };
      fs.writeFileSync(
        paths.sessionFile,
        JSON.stringify(payload, null, 2),
        "utf8",
      );
    } catch {
      /* silent */
    }
  }

  // ── Multi-context workspace (v1.0) ───────────────────────────────────────

  /**
   * Loads workspace data, auto-migrating from legacy format if needed.
   * Returns `undefined` when persistence is disabled or the file is absent.
   */
  static loadWorkspaceData():
    | WorkspaceContexts
    | LegacyWorkspaceSession
    | undefined {
    if (!PersistenceManager.isEnabled()) return undefined;
    try {
      const paths = PersistenceManager.getPaths();
      return migrateSessionFile(paths.sessionFile);
    } catch {
      return undefined;
    }
  }

  /**
   * ATOMIC: Saves multi-context workspace data using write-then-rename.
   * Always serialises to v1.0 format.
   */
  static saveWorkspaceContexts(contexts: WorkspaceContexts): void {
    if (!PersistenceManager.isEnabled()) return;
    try {
      const paths = PersistenceManager.getPaths();
      PersistenceManager.ensureDir(paths.localDir);
      const payload: WorkspaceContexts = {
        ...contexts,
        savedAt: new Date().toISOString(),
      };
      PersistenceManager.atomicWrite(
        paths.sessionFile,
        JSON.stringify(payload, null, 2),
      );
    } catch {
      /* silent */
    }
  }

  // ── Output redirection ───────────────────────────────────────────────────

  /**
   * ATOMIC: Writes `content` to `filePath`.
   * When `append` is true the existing file content is prepended.
   * Creates parent directories automatically.
   */
  static writeOutput(filePath: string, content: string, append: boolean): void {
    const resolved = path.resolve(filePath);
    PersistenceManager.ensureDir(path.dirname(resolved));

    if (append) {
      const existing = fs.existsSync(resolved)
        ? fs.readFileSync(resolved, "utf8")
        : "";
      PersistenceManager.atomicWrite(resolved, existing + content + "\n");
    } else {
      PersistenceManager.atomicWrite(resolved, content + "\n");
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  /**
   * Write-then-rename atomic write pattern.
   * Guarantees no partial writes and no corrupted target file.
   */
  private static atomicWrite(targetPath: string, content: string): void {
    const tmpPath = `${targetPath}.tmp`;
    try {
      fs.writeFileSync(tmpPath, content, "utf8");
      fs.renameSync(tmpPath, targetPath);
    } catch (error) {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {
        /* ignore cleanup errors */
      }
      throw error;
    }
  }

  private static ensureDir(dir: string): void {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }
}
