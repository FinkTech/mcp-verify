/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Session Migration Utilities
 *
 * Handles automatic migration from legacy (single-context) to v1.0 (multi-context) format
 * Includes version detection, backup creation, and safe migration
 */

import fs from "fs";
import path from "path";
import {
  WorkspaceContexts,
  LegacyWorkspaceSession,
  WorkspaceContext,
} from "../types/workspace-context";
import { SECURITY_PROFILES } from "../profiles/security-profiles";

/**
 * Detect the version of a session data object
 *
 * @param data - Unknown session data loaded from file
 * @returns 'legacy' for old single-context format, 'v1' for new multi-context format, 'invalid' if unrecognizable
 */
export function detectSessionVersion(
  data: unknown,
): "legacy" | "v1" | "invalid" {
  if (!data || typeof data !== "object") {
    return "invalid";
  }

  const obj = data as Record<string, unknown>;

  // v1.0 format has 'version' field set to '1.0'
  if ("version" in obj && obj.version === "1.0") {
    return "v1";
  }

  // Legacy format has target, lang, config, savedAt (but no 'version' or 'contexts')
  if ("target" in obj || "lang" in obj || "config" in obj || "savedAt" in obj) {
    // Ensure it doesn't have v1.0 fields
    if (!("contexts" in obj) && !("activeContext" in obj)) {
      return "legacy";
    }
  }

  return "invalid";
}

/**
 * Migrate legacy session to v1.0 multi-context format
 *
 * Creates a 'default' context with the legacy settings
 * Uses balanced security profile as default
 *
 * @param legacy - Legacy session data
 * @returns New v1.0 workspace contexts object
 */
export function migrateSessionToV1(
  legacy: LegacyWorkspaceSession,
): WorkspaceContexts {
  const now = new Date().toISOString();

  // Create default context from legacy data
  const defaultContext: WorkspaceContext = {
    target: legacy.target,
    lang: legacy.lang ?? "en",
    profile: SECURITY_PROFILES.balanced,
    config: legacy.config ?? {},
    createdAt: legacy.savedAt ?? now,
    modifiedAt: now,
  };

  return {
    version: "1.0",
    activeContext: "default",
    contexts: {
      default: defaultContext,
    },
    savedAt: now,
  };
}

/**
 * Create a backup of the session file before migration
 * Backup is saved with .backup extension in the same directory
 *
 * @param sessionPath - Path to the session.json file
 * @returns True if backup was created successfully, false otherwise
 */
export function backupSession(sessionPath: string): boolean {
  try {
    if (!fs.existsSync(sessionPath)) {
      return false;
    }

    const backupPath = `${sessionPath}.backup`;
    fs.copyFileSync(sessionPath, backupPath);
    return true;
  } catch {
    // Silent failure - backup is nice-to-have but not critical
    return false;
  }
}

/**
 * Validate that workspace contexts data is well-formed
 *
 * @param data - Data to validate
 * @returns True if data is valid v1.0 format
 */
export function isValidWorkspaceContexts(
  data: unknown,
): data is WorkspaceContexts {
  if (!data || typeof data !== "object") {
    return false;
  }

  const obj = data as Record<string, unknown>;

  // Must have version: '1.0'
  if (obj.version !== "1.0") {
    return false;
  }

  // Must have activeContext string
  if (typeof obj.activeContext !== "string") {
    return false;
  }

  // Must have contexts object
  if (!obj.contexts || typeof obj.contexts !== "object") {
    return false;
  }

  // Active context must exist in contexts
  const contexts = obj.contexts as Record<string, unknown>;
  if (!(obj.activeContext in contexts)) {
    return false;
  }

  return true;
}

/**
 * Migrate session file in place (if needed)
 * Automatically detects version and performs migration
 *
 * @param sessionPath - Path to session.json file
 * @returns Migrated data or undefined if file doesn't exist
 */
export function migrateSessionFile(
  sessionPath: string,
): WorkspaceContexts | LegacyWorkspaceSession | undefined {
  try {
    if (!fs.existsSync(sessionPath)) {
      return undefined;
    }

    const content = fs.readFileSync(sessionPath, "utf-8");
    const data = JSON.parse(content) as unknown;

    const version = detectSessionVersion(data);

    if (version === "v1") {
      // Already migrated
      return data as WorkspaceContexts;
    }

    if (version === "legacy") {
      // Create backup before migration
      backupSession(sessionPath);

      // Migrate to v1.0
      const migrated = migrateSessionToV1(data as LegacyWorkspaceSession);

      // Save migrated version
      const dir = path.dirname(sessionPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(sessionPath, JSON.stringify(migrated, null, 2), "utf-8");

      return migrated;
    }

    // Invalid format - return undefined to trigger default
    return undefined;
  } catch {
    // Parse error or I/O error - return undefined to trigger default
    return undefined;
  }
}
