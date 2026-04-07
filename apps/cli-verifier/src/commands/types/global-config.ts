/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Global Configuration Type Definitions
 *
 * Defines user-level configuration stored in ~/.mcp-verify/config.json
 * This configuration applies to all workspaces unless overridden by context-specific settings
 */

import {
  Language,
  SecurityProfile,
  SecurityProfilePreset,
} from "./workspace-context";

/**
 * Global user configuration
 * Stored in ~/.mcp-verify/config.json
 *
 * Configuration hierarchy (highest to lowest priority):
 * 1. CLI flags (--timeout=5000)
 * 2. Active context config (.mcp-verify/session.json)
 * 3. Global config (~/.mcp-verify/config.json) ← This file
 * 4. System defaults
 */
export interface GlobalConfig {
  /** Configuration format version */
  version: "1.0";

  /** Default language for new contexts */
  defaultLanguage: Language;

  /** Default security profile for new contexts */
  defaultProfile: SecurityProfilePreset;

  /** Custom security profiles created by the user */
  customProfiles: Record<string, SecurityProfile>;

  /** Default configuration values for all contexts */
  defaults: Record<string, unknown>;

  /** ISO timestamp when config was last updated */
  updatedAt: string;
}
