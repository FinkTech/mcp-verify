/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Global Configuration Manager
 *
 * Manages user-level configuration stored in ~/.mcp-verify/config.json
 * Handles configuration hierarchy: CLI flags > Context config > Global config > System defaults
 */

import fs from "fs";
import path from "path";
import os from "os";
import { GlobalConfig } from "../types/global-config";
import { SecurityProfile } from "../types/workspace-context";

/**
 * Global configuration manager
 * Provides methods to load, save, and resolve configuration values
 */
export class GlobalConfigManager {
  /** Path to global config file: ~/.mcp-verify/config.json */
  private static readonly CONFIG_PATH = path.join(
    os.homedir(),
    ".mcp-verify",
    "config.json",
  );

  /**
   * Load global configuration from disk
   * Creates default config if file doesn't exist
   *
   * @returns GlobalConfig object
   */
  static load(): GlobalConfig {
    try {
      if (!fs.existsSync(GlobalConfigManager.CONFIG_PATH)) {
        // First run - create default config
        const defaultConfig = GlobalConfigManager.getDefaultConfig();
        GlobalConfigManager.save(defaultConfig);
        return defaultConfig;
      }

      const content = fs.readFileSync(GlobalConfigManager.CONFIG_PATH, "utf-8");
      const data = JSON.parse(content) as unknown;

      // Validate and merge with defaults
      if (typeof data === "object" && data !== null) {
        return GlobalConfigManager.mergeWithDefaults(
          data as Partial<GlobalConfig>,
        );
      }

      // Invalid format - return defaults
      return GlobalConfigManager.getDefaultConfig();
    } catch {
      // Parse error or I/O error - return defaults
      return GlobalConfigManager.getDefaultConfig();
    }
  }

  /**
   * Save global configuration to disk
   *
   * @param config - Configuration object to save
   */
  static save(config: GlobalConfig): void {
    try {
      const dir = path.dirname(GlobalConfigManager.CONFIG_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const payload: GlobalConfig = {
        ...config,
        updatedAt: new Date().toISOString(),
      };

      fs.writeFileSync(
        GlobalConfigManager.CONFIG_PATH,
        JSON.stringify(payload, null, 2),
        "utf-8",
      );
    } catch {
      // Silent failure - global config is nice-to-have but not critical
    }
  }

  /**
   * Resolve a configuration value using hierarchy
   *
   * Priority (highest to lowest):
   * 1. CLI flags (passed directly, not handled here)
   * 2. Active context config
   * 3. Global config defaults
   * 4. System defaults
   *
   * @param key - Configuration key (e.g., 'timeout', 'validate.output')
   * @param contextConfig - Context-specific configuration
   * @param globalConfig - Global configuration
   * @returns Resolved value or undefined
   */
  static resolveConfigValue(
    key: string,
    contextConfig: Record<string, unknown>,
    globalConfig: GlobalConfig,
  ): unknown {
    // Check context config first
    if (key in contextConfig) {
      return contextConfig[key];
    }

    // Check global defaults
    if (key in globalConfig.defaults) {
      return globalConfig.defaults[key];
    }

    // Not found in any config
    return undefined;
  }

  /**
   * Add a custom security profile to global config
   *
   * @param name - Profile name
   * @param profile - Profile configuration
   */
  static saveCustomProfile(name: string, profile: SecurityProfile): void {
    const config = GlobalConfigManager.load();

    // Deep copy profile using structuredClone (Node.js 17+)
    // This ensures fuzzing, validation, generators, detectors, enabledBlocks
    // are cloned without shared references
    const clonedProfile = structuredClone(profile);
    clonedProfile.name = name;
    clonedProfile.isPreset = false;

    config.customProfiles[name] = clonedProfile;
    GlobalConfigManager.save(config);
  }

  /**
   * Delete a custom security profile from global config
   *
   * @param name - Profile name to delete
   * @returns True if profile was deleted, false if not found
   */
  static deleteCustomProfile(name: string): boolean {
    const config = GlobalConfigManager.load();
    if (!(name in config.customProfiles)) {
      return false;
    }

    delete config.customProfiles[name];
    GlobalConfigManager.save(config);
    return true;
  }

  /**
   * Get default global configuration
   *
   * @returns Default GlobalConfig object
   */
  private static getDefaultConfig(): GlobalConfig {
    return {
      version: "1.0",
      defaultLanguage: "en",
      defaultProfile: "balanced",
      customProfiles: {},
      defaults: {},
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Merge partial config with defaults
   * Ensures all required fields are present
   *
   * @param partial - Partial configuration from disk
   * @returns Complete GlobalConfig object
   */
  private static mergeWithDefaults(
    partial: Partial<GlobalConfig>,
  ): GlobalConfig {
    const defaults = GlobalConfigManager.getDefaultConfig();

    return {
      version: partial.version ?? defaults.version,
      defaultLanguage: partial.defaultLanguage ?? defaults.defaultLanguage,
      defaultProfile: partial.defaultProfile ?? defaults.defaultProfile,
      customProfiles: partial.customProfiles ?? defaults.customProfiles,
      defaults: partial.defaults ?? defaults.defaults,
      updatedAt: partial.updatedAt ?? defaults.updatedAt,
    };
  }
}
