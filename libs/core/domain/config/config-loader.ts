/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Configuration Loader
 *
 * Loads and merges configuration from multiple sources with proper hierarchy:
 * 1. CLI arguments (highest priority)
 * 2. Environment variables (MCP_VERIFY_*)
 * 3. Config file (mcp-verify.config.json or .mcp-verify.json)
 * 4. Default values (lowest priority)
 *
 * @example
 * ```typescript
 * // Load with CLI overrides
 * const config = ConfigLoader.load({
 *   overrides: { output: { directory: './custom' } }
 * });
 *
 * // Access config values
 * console.log(config.output.directory); // './custom'
 * console.log(config.security.minScore); // 70 (from defaults)
 * ```
 */

import fs from 'fs';
import path from 'path';
import { ZodError } from 'zod';
import { deepMerge } from '@mcp-verify/shared';
import type { McpVerifyConfig, PartialConfig } from './config.types';
import { DEFAULT_CONFIG, validateConfig, ENV_MAPPING } from './config.types';

/**
 * Options for loading configuration
 */
export interface ConfigLoadOptions {
  /** Explicit path to config file */
  configPath?: string;
  /** CLI argument overrides (highest priority) */
  overrides?: PartialConfig;
  /** Suppress logging */
  silent?: boolean;
}

/**
 * Configuration Loader
 * Single point of entry for all configuration loading
 */
export class ConfigLoader {
  private static cachedConfig: McpVerifyConfig | null = null;
  private static configFilePath: string | null = null;
  private static loadError: Error | null = null;

  /**
   * Load configuration with full hierarchy support
   */
  static load(options: ConfigLoadOptions = {}): McpVerifyConfig {
    const { configPath, overrides, silent = false } = options;

    // 1. Start with defaults
    let config: McpVerifyConfig = structuredClone(DEFAULT_CONFIG);

    // 2. Load from config file
    const fileConfig = this.loadFromFile(configPath, silent);
    if (fileConfig) {
      config = this.mergeConfigs(config, fileConfig);
    }

    // 3. Apply environment variable overrides
    const envConfig = this.loadFromEnv();
    if (Object.keys(envConfig).length > 0) {
      config = this.mergeConfigs(config, envConfig);
    }

    // 4. Apply CLI overrides (highest priority)
    if (overrides) {
      config = this.mergeConfigs(config, overrides);
    }

    // Cache the resolved config
    this.cachedConfig = config;

    return config;
  }

  /**
   * Get cached configuration (or load if not cached)
   */
  static get(options?: ConfigLoadOptions): McpVerifyConfig {
    if (this.cachedConfig) {
      return this.cachedConfig;
    }
    return this.load(options);
  }

  /**
   * Clear cached configuration (useful for testing)
   */
  static clearCache(): void {
    this.cachedConfig = null;
    this.configFilePath = null;
  }

  /**
   * Get the path to the loaded config file (if any)
   */
  static getConfigFilePath(): string | null {
    return this.configFilePath;
  }

  /**
   * Get any error that occurred during configuration loading
   */
  static getLoadError(): Error | null {
    return this.loadError;
  }

  /**
   * Load configuration from file
   */
  private static loadFromFile(explicitPath?: string, silent = false): PartialConfig | null {
    const searchPaths = [
      explicitPath,
      path.join(process.cwd(), 'mcp-verify.config.json'),
      path.join(process.cwd(), '.mcp-verify.json'),
      path.join(process.cwd(), '.mcp-verifyrc.json')
    ].filter((p): p is string => p !== undefined);

    for (const filePath of searchPaths) {
      if (fs.existsSync(filePath)) {
        try {
          const raw = fs.readFileSync(filePath, 'utf-8');
          const parsed = JSON.parse(raw);

          // Validate with Zod
          const validated = validateConfig(parsed);

          this.configFilePath = filePath;

          // Silent loading in core library - CLI will handle user notification
          // if (!silent) {
          //   console.error(`\x1b[36m[config]\x1b[0m Loaded from ${path.relative(process.cwd(), filePath)}`);
          // }

          return validated;
        } catch (e) {
          this.loadError = e as Error;
          // Continue to next file
        }
      }
    }

    return null;
  }

  /**
   * Load configuration from environment variables
   */
  private static loadFromEnv(): PartialConfig {
    const envConfig: Record<string, unknown> = {};

    for (const [envVar, configPath] of Object.entries(ENV_MAPPING)) {
      const value = process.env[envVar];
      if (value !== undefined) {
        this.setNestedValue(envConfig, configPath, this.parseEnvValue(value));
      }
    }

    return envConfig as PartialConfig;
  }

  /**
   * Parse environment variable value to appropriate type
   */
  private static parseEnvValue(value: string): unknown {
    // Boolean
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;

    // Number
    const num = Number(value);
    if (!isNaN(num) && value.trim() !== '') return num;

    // String
    return value;
  }

  /**
   * Set a value at a nested path in an object
   */
  private static setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current)) {
        current[part] = {};
      }
      current = current[part] as Record<string, unknown>;
    }

    current[parts[parts.length - 1]] = value;
  }

  /**
   * Deep merge two configuration objects
   */
  private static mergeConfigs(base: McpVerifyConfig, override: PartialConfig): McpVerifyConfig {
    return deepMerge(
      base as unknown as Record<string, unknown>,
      override as unknown as Record<string, unknown>
    ) as unknown as McpVerifyConfig;
  }

  /**
   * Generate a sample configuration file
   */
  static generateSampleConfig(): string {
    const sample: PartialConfig = {
      $schema: 'https://mcp-verify.dev/schema/config.json',
      output: {
        directory: './reports',
        language: 'en',
        html: true
      },
      security: {
        minScore: 70,
        failOnCritical: true,
        failOnHigh: false
      },
      quality: {
        minScore: 50
      },
      fuzzing: {
        timeout: 5000,
        concurrency: 5
      },
      network: {
        requestTimeout: 30000
      },
      sandbox: {
        enabled: false
      }
    };

    return JSON.stringify(sample, null, 2);
  }

  /**
   * Check if a config file exists
   */
  static configFileExists(): boolean {
    const searchPaths = [
      path.join(process.cwd(), 'mcp-verify.config.json'),
      path.join(process.cwd(), '.mcp-verify.json'),
      path.join(process.cwd(), '.mcp-verifyrc.json')
    ];

    return searchPaths.some(p => fs.existsSync(p));
  }
}

/**
 * Convenience function to get a specific config value
 */
export function getConfig<K extends keyof McpVerifyConfig>(key: K): McpVerifyConfig[K] {
  return ConfigLoader.get()[key];
}

/**
 * Convenience function to load config with CLI overrides
 */
export function loadConfig(overrides?: PartialConfig): McpVerifyConfig {
  return ConfigLoader.load({ overrides });
}
