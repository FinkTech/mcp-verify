/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Environment Variables Loader
 *
 * Loads environment variables from .env files in the current workspace
 * Variables are kept session-scoped to avoid polluting global process.env
 *
 * Loaded variables:
 * - ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY: LLM provider keys
 * - DEBUG, NODE_ENV: Common development variables
 * - MCP_*: All MCP-related configuration (prefix pattern)
 */

import fs from 'fs';
import path from 'path';
import { EnvironmentVars } from '../types/environment-vars';

/**
 * Environment variables loader
 * Parses .env files and provides session-scoped environment
 */
export class EnvironmentLoader {
  /** List of .env files to search for (in priority order) */
  private static readonly ENV_FILES = ['.env.local', '.env'];

  /** List of specific environment variables to extract */
  private static readonly KNOWN_VARS = [
    'ANTHROPIC_API_KEY',
    'OPENAI_API_KEY',
    'GEMINI_API_KEY',
    'DEBUG',
    'NODE_ENV',
  ];

  /**
   * Load environment variables from .env file in current directory
   * Searches for .env.local first, then .env
   *
   * @returns EnvironmentVars object with loaded variables
   */
  static load(): EnvironmentVars {
    // Try each env file in order
    for (const filename of EnvironmentLoader.ENV_FILES) {
      const envPath = path.join(process.cwd(), filename);

      if (fs.existsSync(envPath)) {
        try {
          const content = fs.readFileSync(envPath, 'utf-8');
          const parsed = EnvironmentLoader.parseEnvFile(content);
          return EnvironmentLoader.extractVars(parsed, envPath);
        } catch {
          // Parse error - try next file
          continue;
        }
      }
    }

    // No .env file found
    return {
      mcpVars: {},
      sourceFile: undefined,
    };
  }

  /**
   * Parse .env file content into key-value pairs
   * Supports:
   * - Simple KEY=value
   * - Quoted values KEY="value with spaces"
   * - Comments (lines starting with #)
   * - Empty lines
   *
   * @param content - Raw .env file content
   * @returns Record of environment variables
   */
  private static parseEnvFile(content: string): Record<string, string> {
    const result: Record<string, string> = {};

    for (const line of content.split('\n')) {
      const trimmed = line.trim();

      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Match KEY=value or KEY="value"
      const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (!match) {
        continue;
      }

      const [, key, rawValue] = match;

      // Remove quotes if present
      let value = rawValue.trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      result[key] = value;
    }

    return result;
  }

  /**
   * Extract relevant environment variables from parsed data
   *
   * @param parsed - Parsed environment variables
   * @param sourceFile - Path to the .env file that was loaded
   * @returns EnvironmentVars object
   */
  private static extractVars(
    parsed: Record<string, string>,
    sourceFile: string
  ): EnvironmentVars {
    const result: EnvironmentVars = {
      mcpVars: {},
      sourceFile,
    };

    // Extract known variables
    for (const key of EnvironmentLoader.KNOWN_VARS) {
      if (key in parsed) {
        switch (key) {
          case 'ANTHROPIC_API_KEY':
            result.ANTHROPIC_API_KEY = parsed[key];
            break;
          case 'OPENAI_API_KEY':
            result.OPENAI_API_KEY = parsed[key];
            break;
          case 'GEMINI_API_KEY':
            result.GEMINI_API_KEY = parsed[key];
            break;
          case 'DEBUG':
            result.DEBUG = parsed[key];
            break;
          case 'NODE_ENV':
            result.NODE_ENV = parsed[key];
            break;
        }
      }
    }

    // Extract all MCP_* prefixed variables
    for (const [key, value] of Object.entries(parsed)) {
      if (key.startsWith('MCP_')) {
        result.mcpVars[key] = value;
      }
    }

    return result;
  }

  /**
   * Get list of loaded environment variable keys
   * Useful for displaying in status command
   *
   * @param env - EnvironmentVars object
   * @returns Array of key names that were loaded
   */
  static getLoadedKeys(env: EnvironmentVars): string[] {
    const keys: string[] = [];

    if (env.ANTHROPIC_API_KEY) keys.push('ANTHROPIC_API_KEY');
    if (env.OPENAI_API_KEY) keys.push('OPENAI_API_KEY');
    if (env.GEMINI_API_KEY) keys.push('GEMINI_API_KEY');
    if (env.DEBUG) keys.push('DEBUG');
    if (env.NODE_ENV) keys.push('NODE_ENV');

    // Add all MCP_* keys
    keys.push(...Object.keys(env.mcpVars).sort());

    return keys;
  }
}
