/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Environment Variables Type Definitions
 *
 * Defines the structure for environment variables loaded from .env files
 * Variables are loaded on workspace entry but kept session-scoped (not polluting process.env)
 */

/**
 * Environment variables loaded from .env file
 * Session-scoped to avoid polluting global process.env
 *
 * Loaded variables:
 * - ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY: LLM provider keys
 * - DEBUG, NODE_ENV: Common development variables
 * - MCP_*: All MCP-related configuration (prefix pattern)
 */
export interface EnvironmentVars {
  /** Anthropic API key for Claude models */
  ANTHROPIC_API_KEY?: string;

  /** OpenAI API key for GPT models */
  OPENAI_API_KEY?: string;

  /** Google Gemini API key */
  GEMINI_API_KEY?: string;

  /** Debug mode flag */
  DEBUG?: string;

  /** Node environment (development, production, test) */
  NODE_ENV?: string;

  /** All MCP_* prefixed variables (e.g., MCP_TIMEOUT, MCP_HOST, MCP_PORT) */
  mcpVars: Record<string, string>;

  /** Path to the .env file that was loaded (undefined if not found) */
  sourceFile: string | undefined;
}
