/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * API Key Manager - Simple Environment Variable Storage
 *
 * Storage strategy:
 * - Environment Variable: ANTHROPIC_API_KEY
 * - Compatible with Claude Desktop keychain management
 *
 * Security features:
 * - Never logs API keys
 * - Validates key format
 * - Sanitizes keys from logs
 *
 * Note: OS Keychain management is handled by Claude Desktop.
 * For standalone CLI usage, use environment variables.
 *
 * @module libs/shared/utils/api-key-manager
 */

import Anthropic from "@anthropic-ai/sdk";
import { loadNativeAddon } from "./native-loader";
import { t } from "./cli/i18n-helper";

const ENV_VAR_NAME = "ANTHROPIC_API_KEY";
const KEYCHAIN_SERVICE = "mcp-verify";
const KEYCHAIN_ACCOUNT = "anthropic_api_key";

export interface ApiKeyValidationResult {
  valid: boolean;
  error?: string;
  provider?: string;
}

export class ApiKeyManager {
  /**
   * Retrieve API key from:
   * 1. Environment variable (high priority, for CI/CD)
   * 2. System Keychain (local persistence)
   */
  async getApiKey(): Promise<string | null> {
    // 1. Check environment variable
    const envKey = process.env[ENV_VAR_NAME];
    if (envKey && envKey.length > 0) {
      return envKey;
    }

    // 2. Check System Keychain
    try {
      const keyring = loadNativeAddon<any>("@napi-rs/keyring");
      if (keyring) {
        // This is a purely local call to the OS Credential Manager
        return await keyring.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
      }
    } catch (error) {
      // Keychain entry might not exist or module failed to load
    }

    return null;
  }

  /**
   * Save API key to the System Keychain (Local only)
   * This is a transparent process that never sends data to external servers.
   */
  async saveApiKey(apiKey: string): Promise<boolean> {
    try {
      const keyring = loadNativeAddon<any>("@napi-rs/keyring");
      if (!keyring) {
        throw new Error(
          t("mcp_error_native_addon_not_available", {
            addon: "@napi-rs/keyring",
          }),
        );
      }

      await keyring.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, apiKey);
      return true;
    } catch (error) {
      console.error(
        t("mcp_error_keychain_save_failed", {
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      return false;
    }
  }

  /**
   * Delete API key from the System Keychain
   */
  async deleteApiKey(): Promise<boolean> {
    try {
      const keyring = loadNativeAddon<any>("@napi-rs/keyring");
      if (!keyring) return false;

      await keyring.deletePassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate API key format (Anthropic-specific)
   * Format: sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   */
  isValidAnthropicKey(key: string): boolean {
    // Anthropic keys start with sk-ant-api and have 95+ chars after prefix
    return /^sk-ant-api\d{2}-[\w-]{95,}$/.test(key);
  }

  /**
   * Validate API key by making a minimal API call
   * Cost: ~$0.000015 (1 token with Haiku)
   */
  async validateApiKey(apiKey: string): Promise<ApiKeyValidationResult> {
    try {
      const anthropic = new Anthropic({ apiKey });

      // Make minimal request (1 token = cheapest possible)
      await anthropic.messages.create({
        model: "claude-haiku-4-5-20251001", // Cheapest model
        max_tokens: 1,
        messages: [{ role: "user", content: "test" }],
      });

      return {
        valid: true,
        provider: "anthropic",
      };
    } catch (error: any) {
      if (error.status === 401 || error.message?.includes("authentication")) {
        return {
          valid: false,
          error: t("llm_api_key_invalid", { provider: "Anthropic" }),
          provider: "anthropic",
        };
      }

      if (error.status === 429) {
        // Rate limited, but key is valid
        return {
          valid: true,
          provider: "anthropic",
        };
      }

      return {
        valid: false,
        error: t("llm_validation_failed", {
          provider: "Anthropic",
          error: error.message,
        }),
        provider: "anthropic",
      };
    }
  }

  /**
   * Get masked API key for display (show only last 4 chars)
   */
  maskApiKey(apiKey: string): string {
    if (apiKey.length < 20) return "***";
    const visible = apiKey.slice(-4);
    return `sk-ant-***...***${visible}`;
  }

  /**
   * Sanitize object for logging (redact API keys).
   * This function is type-safe, recursive, and does not mutate the original object.
   *
   * @param obj - The object to sanitize.
   * @returns A deep-cloned and sanitized object.
   */
  sanitizeForLog<T>(obj: T): T {
    const sensitiveKeys = [
      "api_key",
      "apiKey",
      "apikey",
      "token",
      "authorization",
      "auth",
      "secret",
      "password",
    ];
    const redacted = "[REDACTED]";

    // Use a robust deep-cloning method to avoid mutating the original object
    const clonedObj = structuredClone(obj);

    const recurse = (current: unknown) => {
      // Base case: ignore primitives and null
      if (!current || typeof current !== "object") {
        return;
      }

      // Handle arrays by recursing into each item
      if (Array.isArray(current)) {
        current.forEach(recurse);
        return;
      }

      // Handle objects
      for (const key in current) {
        if (Object.prototype.hasOwnProperty.call(current, key)) {
          const lowerKey = key.toLowerCase();
          const value = (current as Record<string, unknown>)[key];

          if (sensitiveKeys.some((s) => lowerKey.includes(s))) {
            (current as Record<string, unknown>)[key] = redacted;
          } else if (typeof value === "string" && value.startsWith("sk-ant-")) {
            (current as Record<string, unknown>)[key] = redacted;
          } else {
            // Recurse into nested objects/arrays
            recurse(value);
          }
        }
      }
    };

    try {
      recurse(clonedObj);
      return clonedObj;
    } catch (error) {
      // If sanitization fails, return a placeholder instead of throwing
      return { error: "Failed to sanitize object" } as T;
    }
  }

  /**
   * Check if API key is configured
   */
  async isConfigured(): Promise<boolean> {
    const key = await this.getApiKey();
    return key !== null;
  }
}
