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

import Anthropic from '@anthropic-ai/sdk';

const ENV_VAR_NAME = 'ANTHROPIC_API_KEY';

export interface ApiKeyValidationResult {
  valid: boolean;
  error?: string;
  provider?: string;
}

export class ApiKeyManager {
  /**
   * Retrieve API key from environment variable
   */
  async getApiKey(): Promise<string | null> {
    const envKey = process.env[ENV_VAR_NAME];
    if (envKey && envKey.length > 0) {
      return envKey;
    }
    return null;
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
        model: 'claude-haiku-4-5-20251001', // Cheapest model
        max_tokens: 1,
        messages: [{ role: 'user', content: 'test' }]
      });

      return {
        valid: true,
        provider: 'anthropic'
      };
    } catch (error: any) {
      if (error.status === 401 || error.message?.includes('authentication')) {
        return {
          valid: false,
          error: 'API key is invalid or expired',
          provider: 'anthropic'
        };
      }

      if (error.status === 429) {
        // Rate limited, but key is valid
        return {
          valid: true,
          provider: 'anthropic'
        };
      }

      return {
        valid: false,
        error: `Validation failed: ${error.message}`,
        provider: 'anthropic'
      };
    }
  }

  /**
   * Get masked API key for display (show only last 4 chars)
   */
  maskApiKey(apiKey: string): string {
    if (apiKey.length < 20) return '***';
    const visible = apiKey.slice(-4);
    return `sk-ant-***...***${visible}`;
  }

  /**
   * Sanitize object for logging (redact API keys)
   */
  sanitizeForLog(obj: any): any {
    const sensitive = ['api_key', 'apiKey', 'apikey', 'token', 'authorization', 'auth', 'secret', 'password'];

    try {
      return JSON.parse(JSON.stringify(obj, (key, value) => {
        if (typeof key === 'string' && sensitive.some(s => key.toLowerCase().includes(s))) {
          return '[REDACTED]';
        }
        // Also check string values that look like API keys
        if (typeof value === 'string' && value.startsWith('sk-ant-')) {
          return '[REDACTED]';
        }
        return value;
      }));
    } catch (error) {
      // If sanitization fails, return placeholder instead of failing
      return { error: 'Failed to sanitize object' };
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
