/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Anthropic Claude Provider
 *
 * LLM provider implementation for Anthropic's Claude API.
 *
 * Features:
 * - Claude Haiku 4.5, Sonnet 4, Opus 4.5 support
 * - Fast responses (~1-2s)
 * - Excellent reasoning for security analysis
 *
 * Setup:
 * ```bash
 * export ANTHROPIC_API_KEY="sk-ant-api03-..."
 * mcp-verify validate <target> --security --llm anthropic:claude-haiku-4-5
 * ```
 *
 * @module libs/core/domain/quality/providers/anthropic-provider
 */

import Anthropic from "@anthropic-ai/sdk";
import { t } from "@mcp-verify/shared";
import type {
  ILLMProvider,
  LLMMessage,
  LLMResponse,
  LLMProviderConfig,
} from "./llm-provider.interface";

export class AnthropicProvider implements ILLMProvider {
  private client: Anthropic | null = null;
  private config: LLMProviderConfig;

  /**
   * Model context windows
   */
  private readonly CONTEXT_WINDOWS: Record<string, number> = {
    "claude-haiku-4-5-20251001": 200_000,
    "claude-sonnet-4-20250514": 200_000,
    "claude-opus-4-5-20251101": 200_000,
  };

  constructor(config: LLMProviderConfig) {
    this.config = config;

    if (!this.config.apiKey) {
      throw new Error(t("anthropic_api_key_not_configured"));
    }
  }

  getName(): string {
    const modelName = this.config.model
      .replace("claude-", "Claude ")
      .replace(/-\d+$/g, "");
    return `Anthropic ${modelName}`;
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey || this.config.apiKey.length === 0) {
      return false;
    }

    // Validate API key format
    if (!this.isValidAnthropicKey(this.config.apiKey)) {
      console.warn(t("anthropic_invalid_key_format"));
      return false;
    }

    return true;
  }

  async complete(
    messages: LLMMessage[],
    options?: { maxTokens?: number; temperature?: number; timeout?: number },
  ): Promise<LLMResponse> {
    const client = await this.initClient();

    const {
      maxTokens = 2000,
      temperature = 0.2,
      timeout = 30000,
    } = options || {};

    // Create timeout promise
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`Anthropic API timeout after ${timeout}ms`)),
        timeout,
      ),
    );

    // Create API request
    const apiPromise = client.messages.create({
      model: this.config.model,
      max_tokens: maxTokens,
      temperature,
      messages: messages.map((m) => ({
        role: m.role === "system" ? "user" : m.role, // Anthropic doesn't have 'system' role
        content: m.content,
      })),
    });

    // Race between API call and timeout
    const response = await Promise.race([apiPromise, timeoutPromise]);

    // Extract text from response
    const textContent = response.content.find((c) => c.type === "text");
    const text =
      textContent && textContent.type === "text" ? textContent.text : "";

    return {
      text,
      usage: {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens,
      },
      metadata: {
        model: response.model,
        finishReason: response.stop_reason || undefined,
      },
    };
  }

  getModelInfo(): {
    name: string;
    provider: "anthropic" | "ollama" | "openai" | "custom";
    contextWindow: number;
  } {
    return {
      name: this.config.model,
      provider: "anthropic",
      contextWindow: this.CONTEXT_WINDOWS[this.config.model] || 200_000,
    };
  }

  /**
   * Initialize Anthropic client (lazy initialization)
   */
  private async initClient(): Promise<Anthropic> {
    if (this.client) {
      return this.client;
    }

    if (!this.config.apiKey) {
      throw new Error(t("anthropic_api_key_not_configured"));
    }

    this.client = new Anthropic({ apiKey: this.config.apiKey });
    return this.client;
  }

  /**
   * Validate Anthropic API key format
   * Format: sk-ant-api03-XXXXX...
   */
  private isValidAnthropicKey(key: string): boolean {
    return /^sk-ant-api\d{2}-[\w-]{95,}$/.test(key);
  }
}
