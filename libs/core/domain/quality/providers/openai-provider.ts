/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * OpenAI Provider
 *
 * LLM provider implementation for OpenAI's GPT models.
 *
 * Features:
 * - GPT-4o, GPT-4o-mini, GPT-4 Turbo support
 * - Fast responses (~1-2s)
 * - Strong reasoning capabilities
 * - Widely available
 *
 * Setup:
 * ```bash
 * export OPENAI_API_KEY="sk-..."
 * mcp-verify validate <target> --security --llm openai:gpt-4o-mini
 * ```
 *
 * API Docs: https://platform.openai.com/docs/api-reference
 *
 * @module libs/core/domain/quality/providers/openai-provider
 */

import OpenAI from "openai";
import { t } from "@mcp-verify/shared";
import type {
  ILLMProvider,
  LLMMessage,
  LLMResponse,
  LLMProviderConfig,
} from "./llm-provider.interface";

export class OpenAIProvider implements ILLMProvider {
  private client: OpenAI | null = null;
  private config: LLMProviderConfig;

  /**
   * Model context windows
   */
  private readonly CONTEXT_WINDOWS: Record<string, number> = {
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-4": 8_192,
    "gpt-3.5-turbo": 16_385,
  };

  constructor(config: LLMProviderConfig) {
    this.config = config;

    if (!this.config.apiKey) {
      throw new Error(t("openai_api_key_not_configured"));
    }
  }

  getName(): string {
    const modelName = this.config.model.replace("gpt-", "GPT-").toUpperCase();
    return `OpenAI ${modelName}`;
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey || this.config.apiKey.length === 0) {
      return false;
    }

    // Validate API key format (starts with 'sk-')
    if (!this.config.apiKey.startsWith("sk-")) {
      console.warn(t("openai_invalid_key_format"));
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
        () => reject(new Error(`OpenAI API timeout after ${timeout}ms`)),
        timeout,
      ),
    );

    // Create API request
    const apiPromise = client.chat.completions.create({
      model: this.config.model,
      max_tokens: maxTokens,
      temperature,
      messages: messages.map((m) => ({
        role: m.role,
        content: m.content,
      })),
    });

    // Race between API call and timeout
    const response = await Promise.race([apiPromise, timeoutPromise]);

    // Extract text from response
    const text = response.choices[0].message.content || "";

    return {
      text,
      usage: {
        inputTokens: response.usage?.prompt_tokens || 0,
        outputTokens: response.usage?.completion_tokens || 0,
      },
      metadata: {
        model: response.model,
        finishReason: response.choices[0].finish_reason || undefined,
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
      provider: "openai",
      contextWindow: this.CONTEXT_WINDOWS[this.config.model] || 128_000,
    };
  }

  /**
   * Initialize OpenAI client (lazy initialization)
   */
  private async initClient(): Promise<OpenAI> {
    if (this.client) {
      return this.client;
    }

    if (!this.config.apiKey) {
      throw new Error(t("openai_api_key_not_configured"));
    }

    this.client = new OpenAI({
      apiKey: this.config.apiKey,
      timeout: this.config.timeout || 30000,
    });

    return this.client;
  }
}
