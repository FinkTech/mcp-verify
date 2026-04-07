/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Google Gemini Provider
 *
 * LLM provider implementation for Google's Gemini API.
 *
 * Features:
 * - Gemini 2.0 Flash, Gemini 1.5 Pro support
 * - Free tier available (great for getting started)
 * - Fast responses with good reasoning
 *
 * Setup:
 * ```bash
 * export GOOGLE_API_KEY="AIza..."
 * mcp-verify validate <target> --semantic-check --llm gemini:gemini-2.0-flash
 * ```
 *
 * Free tier limits (as of 2024):
 * - 15 RPM (requests per minute)
 * - 1M tokens per minute
 * - 1500 requests per day
 *
 * @module libs/core/domain/quality/providers/gemini-provider
 */

import { t } from "@mcp-verify/shared";
import type {
  ILLMProvider,
  LLMMessage,
  LLMResponse,
  LLMProviderConfig,
} from "./llm-provider.interface";

interface GeminiContent {
  role: "user" | "model";
  parts: { text: string }[];
}

interface GeminiResponse {
  candidates: {
    content: {
      parts: { text: string }[];
      role: string;
    };
    finishReason: string;
  }[];
  usageMetadata?: {
    promptTokenCount: number;
    candidatesTokenCount: number;
    totalTokenCount: number;
  };
}

export class GeminiProvider implements ILLMProvider {
  private config: LLMProviderConfig;
  private baseUrl: string;

  /**
   * Model context windows
   * Updated for latest Gemini models (2025)
   */
  private readonly CONTEXT_WINDOWS: Record<string, number> = {
    // Gemini 3.0 (Latest)
    "gemini-3.0-pro": 2_000_000,
    "gemini-3.0-flash": 1_000_000,
    // Gemini 2.5
    "gemini-2.5-pro": 2_000_000,
    "gemini-2.5-flash": 1_000_000,
    // Gemini 2.0
    "gemini-2.0-flash": 1_000_000,
    "gemini-2.0-flash-lite": 1_000_000,
    // Gemini 1.5 (Legacy)
    "gemini-1.5-pro": 2_000_000,
    "gemini-1.5-flash": 1_000_000,
    "gemini-1.5-flash-8b": 1_000_000,
  };

  constructor(config: LLMProviderConfig) {
    this.config = config;
    this.baseUrl =
      config.baseUrl || "https://generativelanguage.googleapis.com/v1beta";

    if (!this.config.apiKey) {
      throw new Error(
        t("gemini_api_key_not_configured") ||
          "Google API key not configured. Set GOOGLE_API_KEY environment variable.",
      );
    }
  }

  getName(): string {
    const modelName = this.config.model
      .replace("gemini-", "Gemini ")
      .replace(/-/g, " ")
      .replace(/(\d)\.(\d)/g, "$1.$2");
    return `Google ${modelName}`;
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey || this.config.apiKey.length === 0) {
      return false;
    }

    // Validate API key format (Google API keys start with AIza)
    if (!this.isValidGoogleKey(this.config.apiKey)) {
      console.warn(
        t("gemini_invalid_key_format") ||
          'Invalid Google API key format. Keys should start with "AIza".',
      );
      return false;
    }

    return true;
  }

  async complete(
    messages: LLMMessage[],
    options?: { maxTokens?: number; temperature?: number; timeout?: number },
  ): Promise<LLMResponse> {
    const {
      maxTokens = 2000,
      temperature = 0.2,
      timeout = 30000,
    } = options || {};

    // Convert messages to Gemini format
    const contents = this.convertToGeminiFormat(messages);

    // Build request URL
    const url = `${this.baseUrl}/models/${this.config.model}:generateContent?key=${this.config.apiKey}`;

    // Create timeout controller
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents,
          generationConfig: {
            maxOutputTokens: maxTokens,
            temperature,
          },
          safetySettings: [
            // Allow all content for security analysis
            { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
            { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
            {
              category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
              threshold: "BLOCK_NONE",
            },
            {
              category: "HARM_CATEGORY_DANGEROUS_CONTENT",
              threshold: "BLOCK_NONE",
            },
          ],
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`Gemini API error (${response.status}): ${errorBody}`);
      }

      const data = (await response.json()) as unknown as GeminiResponse;

      // Extract text from response
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "";

      return {
        text,
        usage: {
          inputTokens: data.usageMetadata?.promptTokenCount || 0,
          outputTokens: data.usageMetadata?.candidatesTokenCount || 0,
        },
        metadata: {
          model: this.config.model,
          finishReason: data.candidates?.[0]?.finishReason,
        },
      };
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Gemini API timeout after ${timeout}ms`);
      }

      throw error;
    }
  }

  getModelInfo(): {
    name: string;
    provider: "anthropic" | "ollama" | "openai" | "gemini" | "custom";
    contextWindow: number;
  } {
    return {
      name: this.config.model,
      provider: "gemini",
      contextWindow: this.CONTEXT_WINDOWS[this.config.model] || 1_000_000,
    };
  }

  /**
   * Convert messages to Gemini format
   *
   * Gemini uses 'user' and 'model' roles, and doesn't have a system role.
   * System messages are prepended to the first user message.
   */
  private convertToGeminiFormat(messages: LLMMessage[]): GeminiContent[] {
    const contents: GeminiContent[] = [];
    let systemPrompt = "";

    for (const message of messages) {
      if (message.role === "system") {
        // Collect system messages to prepend to first user message
        systemPrompt += message.content + "\n\n";
        continue;
      }

      const role = message.role === "assistant" ? "model" : "user";
      let content = message.content;

      // Prepend system prompt to first user message
      if (role === "user" && systemPrompt && contents.length === 0) {
        content = systemPrompt + content;
        systemPrompt = "";
      }

      contents.push({
        role,
        parts: [{ text: content }],
      });
    }

    // If we only have system messages, convert to user message
    if (contents.length === 0 && systemPrompt) {
      contents.push({
        role: "user",
        parts: [{ text: systemPrompt.trim() }],
      });
    }

    return contents;
  }

  /**
   * Validate Google API key format
   * Format: AIza followed by 35 characters
   */
  private isValidGoogleKey(key: string): boolean {
    return /^AIza[\w-]{35,}$/.test(key);
  }
}
