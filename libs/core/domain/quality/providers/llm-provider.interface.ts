/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * LLM Provider Interface
 *
 * Abstraction for multiple LLM providers (Anthropic, Ollama, OpenAI, etc.)
 * Allows mcp-verify to work with any LLM backend.
 *
 * Design principles:
 * - Provider-agnostic (no hardcoded dependencies)
 * - User must explicitly choose provider (no defaults)
 * - Graceful degradation (works without LLM)
 * - Simple interface (minimal abstraction)
 *
 * @module libs/core/domain/quality/providers/llm-provider.interface
 */

export interface LLMMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

export interface LLMResponse {
  /** Generated text from LLM */
  text: string;

  /** Token usage for the request */
  usage: {
    inputTokens: number;
    outputTokens: number;
  };

  /** Optional metadata from provider */
  metadata?: {
    model?: string;
    finishReason?: string;
    [key: string]: unknown;
  };
}

export interface LLMProviderConfig {
  /** API key (for cloud providers) */
  apiKey?: string;

  /** Base URL (for Ollama, custom endpoints) */
  baseUrl?: string;

  /** Model name (e.g., 'claude-haiku-4-5', 'llama3.2', 'gpt-4o-mini') */
  model: string;

  /** Request timeout in milliseconds */
  timeout?: number;
}

/**
 * LLM Provider Interface
 *
 * All LLM providers must implement this interface.
 */
export interface ILLMProvider {
  /**
   * Get provider display name
   *
   * @example
   * 'Anthropic Claude Haiku 4.5'
   * 'Ollama (llama3.2)'
   * 'OpenAI GPT-4o-mini'
   */
  getName(): string;

  /**
   * Check if provider is available
   *
   * - For cloud APIs: Check if API key is set
   * - For Ollama: Check if localhost:11434 is reachable
   *
   * @returns Promise<boolean> true if provider can be used
   */
  isAvailable(): Promise<boolean>;

  /**
   * Send messages to LLM and get response
   *
   * @param messages - Conversation messages
   * @param options - Optional generation parameters
   * @returns Promise<LLMResponse> LLM response with text and usage
   *
   * @throws Error if request fails (network, auth, rate limit, etc.)
   */
  complete(
    messages: LLMMessage[],
    options?: {
      maxTokens?: number;
      temperature?: number;
      timeout?: number;
    },
  ): Promise<LLMResponse>;

  /**
   * Get model information
   *
   * @returns Model metadata (name, context window, etc.)
   */
  getModelInfo(): {
    name: string;
    provider: "anthropic" | "gemini" | "ollama" | "openai" | "custom";
    contextWindow: number;
  };
}
