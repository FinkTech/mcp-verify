/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Ollama Provider
 *
 * LLM provider implementation for local Ollama models.
 *
 * Features:
 * - 100% local execution (no data sent to cloud)
 * - Free (no API costs)
 * - Supports Llama 3.2, CodeLlama, Mistral, and 100+ models
 * - Works offline
 *
 * Setup:
 * ```bash
 * # Install Ollama
 * curl -fsSL https://ollama.com/install.sh | sh
 *
 * # Pull model
 * ollama pull llama3.2
 *
 * # Use with mcp-verify
 * mcp-verify validate <target> --security --llm ollama:llama3.2
 * ```
 *
 * API Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
 *
 * @module libs/core/domain/quality/providers/ollama-provider
 */

import { t, getUserAgent } from '@mcp-verify/shared';
import type {
  ILLMProvider,
  LLMMessage,
  LLMResponse,
  LLMProviderConfig,
} from './llm-provider.interface';

interface OllamaTagsResponse {
  models: {
    name: string;
    model: string;
    modified_at: string;
    size: number;
    digest: string;
    details: {
      parent_model: string;
      format: string;
      family: string;
      families: string[];
      parameter_size: string;
      quantization_level: string;
    };
  }[];
}

interface OllamaGenerateResponse {
  model: string;
  created_at: string;
  response: string;
  done: boolean;
  context?: number[];
  total_duration?: number;
  load_duration?: number;
  prompt_eval_count?: number;
  prompt_eval_duration?: number;
  eval_count?: number;
  eval_duration?: number;
}

export class OllamaProvider implements ILLMProvider {
  private config: LLMProviderConfig;
  private baseUrl: string;

  /**
   * Model context windows (approximate)
   */
  private readonly CONTEXT_WINDOWS: Record<string, number> = {
    'llama3.2': 128_000,
    'llama3.2:3b': 128_000,
    'llama3.1': 128_000,
    'codellama': 16_000,
    'codellama:7b': 16_000,
    'codellama:13b': 16_000,
    'mistral': 32_000,
    'mistral:7b': 32_000,
  };

  constructor(config: LLMProviderConfig) {
    this.config = config;
    this.baseUrl = config.baseUrl || 'http://localhost:11434';
  }

  getName(): string {
    return `Ollama (${this.config.model})`;
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Check if Ollama server is running
      const response = await fetch(`${this.baseUrl}/api/tags`, {
        signal: AbortSignal.timeout(5000),
        headers: { 'User-Agent': getUserAgent() },
      });

      if (!response.ok) {
        return false;
      }

      // Check if requested model is available
      const data = await response.json() as unknown as OllamaTagsResponse;
      const models = data.models || [];

      const modelExists = models.some(
        (m) =>
          m.name === this.config.model ||
          m.name.startsWith(this.config.model + ':')
      );

      if (!modelExists) {
        const availableModels = models.map((m) => m.name).join(', ');
        console.warn(
          t('ollama_model_not_found', {
            url: this.baseUrl,
            model: this.config.model,
            available: availableModels
          })
        );
        return false;
      }

      return true;
    } catch (error: any) {
      // Ollama not running or not reachable
      return false;
    }
  }

  async complete(
    messages: LLMMessage[],
    options?: { maxTokens?: number; temperature?: number; timeout?: number }
  ): Promise<LLMResponse> {
    const { maxTokens = 2000, temperature = 0.2, timeout = 60000 } = options || {};

    // Convert messages to Ollama prompt format
    // Ollama's /api/generate expects a single prompt string
    const prompt = this.formatMessagesAsPrompt(messages);

    // Make request to Ollama
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': getUserAgent(),
        },
        body: JSON.stringify({
          model: this.config.model,
          prompt,
          stream: false, // We want full response, not streaming
          options: {
            temperature,
            num_predict: maxTokens, // Ollama's equivalent of maxTokens
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Ollama API error (${response.status}): ${errorText}`
        );
      }

      const data = await response.json() as unknown as OllamaGenerateResponse;

      return {
        text: data.response || '',
        usage: {
          inputTokens: data.prompt_eval_count || 0,
          outputTokens: data.eval_count || 0,
        },
        metadata: {
          model: data.model,
          finishReason: data.done ? 'stop' : 'length',
        },
      };
    } catch (error: any) {
      clearTimeout(timeoutId);

      if (error.name === 'AbortError') {
        throw new Error(t('ollama_timeout', { timeout }));
      }

      throw new Error(t('ollama_api_error', { error: error.message }));
    }
  }

  getModelInfo(): {
    name: string;
    provider: 'anthropic' | 'ollama' | 'openai' | 'custom';
    contextWindow: number;
  } {
    // Try to find exact match or base model match
    const contextWindow =
      this.CONTEXT_WINDOWS[this.config.model] ||
      this.CONTEXT_WINDOWS[this.config.model.split(':')[0]] ||
      32_000; // Default

    return {
      name: this.config.model,
      provider: 'ollama',
      contextWindow,
    };
  }

  /**
   * Format messages array into single prompt string
   *
   * Ollama doesn't have a native chat API, so we format messages
   * into a single prompt with clear role markers.
   */
  private formatMessagesAsPrompt(messages: LLMMessage[]): string {
    return messages
      .map((m) => {
        const role = m.role === 'system' ? 'System' : m.role === 'user' ? 'User' : 'Assistant';
        return `${role}: ${m.content}`;
      })
      .join('\n\n');
  }
}
