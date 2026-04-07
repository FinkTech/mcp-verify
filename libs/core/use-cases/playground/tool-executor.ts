/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import type { ITransport } from "../../domain/transport";
import type {
  JsonObject,
  JsonValue,
  McpTool,
  McpPrompt,
  JsonRpcNotification,
} from "../../domain/shared/common.types";

export interface ToolExecutionResult {
  success: boolean;
  result?: JsonValue;
  error?: string;
  durationMs: number;
}

export class ToolExecutor {
  private transport: ITransport;
  private requestId: number = 1000;

  constructor(transport: ITransport) {
    this.transport = transport;
  }

  async connect(): Promise<void> {
    await this.transport.connect();
    // Initialize connection
    await this.executeRPC("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "mcp-playground", version: "0.1.0" },
    });
    // Send initialized notification (fire and forget, no ID)
    await this.executeRPC(
      "notifications/initialized",
      {},
      { isNotification: true },
    );
  }

  async listTools(): Promise<McpTool[]> {
    const response = await this.executeRPC("tools/list", {});
    return (response.tools as McpTool[]) || [];
  }

  async listPrompts(): Promise<McpPrompt[]> {
    try {
      const response = await this.executeRPC("prompts/list", {});
      return (response.prompts as McpPrompt[]) || [];
    } catch (e) {
      // Server might not support prompts
      return [];
    }
  }

  async executeTool(
    name: string,
    args: JsonObject,
  ): Promise<ToolExecutionResult> {
    const start = Date.now();
    try {
      const response = await this.executeRPC("tools/call", {
        name,
        arguments: args,
      });

      return {
        success: true,
        result: response,
        durationMs: Date.now() - start,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - start,
      };
    }
  }

  async getPrompt(
    name: string,
    args: JsonObject,
  ): Promise<ToolExecutionResult> {
    const start = Date.now();
    try {
      const response = await this.executeRPC("prompts/get", {
        name,
        arguments: args,
      });

      return {
        success: true,
        result: response,
        durationMs: Date.now() - start,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - start,
      };
    }
  }

  private async sendJsonRPC(
    method: string,
    params: JsonObject,
    timeoutMs?: number,
  ): Promise<any> {
    const response = await this.transport.send(
      {
        jsonrpc: "2.0",
        id: this.requestId++,
        method,
        params,
      },
      { timeoutMs },
    );
    return response;
  }

  private async sendNotification(
    method: string,
    params: JsonObject,
  ): Promise<void> {
    // Notifications have no ID
    const notification: JsonRpcNotification = {
      jsonrpc: "2.0",
      method,
      params,
    };
    await this.transport.send(notification);
  }

  /**
   * Execute RPC operation with robust error handling
   */
  private async executeRPC<T = any>(
    method: string,
    params: JsonObject,
    options?: { isNotification?: boolean; timeoutMs?: number },
  ): Promise<T | any> {
    // Using any as fallback return type since T | null causes strict check issues in callers
    try {
      if (options?.isNotification) {
        await this.sendNotification(method, params);
        return null;
      }
      return await this.sendJsonRPC(method, params, options?.timeoutMs);
    } catch (error) {
      // Log error but don't crash for optional notifications
      if (options?.isNotification) {
        // console.warn(`Notification ${method} failed (non-critical):`, error);
        return null;
      }
      throw error;
    }
  }

  async close(): Promise<void> {
    this.transport.close();
  }
}
