/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Strict JSON Types to avoid 'any'
 */
export type JsonPrimitive = string | number | boolean | null;
export type JsonArray = JsonValue[];
export type JsonObject = {
  [key: string]: JsonValue;
};
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;
/**
 * JSON-RPC Message Types
 */
export interface JsonRpcRequest {
  jsonrpc?: string;
  id: number | string;
  method: string;
  params?: JsonValue;
}
export interface JsonRpcResponse {
  jsonrpc?: string;
  id: number | string;
  result?: JsonValue;
  error?: {
    code: number;
    message: string;
    data?: JsonValue;
  };
}
/**
 * MCP Protocol Base Types
 */
export interface McpSchema {
  type: string;
  properties?: Record<string, JsonValue>;
  required?: string[];
  [key: string]:
    | JsonValue
    | string
    | string[]
    | Record<string, JsonValue>
    | undefined;
}
export interface McpTool {
  name: string;
  description?: string;
  inputSchema: {
    type: string;
    properties?: Record<string, JsonValue>;
    required?: string[];
    [key: string]:
      | JsonValue
      | string
      | string[]
      | Record<string, JsonValue>
      | undefined;
  };
}
export interface McpResource {
  name: string;
  uri: string;
  mimeType?: string;
  description?: string;
}
export interface McpPrompt {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}
//# sourceMappingURL=common.types.d.ts.map
