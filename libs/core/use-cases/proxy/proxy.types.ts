/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import type { JsonValue } from '../../domain/shared/common.types';
import type { McpVerifyConfig } from '../../domain/config/config.types';
import type { SecurityFinding } from '../../domain/mcp-server/entities/validation.types';

export interface ProxyConfig {
  targetUrl: string;
  port: number;
  blockCritical: boolean; // Auto-block critical risks?
  maskPii: boolean; // Mask PII in logs?
  lang?: string;
  /** Security scanner configuration (default: DEFAULT_CONFIG) */
  securityConfig?: McpVerifyConfig;
  /** Enable Layer 3 (LLM-based) deep analysis (default: false) */
  deepAnalysis?: boolean;
}

export interface InterceptResult {
  action: 'allow' | 'block' | 'modify';
  modifiedMessage?: JsonValue;
  reason?: string;
  /** Security findings that triggered the action */
  findings?: SecurityFinding[];
  /** Defense layer that made the decision (1=Fast, 2=Suspicious, 3=LLM) */
  layer?: number;
  /** Latency in milliseconds */
  latencyMs?: number;
  /** Custom JSON-RPC error code for explainable blocking */
  errorCode?: number;
}

export interface IGuardrail {
  name: string;
  inspectRequest(message: JsonValue): InterceptResult;
  inspectResponse(message: JsonValue): InterceptResult;
}
