/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Multi-Context Workspace Type Definitions
 *
 * Defines the core types for the multi-context workspace system:
 * - SecurityProfile: Fuzzing/validation configuration presets
 * - WorkspaceContext: Individual context (dev, staging, prod)
 * - WorkspaceContexts: Collection of contexts (v1.0 format)
 * - LegacyWorkspaceSession: Old format (legacy) for migration
 */

/** Language type for i18n support */
export type Language = 'en' | 'es';

/**
 * Security rule blocks for categorization
 */
export type SecurityRuleBlock = 'OWASP' | 'MCP' | 'A' | 'B' | 'C' | 'D';

/**
 * Security profile preset names
 */
export type SecurityProfilePreset = 'light' | 'balanced' | 'aggressive';

/**
 * Security profile configuration
 * Controls fuzzing behavior, validation thresholds, generator/detector settings
 */
export interface SecurityProfile {
  /** Profile name (preset or custom) */
  name: string;

  /** Whether this is a hardcoded preset */
  isPreset: boolean;

  /** Security rule blocks to enable */
  enabledBlocks: SecurityRuleBlock[];

  /** Fuzzing engine configuration */
  fuzzing: {
    useMutations: boolean;
    mutationsPerPayload: number;
    maxPayloadsPerTool: number;
    enableFeedbackLoop: boolean;
  };

  /** Validation thresholds */
  validation: {
    minSecurityScore: number;
    failOnCritical: boolean;
    failOnHigh: boolean;
  };

  /** Attack generator toggles */
  generators: {
    enablePromptInjection: boolean;
    enableClassicPayloads: boolean;
    enablePrototypePollution: boolean;
    enableJwtAttacks: boolean;
  };

  /** Vulnerability detector configuration */
  detectors: {
    enableTimingDetection: boolean;
    timingAnomalyMultiplier: number;
    enableErrorDetection: boolean;
  };
}

/**
 * Individual workspace context (e.g., dev, staging, prod)
 */
export interface WorkspaceContext {
  target: string | undefined;
  lang: Language;
  profile: SecurityProfile;
  config: Record<string, unknown>;
  createdAt: string;
  modifiedAt: string;
}

/**
 * Multi-context workspace data (v1.0 format)
 * Stored in .mcp-verify/session.json
 */
export interface WorkspaceContexts {
  version: '1.0';
  activeContext: string;
  contexts: Record<string, WorkspaceContext>;
  savedAt: string;
}

/**
 * Format of the .mcp-verify/session.json file (legacy format)
 */
export interface WorkspaceSession {
  target?: string;
  lang?: Language;
  config?: Record<string, unknown>;
  savedAt?: string;
}

/**
 * Legacy workspace session format for migration
 */
export interface LegacyWorkspaceSession {
  target?: string;
  lang?: Language;
  config?: Record<string, unknown>;
  savedAt?: string;
}

/**
 * Mutable in-memory state of the active session.
 * Single source of truth for the interactive shell.
 */
export interface SessionState {
  /** Name of the active context (e.g., 'dev', 'staging', 'default') */
  activeContextName: string;

  /** Map of context name → context data */
  contexts: Record<string, WorkspaceContext>;

  /** Global user configuration from ~/.mcp-verify/config.json */
  globalConfig: import('./global-config').GlobalConfig;

  /** Environment variables loaded from .env (session-scoped) */
  environment: import('./environment-vars').EnvironmentVars | undefined;

  // ── Legacy Compatibility Fields ──────────────────────────────────────
  target: string | undefined;
  lang: Language;
  config: Record<string, unknown>;

  // ── Session Metadata ─────────────────────────────────────────────────
  history: string[];
  workspace: string | undefined;
  startedAt: Date;
  availableTools?: string[];
}
