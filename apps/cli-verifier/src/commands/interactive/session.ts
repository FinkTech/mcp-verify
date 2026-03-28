/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ShellSession — Single source of truth for all mutable session state.
 *
 * Responsibilities:
 *   - Bootstrap in-memory state from persisted workspace (auto-migration included)
 *   - Manage multiple workspace contexts (create / switch / delete / clone)
 *   - Keep legacy fields (target, lang, config) in sync with the active context
 *   - Record command history with secret redaction
 *   - Best-effort tool discovery from the active target
 */

import path from 'path';

import { setLanguage } from '@mcp-verify/shared';
import {
  ITransport,
  SecretScanner,
  HighConfidenceDetector,
  EntropyDetector,
  PrefixDetector,
} from '@mcp-verify/core';
import { createTransport } from '../../utils/transport-factory';

import { PersistenceManager } from './persistence';
import type {
  Language,
  SessionState,
  WorkspaceContexts,
  LegacyWorkspaceSession,
  WorkspaceContext,
  SecurityProfile,
  SecurityProfilePreset,
} from '../types/workspace-context';
import { GlobalConfigManager } from '../managers/global-config-manager';
import { EnvironmentLoader } from '../managers/environment-loader';
import { SECURITY_PROFILES } from '../profiles/security-profiles';
import { detectSessionVersion } from '../managers/migration';

const RE_ASSIGNMENT = /\b(?:api[_-]?key|secret|token|password|credential|auth[_-]?token|access[_-]?key)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi;
const RE_BEARER = /Bearer\s+([a-zA-Z0-9_\-+/=.]{20,})/gi;
const RE_AUTH_HEADER = /"Authorization"\s*:\s*"Bearer\s+([^"]{20,})"/gi;
const SEPARATOR_RE = /([\s,;()[\]{}<>`]+)/;


export class ShellSession {

  readonly state: SessionState;
  private secretScanner: SecretScanner;

  constructor() {
    const workspaceData = PersistenceManager.loadWorkspaceData();
    const contexts      = this.loadContexts(workspaceData);
    const globalConfig  = GlobalConfigManager.load();
    const environment   = EnvironmentLoader.load();
    const activeContext = contexts.contexts[contexts.activeContext];

    this.state = {
      // Multi-context fields
      activeContextName: contexts.activeContext,
      contexts:          contexts.contexts,
      globalConfig,
      environment,
      // Legacy compatibility fields (mirror the active context)
      target:    activeContext?.target,
      lang:      activeContext?.lang ?? globalConfig.defaultLanguage,
      config:    activeContext?.config ?? {},
      // Session metadata
      history:   [],
      workspace: path.basename(process.cwd()),
      startedAt: new Date(),
    };

    // Instantiate and configure the secret scanner
    this.secretScanner = new SecretScanner([
      new HighConfidenceDetector(),
      new EntropyDetector(),
      new PrefixDetector(),
    ]);

    if (activeContext) setLanguage(activeContext.lang);
  }

  // ── Active context accessor ──────────────────────────────────────────────

  getActiveContext(): WorkspaceContext {
    return this.state.contexts[this.state.activeContextName];
  }

  // ── Multi-context operations ─────────────────────────────────────────────

  /** Switches the active context. Returns `false` if the name does not exist. */
  switchContext(name: string): boolean {
    if (!(name in this.state.contexts)) return false;

    this.state.activeContextName = name;
    const ctx = this.state.contexts[name];
    this.syncLegacyFields(ctx);
    setLanguage(ctx.lang);
    this.persistContext();
    this.fetchAvailableTools().catch(() => {});
    return true;
  }

  /**
   * Creates a new context. Pass `baseOnActive = true` to deep-clone the current
   * context settings instead of using defaults.
   * Returns `false` if the name already exists.
   */
  createContext(name: string, baseOnActive = false): boolean {
    if (name in this.state.contexts) return false;

    const now = new Date().toISOString();
    const newContext: WorkspaceContext = baseOnActive
      ? { ...structuredClone(this.getActiveContext()), createdAt: now, modifiedAt: now }
      : this.buildDefaultContext();

    this.state.contexts[name] = newContext;
    this.persistContext();
    return true;
  }

  /**
   * Deletes a context. Cannot delete the currently active context.
   * Returns `false` when the context doesn't exist or is active.
   */
  deleteContext(name: string): boolean {
    if (name === this.state.activeContextName) return false;
    if (!(name in this.state.contexts)) return false;

    delete this.state.contexts[name];
    this.persistContext();
    return true;
  }

  /**
   * Deep-clones `source` into a new context named `targetName`, optionally
   * applying `overrides`. Returns `false` on any naming conflict.
   */
  cloneContext(
    source: string,
    targetName: string,
    overrides?: Partial<WorkspaceContext>
  ): boolean {
    if (!(source in this.state.contexts)) return false;
    if (targetName in this.state.contexts) return false;

    const now    = new Date().toISOString();
    const cloned = structuredClone(this.state.contexts[source]);
    cloned.createdAt  = now;
    cloned.modifiedAt = now;

    if (overrides) {
      Object.assign(cloned, overrides);
      cloned.modifiedAt = now;
    }

    this.state.contexts[targetName] = cloned;
    this.persistContext();
    return true;
  }

  /** Returns the names of all contexts. */
  listContexts(): string[] {
    return Object.keys(this.state.contexts);
  }

  // ── Setters ──────────────────────────────────────────────────────────────

  setTarget(value: string): void {
    const ctx      = this.getActiveContext();
    ctx.target     = value;
    ctx.modifiedAt = new Date().toISOString();
    this.state.target = value;
    this.persistContext();
    this.fetchAvailableTools().catch(() => {});
  }

  setLanguage(lang: Language): void {
    const ctx      = this.getActiveContext();
    ctx.lang       = lang;
    ctx.modifiedAt = new Date().toISOString();
    this.state.lang = lang;
    setLanguage(lang);
    this.persistContext();
  }

  /**
   * Switches the security profile of the active context.
   * Accepts any preset name (light | balanced | aggressive) or a custom name.
   * Falls back to 'balanced' if the name is not found.
   */
  setProfile(profileName: string): void {
    const ctx      = this.getActiveContext();
    ctx.profile    = SECURITY_PROFILES[profileName as SecurityProfilePreset]
                       ?? SECURITY_PROFILES['balanced'];
    ctx.modifiedAt = new Date().toISOString();
    this.persistContext();
  }

  /**
   * Saves the current profile settings as a custom named profile.
   * Does NOT mutate the read-only SECURITY_PROFILES constant — creates a
   * shallow copy stored only on the active context.
   */
  saveCustomProfile(profileName: string): void {
    const ctx      = this.getActiveContext();
    ctx.profile    = { ...ctx.profile, name: profileName, isPreset: false };
    ctx.modifiedAt = new Date().toISOString();
    this.persistContext();
  }

  // ── History ──────────────────────────────────────────────────────────────

  /** Records a command to in-memory + on-disk history, redacting secrets first. */
  recordCommand(cmd: string): void {
    if (!cmd.trim()) return;
    const redacted = this.redactSecrets(cmd);
    this.state.history.push(redacted);
    PersistenceManager.appendHistory(redacted);
  }

  /** Replaces known secret patterns with `[REDACTED]`. */
  redactSecrets(text: string): string {
    if (!text || text.trim().length === 0) return text;

    const parts = text.split(SEPARATOR_RE);
    const redacted = parts.map((part) => {
      if (SEPARATOR_RE.test(part)) return part;

      const trimmedToken = part.replace(/^["'`]+|["'`]+$/g, '');
      const wrapLen      = (part.length - trimmedToken.length) / 2;
      const prefix       = wrapLen > 0 ? part.slice(0, wrapLen)        : '';
      const suffix       = wrapLen > 0 ? part.slice(part.length - wrapLen) : '';

      if (this.secretScanner.isSecret(trimmedToken)) {
        return `${prefix}[REDACTED]${suffix}`;
      }
      return part;
    });

    let result = redacted.join('');

    result = result.replace(RE_ASSIGNMENT, (_match, _value, offset, string) => {
      const beforeValue = string.slice(
        offset,
        offset + _match.length - _value.length
      );
      return `${beforeValue}[REDACTED]`;
    });

    result = result.replace(RE_BEARER, `Bearer [REDACTED]`);
    result = result.replace(RE_AUTH_HEADER, `"Authorization": "Bearer [REDACTED]"`);

    return result;
  }

  redactConfig(obj: Record<string, unknown>): Record<string, unknown> {
    const newObj: Record<string, unknown> = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        const value = obj[key];
        if (typeof value === 'string') {
          newObj[key] = this.redactSecrets(value);
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          newObj[key] = this.redactConfig(value as Record<string, unknown>);
        } else {
          newObj[key] = value;
        }
      }
    }
    return newObj;
  }

  // ── Tool discovery ───────────────────────────────────────────────────────

  /**
   * Best-effort: connects to the active target and caches tool names.
   * All errors are silently swallowed — this is a background optimisation.
   */
  async fetchAvailableTools(): Promise<void> {
    const ctx = this.getActiveContext();
    if (!ctx?.target) return;

    let transport: ITransport | null = null;
    try {
      const transportType = ctx.target.startsWith('http') ? 'http' : 'stdio';
      transport = createTransport(ctx.target, { transportType, timeout: 5000 });

      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), 4000)
      );

      const init = transport.send({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities:    {},
          clientInfo:      { name: 'mcp-verify-shell', version: '1.0.0' },
        },
      });

      const response = await Promise.race([init, timeout]);

      if (response) {
        const toolsResponse = await transport.send({
          jsonrpc: '2.0', id: 2, method: 'tools/list', params: {},
        });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tools = (toolsResponse as any)?.result?.tools as
          Array<{ name: string }> | undefined;
        if (Array.isArray(tools)) {
          this.state.availableTools = tools.map(item => item.name);
        }
      }
    } catch {
      // Best-effort — ignore all errors
    } finally {
      try { await transport?.close?.(); } catch { /* ignore */ }
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private loadContexts(
    data: WorkspaceContexts | LegacyWorkspaceSession | undefined
  ): WorkspaceContexts {
    if (!data) return this.buildDefaultContexts();

    const version = detectSessionVersion(data);

    if (version === 'v1') {
      const v1 = data as WorkspaceContexts;
      if (!(v1.activeContext in v1.contexts)) {
        v1.contexts[v1.activeContext] = this.buildDefaultContext();
      }
      return v1;
    }

    if (version === 'legacy') {
      const legacy = data as LegacyWorkspaceSession;
      const now    = new Date().toISOString();
      const ctx    = this.buildDefaultContext();
      if (legacy.target) ctx.target = legacy.target;
      if (legacy.lang)   ctx.lang   = legacy.lang;
      if (legacy.config) ctx.config = legacy.config as Record<string, unknown>;
      return {
        version:       '1.0',
        activeContext: 'default',
        contexts:      { default: ctx },
        savedAt:       now,
      };
    }

    return this.buildDefaultContexts();
  }

  private buildDefaultContexts(): WorkspaceContexts {
    return {
      version:       '1.0',
      activeContext: 'default',
      contexts:      { default: this.buildDefaultContext() },
      savedAt:       new Date().toISOString(),
    };
  }

  private buildDefaultContext(): WorkspaceContext {
    const now          = new Date().toISOString();
    const globalConfig = GlobalConfigManager.load();
    return {
      target:     undefined,
      lang:       globalConfig.defaultLanguage,
      profile:    SECURITY_PROFILES[globalConfig.defaultProfile]
                    ?? SECURITY_PROFILES['balanced'],
      config:     {},
      createdAt:  now,
      modifiedAt: now,
    };
  }

  private syncLegacyFields(ctx: WorkspaceContext): void {
    this.state.target = ctx.target;
    this.state.lang   = ctx.lang;
    this.state.config = ctx.config;
  }

  private persistContext(): void {
    PersistenceManager.saveWorkspaceContexts({
      version:       '1.0',
      activeContext: this.state.activeContextName,
      contexts:      this.state.contexts,
      savedAt:       new Date().toISOString(),
    });
  }
}
