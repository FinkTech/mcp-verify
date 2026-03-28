/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * listInstalledServers Tool — v2.1
 *
 * Discovers MCP servers from all known client configuration files:
 *   - Claude Desktop  (~/.claude/claude_desktop_config.json)
 *   - Gemini CLI      (~/.gemini/settings.json)
 *   - Gemini CLI      (./.gemini/settings.json  — local, overrides global)
 *   - Cursor          (~/.cursor/mcp.json)
 *   - Zed             (~/.config/zed/settings.json)
 *
 * Returns a unified list with precedence/shadowing metadata so callers
 * (and the selfAudit tool) can reason about which config file actually
 * controls each server name.
 */

import { createScopedLogger, translations, Language } from '@mcp-verify/core';
import * as fs   from 'node:fs';
import * as path from 'node:path';
import * as os   from 'node:os';

const logger = createScopedLogger('listInstalledServersTool');
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || 'en';
const t = translations[lang];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ListInstalledServersArgs {
  /** Scan a specific file instead of the standard discovery locations. */
  configPath?: string;
}

interface ListInstalledServersResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

interface RawServerEntry {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

interface ConfigSource {
  label: string;
  path: string;
  exists: boolean;
  parseError?: string;
  servers: Record<string, RawServerEntry>;
}

/** A fully-resolved server entry with precedence information. */
export interface InstalledServer {
  name: string;
  /** Which config file this entry comes from */
  sourceLabel: string;
  sourcePath: string;
  /**
   * ACTIVE   — this entry is the effective one for this server name.
   * SHADOWED — a more-local config defines the same name; this entry is ignored.
   */
  precedence: 'ACTIVE' | 'SHADOWED';
  command: string;
  args: string[];
  hasEnv: boolean;
  envVars: string[];
}

interface ListInstalledServersOutput {
  status: 'success' | 'not_found' | 'error';
  message?: string;
  configPath?: string;
  /** All config files that were considered, including non-existent ones */
  sourcesScanned: Array<{
    label: string;
    path: string;
    exists: boolean;
    serverCount: number;
    parseError?: string;
  }>;
  totalServers: number;
  servers: InstalledServer[];
  serverNames: string[];
  llm_summary: string;
  next_steps: string[];
}

// ---------------------------------------------------------------------------
// Config discovery helpers
// ---------------------------------------------------------------------------

/**
 * Return all candidate config file locations in order from most-global to
 * most-local. When multiple files define the same server name, the last one
 * (most local) takes precedence.
 */
function buildDiscoveryLocations(
  customPath?: string
): Array<{ label: string; path: string }> {
  const home     = os.homedir();
  const platform = os.platform();
  const cwd      = process.cwd();

  if (customPath) {
    return [{ label: 'Custom Config', path: customPath }];
  }

  return [
    {
      label: 'Claude Desktop (Global)',
      path: platform === 'win32'
        ? path.join(process.env.APPDATA ?? '', 'Claude', 'claude_desktop_config.json')
        : platform === 'darwin'
          ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
          : path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    },
    {
      label: 'Gemini CLI (Global)',
      path: path.join(home, '.gemini', 'settings.json'),
    },
    {
      label: 'Gemini CLI (Local)',
      path: path.join(cwd, '.gemini', 'settings.json'),
    },
    {
      label: 'Cursor',
      path: platform === 'win32'
        ? path.join(process.env.APPDATA ?? '', 'Cursor', 'User', 'settings.json')
        : path.join(home, '.cursor', 'mcp.json'),
    },
    {
      label: 'Zed',
      path: path.join(home, '.config', 'zed', 'settings.json'),
    },
  ];
}

/** Extract the mcpServers map from a parsed JSON object. */
function extractMcpServers(raw: unknown): Record<string, RawServerEntry> {
  if (typeof raw !== 'object' || raw === null) return {};
  const obj = raw as Record<string, unknown>;
  if (typeof obj['mcpServers'] === 'object' && obj['mcpServers'] !== null) {
    return obj['mcpServers'] as Record<string, RawServerEntry>;
  }
  return {};
}

/** Read and parse all candidate config files. */
function readAllConfigs(customPath?: string): ConfigSource[] {
  const locations = buildDiscoveryLocations(customPath);

  return locations.map(loc => {
    if (!fs.existsSync(loc.path)) {
      return { label: loc.label, path: loc.path, exists: false, servers: {} };
    }

    try {
      const raw = JSON.parse(fs.readFileSync(loc.path, 'utf8')) as unknown;
      return {
        label:   loc.label,
        path:    loc.path,
        exists:  true,
        servers: extractMcpServers(raw),
      };
    } catch (err) {
      return {
        label:      loc.label,
        path:       loc.path,
        exists:     true,
        parseError: err instanceof Error ? err.message : String(err),
        servers:    {},
      };
    }
  });
}

/**
 * Resolve precedence across all sources.
 * The last source (most local) that defines a server name is ACTIVE;
 * earlier definitions of the same name are SHADOWED.
 */
function resolvePrecedence(sources: ConfigSource[]): InstalledServer[] {
  // Find the index of the winning source for each server name
  const winnerIndex = new Map<string, number>();
  for (let i = 0; i < sources.length; i++) {
    for (const name of Object.keys(sources[i].servers)) {
      winnerIndex.set(name, i);
    }
  }

  const result: InstalledServer[] = [];

  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];
    for (const [name, entry] of Object.entries(src.servers)) {
      result.push({
        name,
        sourceLabel: src.label,
        sourcePath:  src.path,
        precedence:  winnerIndex.get(name) === i ? 'ACTIVE' : 'SHADOWED',
        command:     entry.command,
        args:        entry.args ?? [],
        hasEnv:      !!(entry.env && Object.keys(entry.env).length > 0),
        envVars:     entry.env ? Object.keys(entry.env) : [],
      });
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Summary & next-steps generators
// ---------------------------------------------------------------------------

function buildSummary(servers: InstalledServer[], sourcesFound: number): string {
  if (servers.length === 0) {
    return '📭 No MCP servers found in any of the scanned configuration files.';
  }

  const active   = servers.filter(s => s.precedence === 'ACTIVE');
  const shadowed = servers.filter(s => s.precedence === 'SHADOWED');

  const lines: string[] = [
    `📡 Found ${servers.length} MCP server entry/entries across ${sourcesFound} config file(s):`,
    `   • ${active.length} ACTIVE (will be used by their respective clients)`,
  ];

  if (shadowed.length > 0) {
    lines.push(`   • ${shadowed.length} SHADOWED (overridden by a more-local config — these are ignored)`);
  }

  lines.push('');

  for (const s of active) {
    const argsInfo = s.args.length > 0 ? ` with ${s.args.length} arg(s)` : '';
    const envInfo  = s.hasEnv ? ` + ${s.envVars.length} env var(s)` : '';
    lines.push(`  ✅ "${s.name}"  [${s.sourceLabel}]`);
    lines.push(`     command: ${s.command}${argsInfo}${envInfo}`);
  }

  if (shadowed.length > 0) {
    lines.push('');
    for (const s of shadowed) {
      lines.push(`  ⚠️  "${s.name}"  [${s.sourceLabel}] — SHADOWED by a more-local config`);
    }
  }

  return lines.join('\n');
}

function buildNextSteps(servers: InstalledServer[]): string[] {
  const active = servers.filter(s => s.precedence === 'ACTIVE');

  if (servers.length === 0) {
    return [
      'Add MCP servers to one of the scanned configuration files',
      'Use the configPath argument to specify a custom config file location',
    ];
  }

  const steps: string[] = [
    `Run a full health check: selfAudit()`,
  ];

  active.slice(0, 3).forEach(s => {
    steps.push(
      `Validate "${s.name}": validateServer({command: "${s.command}", args: [${s.args.map(a => `"${a}"`).join(', ')}]})`
    );
  });

  if (active.length > 3) {
    steps.push(`... and ${active.length - 3} more active server(s)`);
  }

  return steps;
}

// ---------------------------------------------------------------------------
// Tool export
// ---------------------------------------------------------------------------

export async function listInstalledServersTool(
  args: unknown
): Promise<ListInstalledServersResult> {
  const { configPath } = (args ?? {}) as ListInstalledServersArgs;

  logger.info('Starting listInstalledServers v2.1', {
    metadata: { configPath: configPath ?? 'auto-discover' },
  });

  try {
    const sources = readAllConfigs(configPath);
    const servers = resolvePrecedence(sources);

    const existingSources = sources.filter(s => s.exists);

    if (existingSources.length === 0 && !configPath) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            status:         'not_found',
            message:        t.mcp_error_config_not_found,
            sourcesScanned: sources.map(s => ({
              label:       s.label,
              path:        s.path,
              exists:      s.exists,
              serverCount: 0,
            })),
            totalServers: 0,
            servers:      [],
            serverNames:  [],
            llm_summary:  '📭 No MCP configuration files found in any standard location.',
            next_steps: [
              'Install Claude Desktop, Gemini CLI, Cursor or another MCP client',
              'Use the configPath argument to point to a custom config file',
            ],
          } satisfies ListInstalledServersOutput, null, 2),
        }],
      };
    }

    const output: ListInstalledServersOutput = {
      status: 'success',
      sourcesScanned: sources.map(s => ({
        label:       s.label,
        path:        s.path,
        exists:      s.exists,
        serverCount: Object.keys(s.servers).length,
        parseError:  s.parseError,
      })),
      totalServers: servers.length,
      servers,
      serverNames:  [...new Set(servers.map(s => s.name))],
      llm_summary:  buildSummary(servers, existingSources.length),
      next_steps:   buildNextSteps(servers),
    };

    logger.info('listInstalledServers complete', {
      metadata: {
        sourcesScanned: sources.length,
        sourcesFound:   existingSources.length,
        totalServers:   servers.length,
        active:         servers.filter(s => s.precedence === 'ACTIVE').length,
        shadowed:       servers.filter(s => s.precedence === 'SHADOWED').length,
      },
    });

    return {
      content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
    };

  } catch (error) {
    logger.error('listInstalledServers failed', error as Error);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status:  'error',
          error:   (error as Error).message,
          message: t.mcp_error_failed_to_read_config,
          llm_summary: `Error scanning configuration files: ${(error as Error).message}`,
          next_steps: [
            'Check that the config files are readable',
            'Verify the JSON syntax in your config files',
            'Try specifying a configPath to a specific file',
          ],
        }, null, 2),
      }],
      isError: true,
    };
  }
}
