/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export interface RawServerEntry {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface ConfigSource {
  label: string;
  path: string;
  servers: Record<string, RawServerEntry>;
  parseError?: string;
}

export function buildConfigLocations(
  customPath?: string,
): Array<{ label: string; path: string }> {
  const home = os.homedir();
  const platform = os.platform();
  const cwd = process.cwd();

  if (customPath) {
    return [{ label: "Custom Config", path: customPath }];
  }

  return [
    {
      label: "Claude Desktop (Global)",
      path:
        platform === "win32"
          ? path.join(
              process.env.APPDATA ?? "",
              "Claude",
              "claude_desktop_config.json",
            )
          : platform === "darwin"
            ? path.join(
                home,
                "Library",
                "Application Support",
                "Claude",
                "claude_desktop_config.json",
              )
            : path.join(
                home,
                ".config",
                "Claude",
                "claude_desktop_config.json",
              ),
    },
    {
      label: "Gemini CLI (Global)",
      path: path.join(home, ".gemini", "settings.json"),
    },
    {
      label: "Gemini CLI (Local)",
      path: path.join(cwd, ".gemini", "settings.json"),
    },
    {
      label: "Cursor",
      path:
        platform === "win32"
          ? path.join(
              process.env.APPDATA ?? "",
              "Cursor",
              "User",
              "settings.json",
            )
          : path.join(home, ".cursor", "mcp.json"),
    },
    {
      label: "Zed",
      path: path.join(home, ".config", "zed", "settings.json"),
    },
  ];
}

export function extractMcpServers(
  raw: unknown,
): Record<string, RawServerEntry> {
  if (typeof raw !== "object" || raw === null) return {};
  const obj = raw as Record<string, unknown>;
  if (obj["mcpServers"] && typeof obj["mcpServers"] === "object") {
    return obj["mcpServers"] as Record<string, RawServerEntry>;
  }
  return {};
}

export function discoverConfigs(customPath?: string): ConfigSource[] {
  const locations = buildConfigLocations(customPath);
  const sources: ConfigSource[] = [];

  for (const loc of locations) {
    if (!fs.existsSync(loc.path)) continue;

    try {
      const raw = JSON.parse(fs.readFileSync(loc.path, "utf8")) as unknown;
      sources.push({
        label: loc.label,
        path: loc.path,
        servers: extractMcpServers(raw),
      });
    } catch (err) {
      sources.push({
        label: loc.label,
        path: loc.path,
        servers: {},
        parseError: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return sources;
}

/**
 * Resolve a server name to its full command and args by searching all configs.
 */
export function resolveServerByName(name: string): RawServerEntry | undefined {
  const sources = discoverConfigs();
  // Reverse to respect precedence (local wins)
  for (const src of [...sources].reverse()) {
    if (src.servers[name]) {
      return src.servers[name];
    }
  }
  return undefined;
}
