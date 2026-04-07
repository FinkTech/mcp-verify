/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * selfAudit Tool — v2.1 "Environment Health Check"
 *
 * The immune system of the MCP development environment.
 * Beyond listing servers, this tool understands the holistic health of the
 * entire local MCP ecosystem:
 *
 *   Phase 1 — Environment Diagnostics   (Node, Git, Python, Deno)
 *   Phase 2 — Config Discovery          (with shadowing/precedence detection)
 *   Phase 3 — Command DNA Validation    (binary, args, format checks)
 *   Phase 4 — Reachability / Life Test  (HEALTHY | ZOMBIE | GHOST | MISCONFIGURED)
 *   Phase 5 — LLM Summary               (hierarchical, emoji-rich, actionable)
 */

import {
  createScopedLogger,
  translations,
  Language,
  DiagnosticRunner,
} from "@mcp-verify/core";
import {
  NodeRuntimeCheck,
  GitInstallationCheck,
  PythonRuntimeCheck,
  DenoRuntimeCheck,
} from "@mcp-verify/core/infrastructure/diagnostics/checks/environment-checks";
import { MCPValidator } from "@mcp-verify/core/use-cases/validator/validator";
import {
  discoverConfigs,
  RawServerEntry,
  ConfigSource,
} from "../utils/config-discovery.js";
import { StdioTransport } from "@mcp-verify/core";
// Fix: Import from cli-verifier utils which is accessible in this monorepo build context
import { createTransport } from "../../../cli-verifier/src/utils/transport-factory";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { execSync } from "node:child_process";

const logger = createScopedLogger("selfAuditTool");
const lang: Language = (process.env.MCP_VERIFY_LANG as Language) || "en";
const t = translations[lang];

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Timeout for the MCP handshake life-test, in milliseconds. */
const HANDSHAKE_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SelfAuditArgs {
  configPath?: string;
  skipServerValidation?: boolean;
}

interface SelfAuditResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Config discovery result types
// ---------------------------------------------------------------------------

type ServerHealthStatus = "HEALTHY" | "ZOMBIE" | "GHOST" | "MISCONFIGURED";
type CommandFormatIssue =
  | "ARGS_IN_COMMAND"
  | "BINARY_NOT_FOUND"
  | "ARG0_NOT_FOUND";

interface CommandDnaResult {
  binaryFound: boolean;
  arg0Exists: boolean;
  formatIssue?: CommandFormatIssue;
  resolvedBinaryPath?: string;
  resolvedArg0Path?: string;
  suggestedFix?: string;
}

interface ServerAuditEntry {
  name: string;
  sourceLabel: string;
  sourcePath: string;
  /** ACTIVE = this entry wins; SHADOWED = overridden by a more-local config */
  precedence: "ACTIVE" | "SHADOWED";
  command: string;
  args: string[];
  commandDna: CommandDnaResult;
  health: ServerHealthStatus;
  healthDetail?: string;
  /** Handshake latency in ms, only set when health === HEALTHY */
  latencyMs?: number;
}

interface EnvironmentHealthReport {
  status: "success" | "error";
  generatedAt: string;
  environment: {
    status: "healthy" | "issues_detected";
    checks: Array<{ name: string; status: string; message: string }>;
  };
  configs: {
    found: number;
    sources: Array<{
      label: string;
      path: string;
      serverCount: number;
      parseError?: string;
    }>;
  };
  servers: {
    total: number;
    healthy: number;
    misconfigured: number;
    ghost: number;
    zombie: number;
    entries: ServerAuditEntry[];
  };
  llm_summary: string;
}

// ---------------------------------------------------------------------------
// Phase 2 — Config shadowing / precedence resolution
// ---------------------------------------------------------------------------

interface ResolvedServer {
  name: string;
  sourceLabel: string;
  sourcePath: string;
  precedence: "ACTIVE" | "SHADOWED";
  entry: RawServerEntry;
}

/**
 * Flatten all config sources into a list of resolved server entries.
 * Later sources in the array override earlier ones (more-local wins).
 */
function resolveServerPrecedence(sources: ConfigSource[]): ResolvedServer[] {
  // Map: serverName → index of the ACTIVE source (last one that defines it)
  const activeSource: Map<string, number> = new Map();

  for (let i = 0; i < sources.length; i++) {
    for (const name of Object.keys(sources[i].servers)) {
      activeSource.set(name, i);
    }
  }

  const resolved: ResolvedServer[] = [];

  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];
    for (const [name, entry] of Object.entries(src.servers)) {
      resolved.push({
        name,
        sourceLabel: src.label,
        sourcePath: src.path,
        precedence: activeSource.get(name) === i ? "ACTIVE" : "SHADOWED",
        entry,
      });
    }
  }

  return resolved;
}

// ---------------------------------------------------------------------------
// Phase 3 — Command DNA validation
// ---------------------------------------------------------------------------

/**
 * Check whether an executable is available via PATH using `where` (Windows)
 * or `which` (Unix).
 */
function resolveCommandInPath(command: string): string | undefined {
  try {
    const cmd =
      os.platform() === "win32" ? `where "${command}"` : `which "${command}"`;
    const result = execSync(cmd, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
    return result.split(/\r?\n/)[0]; // take first match
  } catch {
    return undefined;
  }
}

/**
 * Detect the "args mixed into command string" anti-pattern.
 * e.g. command: "node D:\\server.js"  →  should be split into command + args.
 */
function detectArgsMixedInCommand(command: string): boolean {
  // If the command string contains a space followed by a path separator or flag
  return (
    /\s+[A-Za-z]:[/\\]/.test(command) || // Windows absolute path in string
    /\s+\/[a-zA-Z]/.test(command) || // Unix absolute path in string
    /\s+-/.test(command) || // flags mixed in
    /\s+\w.*\.js/.test(command)
  ); // .js file mixed in
}

/**
 * Validate the "DNA" of a server command: binary existence, arg0 existence,
 * and format correctness.
 */
function validateCommandDna(entry: RawServerEntry): CommandDnaResult {
  const result: CommandDnaResult = {
    binaryFound: false,
    arg0Exists: false,
  };

  // --- Format check: args mixed into command string ---
  if (detectArgsMixedInCommand(entry.command)) {
    result.formatIssue = "ARGS_IN_COMMAND";
    // Try to auto-suggest the correct split
    const parts = entry.command.trim().split(/\s+/);
    const suggestedCommand = parts[0];
    const suggestedArgs = parts.slice(1).concat(entry.args ?? []);
    result.suggestedFix = `"command": "${suggestedCommand}", "args": [${suggestedArgs.map((a) => `"${a}"`).join(", ")}]`;
  }

  // --- Binary check ---
  const rawCommand = entry.command.trim();
  let cmd = rawCommand;

  // If the command contains spaces but is not quoted, it might be a path with spaces
  // or a command with args. We first check if the whole string is a valid file.
  if (!fs.existsSync(rawCommand)) {
    // If not a full file, it's likely a command + args or a path in PATH
    // We only split if we don't find the command as is
    cmd = rawCommand.split(/\s+/)[0].replace(/^"/, "").replace(/"$/, "");
  }

  if (path.isAbsolute(cmd)) {
    result.binaryFound = fs.existsSync(cmd);
    result.resolvedBinaryPath = cmd;
  } else {
    const found = resolveCommandInPath(cmd);
    result.binaryFound = found !== undefined;
    result.resolvedBinaryPath = found;
  }

  if (!result.binaryFound) {
    result.formatIssue = result.formatIssue ?? "BINARY_NOT_FOUND";
  }

  // --- Arg0 check (first meaningful argument, usually the script file) ---
  const args = entry.args ?? [];
  const scriptArg = args.find(
    (a) =>
      !a.startsWith("-") &&
      (a.endsWith(".js") ||
        a.endsWith(".ts") ||
        a.endsWith(".mjs") ||
        a.endsWith(".cjs")),
  );

  if (scriptArg) {
    const resolvedScript = path.isAbsolute(scriptArg)
      ? scriptArg
      : path.resolve(process.cwd(), scriptArg);

    result.arg0Exists = fs.existsSync(resolvedScript);
    result.resolvedArg0Path = resolvedScript;

    if (!result.arg0Exists) {
      result.formatIssue = result.formatIssue ?? "ARG0_NOT_FOUND";

      // Suggest possible compiled output locations
      const alternatives = [
        resolvedScript.replace("apps/", "").replace("/src/", "/dist/"),
        resolvedScript.replace("/src/", "/dist/"),
        resolvedScript.replace("index.ts", "index.js"),
      ].filter((p) => fs.existsSync(p));

      if (alternatives.length > 0) {
        result.suggestedFix =
          (result.suggestedFix ?? "") +
          ` Possible existing path: "${alternatives[0]}"`;
      }
    }
  } else {
    // No script arg — binary-only command (e.g. npx, uvx), treat arg0 as N/A
    result.arg0Exists = true;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Phase 4 — Reachability / Life Test
// ---------------------------------------------------------------------------

/**
 * Check if a process with the given command name is currently running.
 * Uses `tasklist` on Windows and `pgrep` on Unix.
 */
function isProcessRunning(command: string, dna: CommandDnaResult): boolean {
  try {
    // Use the resolved binary name for better matching
    const binaryName = dna.resolvedBinaryPath
      ? path.basename(dna.resolvedBinaryPath)
      : path.basename(command.trim().split(/\s+/)[0]);

    const searchName = binaryName.replace(/\.exe$/i, "");

    if (os.platform() === "win32") {
      const output = execSync(
        `tasklist /FI "IMAGENAME eq ${searchName}.exe" /NH`,
        {
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"],
        },
      );
      return output.toLowerCase().includes(searchName.toLowerCase());
    } else {
      execSync(`pgrep -f "${searchName}"`, { stdio: ["pipe", "pipe", "pipe"] });
      return true;
    }
  } catch {
    return false;
  }
}

/**
 * Attempt a real MCP handshake with a hard timeout.
 * Returns the health status and optional latency.
 */
async function testServerLife(
  entry: RawServerEntry,
  dna: CommandDnaResult,
): Promise<{
  health: ServerHealthStatus;
  detail?: string;
  latencyMs?: number;
}> {
  // If command DNA is broken, skip the network test — it will never connect
  if (
    !dna.binaryFound ||
    (!dna.arg0Exists && dna.resolvedArg0Path !== undefined)
  ) {
    return {
      health: "MISCONFIGURED",
      detail:
        dna.formatIssue === "ARGS_IN_COMMAND"
          ? "Arguments are mixed into the command string"
          : dna.formatIssue === "BINARY_NOT_FOUND"
            ? `Binary not found: "${entry.command}"`
            : `Script file not found: "${dna.resolvedArg0Path}"`,
    };
  }

  const start = Date.now();
  let validator: MCPValidator | null = null;

  try {
    // Quote command if it has spaces for Windows shell compatibility
    const spawnCmd =
      os.platform() === "win32" &&
      entry.command.includes(" ") &&
      !entry.command.startsWith('"')
        ? `"${entry.command}"`
        : entry.command;

    const transport = StdioTransport.create(
      spawnCmd,
      entry.args ?? [],
      HANDSHAKE_TIMEOUT_MS,
      entry.env,
    );

    validator = new MCPValidator(transport);

    const handshakePromise = validator.testHandshake();
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error("Handshake timeout")),
        HANDSHAKE_TIMEOUT_MS,
      ),
    );

    const result = await Promise.race([handshakePromise, timeoutPromise]);
    const latencyMs = Date.now() - start;

    if (result.success) {
      return { health: "HEALTHY", latencyMs };
    }

    // Handshake responded but returned an error — process is alive but broken
    const processRunning = isProcessRunning(entry.command, dna);
    return {
      health: processRunning ? "ZOMBIE" : "GHOST",
      detail: result.error,
    };
  } catch (err) {
    const latencyMs = Date.now() - start;
    const processRunning = isProcessRunning(entry.command, dna);

    if (latencyMs >= HANDSHAKE_TIMEOUT_MS && processRunning) {
      return {
        health: "ZOMBIE",
        detail: `Process exists but did not respond within ${HANDSHAKE_TIMEOUT_MS / 1000}s`,
      };
    }

    return {
      health: processRunning ? "ZOMBIE" : "GHOST",
      detail: err instanceof Error ? err.message : String(err),
    };
  } finally {
    try {
      validator?.cleanup();
    } catch {
      /* ignore cleanup errors */
    }
  }
}

// ---------------------------------------------------------------------------
// Phase 5 — LLM Summary generation
// ---------------------------------------------------------------------------

function buildLlmSummary(
  envStatus: string,
  sources: ConfigSource[],
  entries: ServerAuditEntry[],
): string {
  const lines: string[] = [];

  lines.push("🩺 mcp-verify Environment Health Check\n");

  // Environment
  const envIcon = envStatus === "healthy" ? "✅" : "⚠️";
  lines.push(`${envIcon} Environment: ${envStatus}`);

  // Config files
  lines.push(`\n📁 Configuration Files Found: ${sources.length}`);
  for (const src of sources) {
    if (src.parseError) {
      lines.push(`  ❌ ${src.label}`);
      lines.push(`     Path: ${src.path}`);
      lines.push(`     Error: ${src.parseError}`);
    } else {
      lines.push(
        `  📄 ${src.label} (${Object.keys(src.servers).length} server(s))`,
      );
      lines.push(`     Path: ${src.path}`);
    }
  }

  // Servers grouped by health
  const healthy = entries.filter((e) => e.health === "HEALTHY");
  const misconfigured = entries.filter((e) => e.health === "MISCONFIGURED");
  const zombies = entries.filter((e) => e.health === "ZOMBIE");
  const ghosts = entries.filter((e) => e.health === "GHOST");
  const shadowed = entries.filter((e) => e.precedence === "SHADOWED");

  lines.push(`\n🖥️  Servers: ${entries.length} total`);

  if (healthy.length > 0) {
    lines.push(`\n  ✅ HEALTHY (${healthy.length})`);
    for (const s of healthy) {
      lines.push(`     • ${s.name}  [${s.sourceLabel}]  ${s.latencyMs}ms`);
    }
  }

  if (misconfigured.length > 0) {
    lines.push(`\n  ❌ MISCONFIGURED (${misconfigured.length})`);
    for (const s of misconfigured) {
      lines.push(`     • ${s.name}  [${s.sourceLabel}]`);
      lines.push(`       Reason: ${s.healthDetail ?? "Unknown"}`);
      if (s.commandDna.suggestedFix) {
        lines.push(`       💡 Fix: ${s.commandDna.suggestedFix}`);
      }
    }
  }

  if (zombies.length > 0) {
    lines.push(
      `\n  🧟 ZOMBIE (${zombies.length}) — process running but not responding`,
    );
    for (const s of zombies) {
      lines.push(`     • ${s.name}  [${s.sourceLabel}]`);
      if (s.healthDetail) lines.push(`       Detail: ${s.healthDetail}`);
    }
  }

  if (ghosts.length > 0) {
    lines.push(
      `\n  👻 GHOST (${ghosts.length}) — configured but no process found`,
    );
    for (const s of ghosts) {
      lines.push(`     • ${s.name}  [${s.sourceLabel}]`);
      if (s.healthDetail) lines.push(`       Detail: ${s.healthDetail}`);
    }
  }

  if (shadowed.length > 0) {
    lines.push(
      `\n  ⚠️  SHADOWED (${shadowed.length}) — overridden by a more-local config`,
    );
    for (const s of shadowed) {
      lines.push(
        `     • ${s.name}  [${s.sourceLabel}] is overridden — its settings are ignored`,
      );
    }
  }

  // Overall verdict
  lines.push("");
  if (misconfigured.length > 0 || zombies.length > 0) {
    lines.push(
      "⚡ Action required: Fix misconfigured servers before the agent can use them.",
    );
  } else if (ghosts.length > 0) {
    lines.push(
      "ℹ️  Some servers are configured but not running. Start them to make them available.",
    );
  } else if (healthy.length === entries.length && entries.length > 0) {
    lines.push("🎉 All servers are healthy and reachable.");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Main tool export
// ---------------------------------------------------------------------------

export async function selfAuditTool(args: unknown): Promise<SelfAuditResult> {
  const { configPath, skipServerValidation } = (args ?? {}) as SelfAuditArgs;

  logger.info("Starting selfAudit v2.1", {
    metadata: { configPath, skipServerValidation },
  });

  try {
    // ------------------------------------------------------------------
    // Phase 1 — Environment diagnostics
    // ------------------------------------------------------------------
    logger.info("Phase 1: Environment diagnostics");

    const diagRunner = new DiagnosticRunner();
    diagRunner.register(new NodeRuntimeCheck());
    diagRunner.register(new GitInstallationCheck());
    diagRunner.register(new PythonRuntimeCheck());
    diagRunner.register(new DenoRuntimeCheck());

    const diagResults = await diagRunner.runAll();
    const envStatus: "healthy" | "issues_detected" = diagResults.every(
      (r) => r.status === "pass" || r.status === "skip",
    )
      ? "healthy"
      : "issues_detected";

    // ------------------------------------------------------------------
    // Phase 2 — Config discovery + shadowing resolution
    // ------------------------------------------------------------------
    logger.info("Phase 2: Config discovery");

    const sources = discoverConfigs(configPath);
    const resolved = resolveServerPrecedence(sources);

    logger.info(
      `Discovered ${sources.length} config file(s), ${resolved.length} server entries`,
    );

    // ------------------------------------------------------------------
    // Phase 3 + 4 — DNA validation & life test per server
    // ------------------------------------------------------------------
    logger.info("Phase 3+4: Command DNA validation and life tests");

    const serverEntries: ServerAuditEntry[] = [];

    for (const srv of resolved) {
      logger.debug(`Auditing server: ${srv.name} (${srv.precedence})`);

      const dna = validateCommandDna(srv.entry);

      let health: ServerHealthStatus = "GHOST";
      let healthDetail: string | undefined;
      let latencyMs: number | undefined;

      if (!skipServerValidation && srv.precedence === "ACTIVE") {
        const lifeTest = await testServerLife(srv.entry, dna);
        health = lifeTest.health;
        healthDetail = lifeTest.detail;
        latencyMs = lifeTest.latencyMs;
      } else if (srv.precedence === "SHADOWED") {
        // Don't bother testing shadowed entries — they are not in use
        health = "GHOST";
        healthDetail = "Shadowed by a more-local configuration";
      } else {
        // skipServerValidation = true
        health = dna.binaryFound && dna.arg0Exists ? "GHOST" : "MISCONFIGURED";
        healthDetail = "Validation skipped";
      }

      serverEntries.push({
        name: srv.name,
        sourceLabel: srv.sourceLabel,
        sourcePath: srv.sourcePath,
        precedence: srv.precedence,
        command: srv.entry.command,
        args: srv.entry.args ?? [],
        commandDna: dna,
        health,
        healthDetail,
        latencyMs,
      });
    }

    // ------------------------------------------------------------------
    // Phase 5 — Build report
    // ------------------------------------------------------------------
    const llmSummary = buildLlmSummary(envStatus, sources, serverEntries);

    const report: EnvironmentHealthReport = {
      status: "success",
      generatedAt: new Date().toISOString(),
      environment: {
        status: envStatus,
        checks: diagResults.map((r) => ({
          name: r.name,
          status: r.status,
          message: r.message ?? "",
        })),
      },
      configs: {
        found: sources.length,
        sources: sources.map((s) => ({
          label: s.label,
          path: s.path,
          serverCount: Object.keys(s.servers).length,
          parseError: s.parseError,
        })),
      },
      servers: {
        total: serverEntries.length,
        healthy: serverEntries.filter((e) => e.health === "HEALTHY").length,
        misconfigured: serverEntries.filter((e) => e.health === "MISCONFIGURED")
          .length,
        ghost: serverEntries.filter((e) => e.health === "GHOST").length,
        zombie: serverEntries.filter((e) => e.health === "ZOMBIE").length,
        entries: serverEntries,
      },
      llm_summary: llmSummary,
    };

    logger.info("selfAudit v2.1 complete", {
      metadata: {
        envStatus,
        totalServers: serverEntries.length,
        healthy: report.servers.healthy,
        misconfigured: report.servers.misconfigured,
      },
    });

    return {
      content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
    };
  } catch (error) {
    logger.error("selfAudit failed", error as Error);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              status: "error",
              error: (error as Error).message,
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }
}
