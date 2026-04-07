/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { StringDecoder } from "string_decoder";
import { parse as parseShellCommand } from "shell-quote";
import { t, getUserAgent } from "@mcp-verify/shared";
import type { ISandbox } from "./sandbox/sandbox.interface";
import type {
  JsonValue,
  JsonRpcRequest,
  JsonRpcNotification,
} from "./shared/common.types";

interface SseMessageEvent {
  data: string;
}

export interface TransportOptions {
  timeoutMs?: number;
}

export interface ITransport {
  connect(): Promise<void>;
  send(
    message: JsonRpcRequest | JsonRpcNotification,
    options?: TransportOptions,
  ): Promise<JsonValue>;
  close(): void;
}

export class HttpTransport implements ITransport {
  private url: string;
  private defaultTimeout: number;
  private userAgent: string;
  private customHeaders: Record<string, string>;

  private constructor(
    url: string,
    defaultTimeout = 30000,
    headers: Record<string, string> = {},
  ) {
    this.url = url;
    this.defaultTimeout = defaultTimeout;
    this.customHeaders = headers;
    // Use shared User-Agent for consistent identification across all HTTP requests
    this.userAgent = getUserAgent();
  }

  /**
   * Factory method to create HttpTransport instances.
   * This is the only way to instantiate HttpTransport from outside the class.
   *
   * @param url - The HTTP/HTTPS URL of the MCP server
   * @param defaultTimeout - Default timeout in milliseconds (default: 30000)
   * @param headers - Custom HTTP headers to include in requests
   * @returns A new HttpTransport instance
   */
  public static create(
    url: string,
    defaultTimeout = 30000,
    headers: Record<string, string> = {},
  ): HttpTransport {
    return new HttpTransport(url, defaultTimeout, headers);
  }

  async connect(): Promise<void> {
    return Promise.resolve();
  }

  async send(
    message: JsonRpcRequest | JsonRpcNotification,
    options?: TransportOptions,
  ): Promise<JsonValue> {
    const timeout = options?.timeoutMs ?? this.defaultTimeout;

    // AbortController handles both manual cancellation and timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    let response: Response;

    try {
      response = await fetch(this.url, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          "User-Agent": this.userAgent,
          ...this.customHeaders,
        },
        body: JSON.stringify(message),
      });
    } catch (err) {
      // Distinguish timeout from other network failures for clearer error messages
      if ((err as Error).name === "AbortError") {
        throw new Error(
          `MCP request timed out after ${timeout}ms (method: "${message.method}")`,
        );
      }
      // Re-wrap low-level fetch/network errors with context
      throw new Error(
        `MCP network error for method "${message.method}": ${(err as Error).message}`,
      );
    } finally {
      // Always clear the timer, whether the request succeeded or failed
      clearTimeout(timeoutId);
    }

    // --- HTTP-level error handling ---
    if (!response.ok) {
      // Attempt to read the body for a more descriptive error message
      const body = await response.text().catch(() => "(unreadable body)");
      throw new Error(
        `MCP server returned HTTP ${response.status} ${response.statusText} ` +
          `for method "${message.method}". Body: ${body}`,
      );
    }

    // --- Parse JSON response ---
    let data: JsonValue;
    try {
      data = (await response.json()) as JsonValue;
    } catch {
      throw new Error(
        `MCP server returned a non-JSON response for method "${message.method}"`,
      );
    }

    // --- JSON-RPC 2.0 application-level error handling ---
    if (
      data !== null &&
      typeof data === "object" &&
      !Array.isArray(data) &&
      "error" in data
    ) {
      const rpcError = (data as Record<string, unknown>).error;

      if (rpcError !== null && typeof rpcError === "object") {
        const {
          code,
          message: msg,
          data: errData,
        } = rpcError as {
          code?: number;
          message?: string;
          data?: unknown;
        };

        const detail =
          errData !== undefined ? ` | data: ${JSON.stringify(errData)}` : "";
        throw new Error(
          `JSON-RPC error ${code ?? "unknown"}: ${msg ?? "No message provided"}${detail}`,
        );
      }
    }

    // Return the result property for success cases
    if (
      data !== null &&
      typeof data === "object" &&
      !Array.isArray(data) &&
      "result" in data
    ) {
      return (data as Record<string, unknown>).result as JsonValue;
    }

    return data;
  }

  close(): void {
    // No persistent connection to close in this implementation
  }
}

/**
 * Safely parse a command string into command and arguments using shell-quote.
 * This prevents command injection vulnerabilities by properly handling shell metacharacters.
 *
 * SECURITY NOTE: This function now uses the battle-tested shell-quote library
 * instead of custom regex parsing to prevent command injection attacks.
 *
 * @param commandString - Full command string (e.g., "node server.js --port 3000")
 * @returns Tuple of [command, args[]]
 * @throws Error if command string is invalid or contains shell operators
 */
function parseCommandString(commandString: string): [string, string[]] {
  const trimmed = commandString.trim();

  if (!trimmed) {
    throw new Error(t("error_command_empty"));
  }

  // Use shell-quote to safely parse the command string
  // This handles quotes, escapes, and prevents injection attacks
  const parsed = parseShellCommand(trimmed);

  // Filter out any shell operators (objects) which indicate dangerous constructs
  // shell-quote returns objects for operators like |, &&, ||, ;, etc.
  const stringParts = parsed.filter(
    (part: string | object): part is string => typeof part === "string",
  );

  // If we filtered out any operators, the command is potentially dangerous
  if (stringParts.length !== parsed.length) {
    throw new Error(
      "Command string contains shell operators (|, &&, ||, ;, etc.) which are not allowed. " +
        "Use separate command and args instead: new StdioTransport(command, [args])",
    );
  }

  if (stringParts.length === 0) {
    throw new Error("No command found in command string");
  }

  const command = stringParts[0];
  const args = stringParts.slice(1);

  return [command, args];
}

export class StdioTransport implements ITransport {
  private static readonly MAX_BUFFER_SIZE = 10 * 1024 * 1024; // 10MB hard limit to prevent JSON bomb DoS

  private command: string;
  private args: string[];
  private process: ChildProcess | null = null;
  private buffer: string = "";
  private decoder: StringDecoder;
  private pendingRequests: Map<
    number | string,
    { resolve: Function; reject: Function; timer: NodeJS.Timeout }
  > = new Map();
  private defaultTimeout: number;
  private env: NodeJS.ProcessEnv | undefined;
  private sandbox?: ISandbox;
  private stderrBuffer: string[] = [];
  private static readonly MAX_STDERR_LINES = 10;

  private constructor(
    command: string,
    args: string[] = [],
    defaultTimeout = 30000,
    env?: NodeJS.ProcessEnv,
    sandbox?: ISandbox,
  ) {
    // Validate inputs
    if (!command || typeof command !== "string") {
      throw new Error("Command must be a non-empty string");
    }

    if (!Array.isArray(args)) {
      throw new Error("Args must be an array");
    }

    // Support both patterns:
    // 1. New (recommended): new StdioTransport('node', ['server.js', '--port', '3000'])
    // 2. Legacy (deprecated): new StdioTransport('node server.js --port 3000')
    if (args.length === 0 && command.includes(" ")) {
      // Legacy format: Parse command string
      // Emit deprecation warning in dev mode
      if (process.env.NODE_ENV !== "production") {
        console.warn(
          "[DEPRECATION WARNING] Passing a single command string to StdioTransport is deprecated. " +
            "Use separate command and args instead: new StdioTransport(command, [args])",
        );
      }

      try {
        const [parsedCommand, parsedArgs] = parseCommandString(command);
        this.command = parsedCommand;
        this.args = parsedArgs;
      } catch (error) {
        throw new Error(
          `Failed to parse command string: ${(error as Error).message}`,
        );
      }
    } else {
      // New format: Use provided command and args
      this.command = command;
      this.args = args;
    }

    this.defaultTimeout = defaultTimeout;
    this.env = env;
    this.sandbox = sandbox;
    this.decoder = new StringDecoder("utf8");

    // Windows Compatibility: npm and npx are batch files (.cmd) on Windows
    // spawn() without shell:true requires the full extension
    if (process.platform === "win32") {
      if (this.command === "npm" || this.command === "npx") {
        this.command = `${this.command}.cmd`;
      }
    }
  }

  /**
   * Factory method to create StdioTransport instances.
   * This is the only way to instantiate StdioTransport from outside the class.
   *
   * @param command - Command to execute (e.g., 'node', 'npx')
   * @param args - Command arguments (e.g., ['server.js', '--port', '3000'])
   * @param defaultTimeout - Default timeout in milliseconds (default: 30000)
   * @param env - Environment variables to pass to the spawned process
   * @param sandbox - Optional sandbox to wrap the command execution
   * @returns A new StdioTransport instance
   */
  public static create(
    command: string,
    args: string[] = [],
    defaultTimeout = 30000,
    env?: NodeJS.ProcessEnv,
    sandbox?: ISandbox,
  ): StdioTransport {
    return new StdioTransport(command, args, defaultTimeout, env, sandbox);
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        let spawnCmd = this.command;
        let spawnArgs = this.args;

        if (this.sandbox) {
          [spawnCmd, spawnArgs] = this.sandbox.wrap(this.command, this.args);
        }

        this.process = spawn(spawnCmd, spawnArgs, {
          stdio: ["pipe", "pipe", "pipe"],
          env: { ...process.env, ...this.env },
          shell: process.platform === "win32", // Windows needs shell to resolve .cmd scripts
        });

        // Capture stderr to help debug startup issues (e.g. missing modules, syntax errors)
        this.process.stderr?.on("data", (data) => {
          const lines = data.toString().split("\n");

          // Noise patterns to filter out from user console (but keep in internal buffer)
          const noisePatterns = [
            /\[MODULE_TYPELESS_PACKAGE_JSON\]/,
            /Warning: Module type of file/,
            /Reparsing as ES module because module syntax was detected/,
            /To eliminate this warning, add "type": "module"/,
            /Use `node --trace-warnings ...` to show where the warning was created/,
          ];

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed) {
              this.stderrBuffer.push(trimmed);

              // Only passthrough to real stderr if it's NOT a noise pattern
              const isNoise = noisePatterns.some((p) => p.test(trimmed));
              if (!isNoise) {
                process.stderr.write(line + "\n");
              }
            }
          }
          // Keep buffer size manageable
          if (this.stderrBuffer.length > StdioTransport.MAX_STDERR_LINES) {
            this.stderrBuffer = this.stderrBuffer.slice(
              -StdioTransport.MAX_STDERR_LINES,
            );
          }
        });

        this.process.stdout?.on("data", (data) => this.handleData(data));

        this.process.on("error", (err) => {
          reject(
            new Error(
              t("error_process_spawn").replace("{message}", err.message),
            ),
          );
        });

        this.process.on("spawn", () => {
          resolve();
        });

        this.process.on("exit", (code) => {
          // Reject all pending requests if process dies
          Array.from(this.pendingRequests.entries()).forEach(([id, req]) => {
            clearTimeout(req.timer);
            let errorMsg = t("error_process_exit").replace(
              "{code}",
              String(code),
            );
            if (this.stderrBuffer.length > 0) {
              errorMsg += `\n${t("latest_stderr_output")}\n${this.stderrBuffer.join("\n")}`;
            }
            req.reject(new Error(errorMsg));
          });
          this.pendingRequests.clear();
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  private handleData(data: Buffer) {
    // Use StringDecoder to handle multibyte characters that may be split across chunks
    // This prevents UTF-8 corruption when emojis or accented characters fall on chunk boundaries
    const chunk = this.decoder.write(data);

    // JSON Bomb Protection: Enforce hard limit on buffer size

    // JSON Bomb Protection: Enforce hard limit on buffer size
    // This prevents DoS attacks where a malicious server sends 1GB+ payloads
    const attemptedSize = this.buffer.length + chunk.length;
    if (attemptedSize > StdioTransport.MAX_BUFFER_SIZE) {
      // Kill the connection immediately
      if (this.process) {
        this.process.kill("SIGTERM");
      }

      // Reject all pending requests
      for (const [id, req] of this.pendingRequests.entries()) {
        clearTimeout(req.timer);
        req.reject(
          new Error(
            `Transport buffer limit exceeded (attempted: ${attemptedSize} bytes, ` +
              `limit: ${StdioTransport.MAX_BUFFER_SIZE} bytes). ` +
              "Possible JSON bomb attack detected. Connection terminated.",
          ),
        );
      }
      this.pendingRequests.clear();
      return;
    }

    this.buffer += chunk;

    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const response = JSON.parse(line);
        if (response.id && this.pendingRequests.has(response.id)) {
          const req = this.pendingRequests.get(response.id)!;
          clearTimeout(req.timer); // STOP THE TIMER

          if (response.error) {
            req.reject(new Error(response.error.message));
          } else {
            req.resolve(response.result);
          }
          this.pendingRequests.delete(response.id);
        }
      } catch (e) {
        // Ignore parse errors for partial lines (robustness)
      }
    }
  }

  async send(
    message: JsonRpcRequest | JsonRpcNotification,
    options?: TransportOptions,
  ): Promise<JsonValue> {
    if (!this.process) throw new Error(t("error_process_not_started"));

    // Handle Notifications (Fire and Forget)
    // If no ID is provided, we send the data and resolve immediately
    // as per JSON-RPC 2.0 Notification spec.
    if (message.id === undefined || message.id === null) {
      const jsonLine = JSON.stringify(message) + "\n";
      try {
        this.process?.stdin?.write(jsonLine);
        return null;
      } catch (e) {
        throw new Error((e as Error).message);
      }
    }

    const timeoutMs = options?.timeoutMs || this.defaultTimeout;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pendingRequests.has(message.id!)) {
          this.pendingRequests.delete(message.id!);
          let errorMsg = t("request_timeout", { ms: String(timeoutMs) });
          if (this.stderrBuffer.length > 0) {
            errorMsg += `\n${t("latest_stderr_output")}\n${this.stderrBuffer.join("\n")}`;
          }
          reject(new Error(errorMsg));
        }
      }, timeoutMs);

      this.pendingRequests.set(message.id!, { resolve, reject, timer });

      const jsonLine = JSON.stringify(message) + "\n";
      try {
        this.process?.stdin?.write(jsonLine);
      } catch (e) {
        clearTimeout(timer);
        this.pendingRequests.delete(message.id!);

        let errorMsg = (e as Error).message;
        if (this.stderrBuffer.length > 0) {
          errorMsg += `\n${t("latest_stderr_output")}\n${this.stderrBuffer.join("\n")}`;
        }
        reject(new Error(errorMsg));
      }
    });
  }

  close(): void {
    // Flush any remaining bytes in the decoder
    const remaining = this.decoder.end();
    if (remaining) {
      this.buffer += remaining;
      // Process any final complete lines
      const lines = this.buffer.split("\n");
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const response = JSON.parse(line);
          if (response.id && this.pendingRequests.has(response.id)) {
            const req = this.pendingRequests.get(response.id)!;
            clearTimeout(req.timer);
            if (response.error) {
              req.reject(new Error(response.error.message));
            } else {
              req.resolve(response.result);
            }
            this.pendingRequests.delete(response.id);
          }
        } catch (e) {
          // Ignore parse errors
        }
      }
    }

    if (this.process) {
      this.process.kill();
    }
  }
}
