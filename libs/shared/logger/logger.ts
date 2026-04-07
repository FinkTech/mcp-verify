/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

export class Logger {
  private static instance: Logger;
  private level: LogLevel = LogLevel.INFO;

  private constructor() {}

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  setLevel(level: LogLevel) {
    this.level = level;
  }

  /**
   * Sanitize ANSI escape sequences to prevent Log Spoofing attacks
   * Removes control sequences like \x1b[31m (colors), \x1b[2J (clear screen), etc.
   * This prevents malicious MCP servers from injecting terminal control codes
   */
  private sanitizeAnsi(text: string): string {
    // Remove ANSI escape sequences: \x1b[...m, \x1b[...J, etc.
    return text.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
  }

  debug(message: string, context?: unknown) {
    if (this.level <= LogLevel.DEBUG) {
      const sanitizedMsg = this.sanitizeAnsi(message);
      const msg = context
        ? `[DEBUG] ${sanitizedMsg} ${JSON.stringify(context)}`
        : `[DEBUG] ${sanitizedMsg}`;
      process.stderr.write(msg + "\n");
    }
  }

  info(message: string, context?: unknown) {
    if (this.level <= LogLevel.INFO) {
      const sanitizedMsg = this.sanitizeAnsi(message);
      const msg = context
        ? `[INFO] ${sanitizedMsg} ${JSON.stringify(context)}`
        : `[INFO] ${sanitizedMsg}`;
      process.stderr.write(msg + "\n");
    }
  }

  warn(message: string) {
    if (this.level <= LogLevel.WARN) {
      const sanitizedMsg = this.sanitizeAnsi(message);
      process.stderr.write(`[WARN] ${sanitizedMsg}\n`);
    }
  }

  error(message: string, error?: Error | unknown) {
    if (this.level <= LogLevel.ERROR) {
      const sanitizedMsg = this.sanitizeAnsi(message);
      const errorStr = error ? this.sanitizeAnsi(String(error)) : "";
      const msg = errorStr
        ? `[ERROR] ${sanitizedMsg} ${errorStr}`
        : `[ERROR] ${sanitizedMsg}`;
      process.stderr.write(msg + "\n");
    }
  }
}

export const logger = Logger.getInstance();
