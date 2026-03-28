/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Enterprise Logging System
 *
 * Implements structured logging with:
 * - Multiple log levels (debug, info, warn, error, critical)
 * - Audit trail for security events
 * - PII redaction
 * - Correlation IDs for distributed tracing
 * - JSON structured output
 * - Performance metrics
 * - Ultra-Visual console formatting (Vite/Turborepo inspired)
 * - File logging with rotation (size-based + count-based)
 * - Compliance with enterprise standards
 *
 * Standards compliance:
 * - OWASP Logging Cheat Sheet
 * - CIS Benchmark for logging
 * - SOC 2 Type II requirements
 * - ISO 27001:2013
 *
 * @module libs/core/infrastructure/logging
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Chalk lazy-loader type shim
// We type only the subset of chalk we actually use so we can avoid importing
// the full type package while still being 100% `any`-free.
// ---------------------------------------------------------------------------
interface ChalkInstance {
  gray: ChalkFn;
  cyan: ChalkFn;
  blue: ChalkFn;
  yellow: ChalkFn;
  red: ChalkFn;
  magenta: ChalkFn;
  white: ChalkFn;
  dim: ChalkFn;
  bold: ChalkFn;
  bgCyan: ChalkFn;
  bgYellow: ChalkFn;
  bgRed: ChalkFn;
  bgMagenta: ChalkFn;
  bgBlue: ChalkFn;
  bgGray: ChalkFn;
  black: ChalkFn;
  green: ChalkFn;
}

type ChalkFn = ((text: string) => string) & ChalkInstance;

/** Lazy-load chalk to avoid circular-dependency issues in the infra layer. */
function getChalk(): ChalkInstance {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const c = require('chalk');
  // Handle ESM default export when bundled as CJS
  return (c.default || c) as ChalkInstance;
}

// ---------------------------------------------------------------------------
// Enums & Interfaces
// ---------------------------------------------------------------------------

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  CRITICAL = 4,
}

export enum AuditEventType {
  VALIDATION_STARTED = 'validation.started',
  VALIDATION_COMPLETED = 'validation.completed',
  VALIDATION_FAILED = 'validation.failed',
  SECURITY_FINDING = 'security.finding',
  SECURITY_CRITICAL = 'security.critical',
  GUARDRAIL_BLOCKED = 'guardrail.blocked',
  GUARDRAIL_MODIFIED = 'guardrail.modified',
  FUZZING_STARTED = 'fuzzing.started',
  FUZZING_COMPLETED = 'fuzzing.completed',
  VULNERABILITY_DETECTED = 'vulnerability.detected',
  PROXY_STARTED = 'proxy.started',
  PROXY_STOPPED = 'proxy.stopped',
  RATE_LIMIT_EXCEEDED = 'rate_limit.exceeded',
  PII_REDACTED = 'pii.redacted',
  CONFIG_CHANGED = 'config.changed',
  ERROR_OCCURRED = 'error.occurred',
}

export interface LogContext {
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  toolName?: string;
  component?: string;
  operation?: string;
  duration?: number;
  metadata?: Record<string, unknown>;
  // Allow additional properties for flexibility
  [key: string]: unknown;
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context: LogContext;
  error?: {
    name: string;
    message: string;
    stack?: string;
    code?: string;
  };
}

export interface AuditEntry {
  timestamp: string;
  eventType: AuditEventType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  actor?: string;
  resource?: string;
  action: string;
  result: 'success' | 'failure' | 'blocked';
  context: LogContext;
  details?: Record<string, unknown>;
}

export interface LoggerConfig {
  minLevel: LogLevel;
  enableConsole: boolean;
  enableFile: boolean;
  enableAudit: boolean;
  redactPII: boolean;
  includeStackTrace: boolean;
  prettyPrint: boolean;
  maxMessageLength: number;
  fileDirectory: string;
  maxFileSize: number;
  maxFiles: number;
  colorize: boolean;
  includeTimestamps: boolean;
}

// ---------------------------------------------------------------------------
// Visual formatting helpers
// ---------------------------------------------------------------------------

/**
 * Maps each log level to its display icon and chalk colorizer.
 *
 * Layout:  <icon>  <LEVEL-BADGE>
 * Example: ⚠  WARN
 */
const LEVEL_META: Record<
  LogLevel,
  { icon: string; badge: (t: string) => string; label: string }
> = {
  [LogLevel.DEBUG]: {
    icon: '⚙',
    label: 'DEBUG',
    badge: (t: string) => {
      const c = getChalk();
      return c.bgGray(c.white(` ${t} `));
    },
  },
  [LogLevel.INFO]: {
    icon: 'ℹ',
    label: 'INFO ',
    badge: (t: string) => {
      const c = getChalk();
      return c.bgBlue(c.white(` ${t} `));
    },
  },
  [LogLevel.WARN]: {
    icon: '⚠',
    label: 'WARN ',
    badge: (t: string) => {
      const c = getChalk();
      return c.bgYellow(c.black(` ${t} `));
    },
  },
  [LogLevel.ERROR]: {
    icon: '✖',
    label: 'ERROR',
    badge: (t: string) => {
      const c = getChalk();
      return c.bgRed(c.white(` ${t} `));
    },
  },
  [LogLevel.CRITICAL]: {
    icon: '🛡',
    label: 'CRIT ',
    badge: (t: string) => {
      const c = getChalk();
      return c.bgMagenta(c.white(` ${t} `));
    },
  },
};

/**
 * Renders a component name as a colorized block tag.
 * e.g.  ▐ ConfigManager ▌  in cyan-on-black
 */
function renderComponentTag(component: string): string {
  const c = getChalk();
  return c.bgCyan(c.black(` ${component} `));
}

/**
 * Renders an operation name with a leading arrow.
 * e.g.  ► testHandshake
 */
function renderOperation(operation: string): string {
  const c = getChalk();
  return `${c.cyan('►')} ${c.cyan(operation)}`;
}

/**
 * Renders the AUDIT badge shown before audit messages.
 * e.g.  ⚡ AUDIT
 */
function renderAuditBadge(): string {
  const c = getChalk();
  return c.bgYellow(c.black(' ⚡ AUDIT '));
}

/**
 * Renders the duration suffix when present.
 * e.g.  +142ms
 */
function renderDuration(ms: number): string {
  const c = getChalk();
  return c.dim(`+${ms}ms`);
}

/**
 * Renders an error detail block on a new indented line.
 *
 *   └─ TypeError: Cannot read properties of undefined
 *      at Object.<anonymous> (/path/to/file.ts:12:5)
 */
function renderErrorBlock(
  error: NonNullable<LogEntry['error']>,
  includeStack: boolean
): string {
  const c = getChalk();
  const prefix = c.red('  └─ ');
  const name = c.red(c.bold(error.name));
  const msg = c.red(error.message);
  const codeSuffix = error.code != null ? c.dim(` [${error.code}]`) : '';
  let block = `\n${prefix}${name}: ${msg}${codeSuffix}`;

  if (includeStack && error.stack != null) {
    const stackLines = error.stack
      .split('\n')
      .slice(1) // skip the first line (already captured in message)
      .map((l) => `     ${c.dim(l.trim())}`)
      .join('\n');
    if (stackLines.length > 0) {
      block += `\n${stackLines}`;
    }
  }

  return block;
}

// ---------------------------------------------------------------------------
// Logger class
// ---------------------------------------------------------------------------

export class Logger {
  private static instance: Logger;
  private config: LoggerConfig;
  private auditLog: AuditEntry[] = [];
  private logBuffer: LogEntry[] = [];
  private currentLogFile: string | null = null;
  private currentLogSize = 0;

  /** PII patterns for redaction */
  private piiPatterns: ReadonlyArray<{
    pattern: RegExp;
    replacement: string;
    name: string;
  }> = [
    {
      pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
      replacement: '***-**-****',
      name: 'SSN',
    },
    {
      pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      replacement: '****-****-****-****',
      name: 'Credit Card',
    },
    {
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      replacement: '***@***.***',
      name: 'Email',
    },
    {
      pattern:
        /\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b/g,
      replacement: '***-***-****',
      name: 'Phone',
    },
    {
      pattern: /\b(?:Bearer|Token|API[_-]?Key)\s+[A-Za-z0-9_\-.]+/gi,
      replacement: 'Bearer ***REDACTED***',
      name: 'API Token',
    },
  ];

  private constructor(config?: Partial<LoggerConfig>) {
    this.config = {
      minLevel: LogLevel.INFO,
      enableConsole: false,
      enableFile: false,
      enableAudit: true,
      redactPII: true,
      includeStackTrace: false,
      prettyPrint: false,
      maxMessageLength: 5000,
      fileDirectory: '.mcp-verify/logs',
      maxFileSize: 10485760, // 10 MB
      maxFiles: 5,
      colorize: true,
      includeTimestamps: true,
      ...config,
    };

    // Initialize log directory if file logging is enabled
    if (this.config.enableFile) {
      this.initializeLogDirectory();
    }
  }

  // -------------------------------------------------------------------------
  // Singleton
  // -------------------------------------------------------------------------

  static getInstance(config?: Partial<LoggerConfig>): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger(config);
    }
    return Logger.instance;
  }

  configure(config: Partial<LoggerConfig>): void {
    const wasFileLoggingEnabled = this.config.enableFile;
    const oldDirectory = this.config.fileDirectory;

    Object.assign(this.config, config);

    // Re-initialize log directory if enableFile changed or directory changed
    if (this.config.enableFile) {
      if (!wasFileLoggingEnabled || oldDirectory !== this.config.fileDirectory) {
        this.initializeLogDirectory();
      }
    }
  }

  // -------------------------------------------------------------------------
  // Public logging API
  // -------------------------------------------------------------------------

  debug(message: string, context?: LogContext): void {
    this.log(LogLevel.DEBUG, message, context);
  }

  info(message: string, context?: LogContext): void {
    this.log(LogLevel.INFO, message, context);
  }

  warn(message: string, context?: LogContext): void {
    this.log(LogLevel.WARN, message, context);
  }

  error(message: string, error?: Error, context?: LogContext): void {
    const errorContext: LogContext = {
      ...context,
      metadata: {
        ...context?.metadata,
        errorName: error?.name,
        errorMessage: error?.message,
      },
    };

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: LogLevel.ERROR,
      message: this.sanitizeMessage(message),
      context: errorContext,
      error: error
        ? {
            name: error.name,
            message: error.message,
            stack: this.config.includeStackTrace ? error.stack : undefined,
            code: (error as NodeJS.ErrnoException).code,
          }
        : undefined,
    };

    this.writeLog(entry);
  }

  critical(message: string, context?: LogContext): void {
    this.log(LogLevel.CRITICAL, message, context);

    this.audit({
      eventType: AuditEventType.SECURITY_CRITICAL,
      severity: 'critical',
      action: 'critical_event',
      result: 'success',
      context: context ?? {},
      details: { message },
    });
  }

  // -------------------------------------------------------------------------
  // Audit logging
  // -------------------------------------------------------------------------

  audit(entry: Omit<AuditEntry, 'timestamp'>): void {
    if (!this.config.enableAudit) return;

    const auditEntry: AuditEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
    };

    this.auditLog.push(auditEntry);

    const logLevel = this.severityToLogLevel(entry.severity);
    this.log(logLevel, `[AUDIT] ${entry.eventType}: ${entry.action}`, {
      ...entry.context,
      metadata: {
        ...entry.context.metadata,
        eventType: entry.eventType,
        severity: entry.severity,
        result: entry.result,
      },
    });

    if (this.auditLog.length > 10_000) {
      this.auditLog = this.auditLog.slice(-5000);
    }
  }

  // -------------------------------------------------------------------------
  // Internal write pipeline
  // -------------------------------------------------------------------------

  private log(level: LogLevel, message: string, context?: LogContext): void {
    if (level < this.config.minLevel) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message: this.sanitizeMessage(message),
      context: context ?? {},
    };

    this.writeLog(entry);
  }

  private writeLog(entry: LogEntry): void {
    this.logBuffer.push(entry);

    if (this.logBuffer.length > 1000) {
      this.logBuffer = this.logBuffer.slice(-500);
    }

    if (this.config.enableConsole) {
      this.writeToConsole(entry);
    }

    if (this.config.enableFile) {
      this.writeToFile(entry);
    }
  }

  private writeToConsole(entry: LogEntry): void {
    const isTTY = process.stderr.isTTY === true;

    const output =
      this.config.prettyPrint || isTTY
        ? this.formatOneLine(entry)
        : JSON.stringify(entry);

    // SECURITY & CI/CD: Write to stderr to keep stdout clean for data output
    process.stderr.write(output + '\n');
  }

  // -------------------------------------------------------------------------
  // File logging with rotation
  // -------------------------------------------------------------------------

  /**
   * Initialize the log directory structure.
   * Creates the directory if it doesn't exist.
   */
  private initializeLogDirectory(): void {
    try {
      if (!fs.existsSync(this.config.fileDirectory)) {
        fs.mkdirSync(this.config.fileDirectory, { recursive: true });
      }
    } catch (error) {
      // Fall back to console-only if directory creation fails
      this.config.enableFile = false;
      console.error(`Failed to create log directory: ${error}`);
    }
  }

  /**
   * Get the current log file path.
   * Format: mcp-verify-YYYY-MM-DD.log
   */
  private getCurrentLogFilePath(): string {
    const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    return path.join(this.config.fileDirectory, `mcp-verify-${date}.log`);
  }

  /**
   * Rotate log files when maxFileSize is exceeded.
   * Renames current file to .1, .2, .3, etc., and deletes oldest if maxFiles exceeded.
   */
  private rotateLogFiles(currentFile: string): void {
    try {
      // Get all rotated versions of this file
      const baseName = path.basename(currentFile, '.log');
      const dirName = path.dirname(currentFile);

      // Move existing rotated files: file.3 -> file.4, file.2 -> file.3, etc.
      for (let i = this.config.maxFiles - 1; i >= 1; i--) {
        const oldPath = path.join(dirName, `${baseName}.${i}.log`);
        const newPath = path.join(dirName, `${baseName}.${i + 1}.log`);

        if (fs.existsSync(oldPath)) {
          if (i === this.config.maxFiles - 1) {
            // Delete the oldest file
            fs.unlinkSync(oldPath);
          } else {
            // Rename to next number
            fs.renameSync(oldPath, newPath);
          }
        }
      }

      // Rename current file to .1
      const rotatedPath = path.join(dirName, `${baseName}.1.log`);
      if (fs.existsSync(currentFile)) {
        fs.renameSync(currentFile, rotatedPath);
      }

      // Reset current file size
      this.currentLogSize = 0;
      this.currentLogFile = currentFile;
    } catch (error) {
      // If rotation fails, continue writing (may exceed size limit)
      console.error(`Failed to rotate log files: ${error}`);
    }
  }

  /**
   * Write log entry to file with automatic rotation.
   * - Creates new file per day (YYYY-MM-DD format)
   * - Rotates when file exceeds maxFileSize
   * - Keeps up to maxFiles rotated versions
   * - Writes in JSON Lines format (one JSON object per line)
   */
  private writeToFile(entry: LogEntry): void {
    if (!this.config.enableFile) {
      return;
    }

    try {
      const logFilePath = this.getCurrentLogFilePath();

      // Check if log file has changed (new day)
      if (this.currentLogFile !== logFilePath) {
        this.currentLogFile = logFilePath;
        // Check current file size
        if (fs.existsSync(logFilePath)) {
          const stats = fs.statSync(logFilePath);
          this.currentLogSize = stats.size;
        } else {
          this.currentLogSize = 0;
        }
      }

      // Check if rotation is needed
      if (this.currentLogSize >= this.config.maxFileSize) {
        this.rotateLogFiles(logFilePath);
      }

      // Format entry as JSON Line (JSONL format)
      const jsonLine = JSON.stringify(entry) + '\n';

      // Append to file atomically
      fs.appendFileSync(logFilePath, jsonLine, 'utf8');

      // Update current size
      this.currentLogSize += Buffer.byteLength(jsonLine, 'utf8');
    } catch (error) {
      // If file write fails, fall back to console only
      console.error(`Failed to write to log file: ${error}`);
    }
  }

  // -------------------------------------------------------------------------
  // ✨ Ultra-Visual formatter
  // -------------------------------------------------------------------------

  /**
   * Format a log entry as a single, richly coloured terminal line.
   *
   * Anatomy of a normal line:
   *   12:34:56  ℹ  INFO   ▐ MCPValidator ▌  ► parseResponse  Validation passed  +48ms
   *
   * Anatomy of an audit line:
   *   12:34:56  ⚡ AUDIT   ℹ  INFO   ▐ MCPValidator ▌  validation.completed: validate
   *
   * Error lines append a second indented branch:
   *   12:34:56  ✖  ERROR  ▐ ProxyServer ▌  Connection failed
   *     └─ TypeError: Cannot read properties of undefined
   */
  private formatOneLine(entry: LogEntry): string {
    const c = getChalk();

    // ------------------------------------------------------------------
    // 1. Timestamp  (soft gray)
    // ------------------------------------------------------------------
    const timestamp = c.gray(
      new Date(entry.timestamp).toLocaleTimeString('en-US', { hour12: false })
    );

    // ------------------------------------------------------------------
    // 2. Level badge  (icon + coloured background badge)
    // ------------------------------------------------------------------
    const meta = LEVEL_META[entry.level] ?? LEVEL_META[LogLevel.INFO];
    const levelIcon = this.colorizeIcon(entry.level, meta.icon);
    const levelBadge = meta.badge(meta.label);

    // ------------------------------------------------------------------
    // 3. Component tag  (coloured block, optional)
    // ------------------------------------------------------------------
    const componentTag =
      typeof entry.context.component === 'string' &&
      entry.context.component.length > 0
        ? ` ${renderComponentTag(entry.context.component)}`
        : '';

    // ------------------------------------------------------------------
    // 4. Operation  (arrow + cyan text, optional)
    // ------------------------------------------------------------------
    const operationStr =
      typeof entry.context.operation === 'string' &&
      entry.context.operation.length > 0
        ? `  ${renderOperation(entry.context.operation)}`
        : '';

    // ------------------------------------------------------------------
    // 5. AUDIT badge  (prepended when message starts with [AUDIT])
    // ------------------------------------------------------------------
    const isAudit = entry.message.startsWith('[AUDIT]');
    const auditBadge = isAudit ? ` ${renderAuditBadge()}` : '';

    // ------------------------------------------------------------------
    // 6. Message text  (colorized based on level, audit prefix stripped)
    // ------------------------------------------------------------------
    const rawMessage = isAudit
      ? entry.message.replace(/^\[AUDIT\]\s*/, '')
      : entry.message;

    const messageText = this.colorizeMessage(entry.level, rawMessage);

    // ------------------------------------------------------------------
    // 7. Duration suffix  (dim, optional)
    // ------------------------------------------------------------------
    const durationStr =
      typeof entry.context.duration === 'number'
        ? `  ${renderDuration(entry.context.duration)}`
        : '';

    // ------------------------------------------------------------------
    // 8. Error block  (indented branch, optional)
    // ------------------------------------------------------------------
    const errorBlock =
      entry.error != null
        ? renderErrorBlock(entry.error, this.config.includeStackTrace)
        : '';

    // ------------------------------------------------------------------
    // Assemble
    // ------------------------------------------------------------------
    return (
      `${timestamp}  ${levelIcon}  ${levelBadge}` +
      `${componentTag}` +
      `${operationStr}` +
      `${auditBadge}` +
      `  ${messageText}` +
      `${durationStr}` +
      `${errorBlock}`
    );
  }

  /**
   * Returns the icon wrapped in the appropriate level colour.
   */
  private colorizeIcon(level: LogLevel, icon: string): string {
    const c = getChalk();
    switch (level) {
      case LogLevel.DEBUG:    return c.gray(icon);
      case LogLevel.INFO:     return c.blue(icon);
      case LogLevel.WARN:     return c.yellow(icon);
      case LogLevel.ERROR:    return c.red(icon);
      case LogLevel.CRITICAL: return c.magenta(icon);
      default:                return icon;
    }
  }

  /**
   * Returns the message body styled for the given level.
   */
  private colorizeMessage(level: LogLevel, message: string): string {
    const c = getChalk();
    switch (level) {
      case LogLevel.DEBUG:    return c.gray(message);
      case LogLevel.INFO:     return c.white(message);
      case LogLevel.WARN:     return c.yellow(message);
      case LogLevel.ERROR:    return c.red(c.bold(message));
      case LogLevel.CRITICAL: return c.magenta(c.bold(message));
      default:                return message;
    }
  }

  // -------------------------------------------------------------------------
  // Sanitization
  // -------------------------------------------------------------------------

  /**
   * Sanitize message: strip ANSI injection, redact PII, truncate.
   */
  private sanitizeMessage(message: string): string {
    let sanitized = message;

    // 1. SECURITY: Remove ANSI escape sequences → prevents Log Spoofing attacks.
    //    Malicious MCP servers could inject terminal control codes to manipulate logs.
    sanitized = sanitized.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');

    // 2. Redact PII patterns
    if (this.config.redactPII) {
      for (const pii of this.piiPatterns) {
        sanitized = sanitized.replace(pii.pattern, pii.replacement);
      }
    }

    // 3. Truncate
    if (sanitized.length > this.config.maxMessageLength) {
      sanitized =
        sanitized.substring(0, this.config.maxMessageLength) +
        '... [truncated]';
    }

    return sanitized;
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private severityToLogLevel(severity: string): LogLevel {
    switch (severity) {
      case 'critical': return LogLevel.CRITICAL;
      case 'high':     return LogLevel.ERROR;
      case 'medium':   return LogLevel.WARN;
      case 'low':      return LogLevel.INFO;
      default:         return LogLevel.INFO;
    }
  }

  // -------------------------------------------------------------------------
  // Query API
  // -------------------------------------------------------------------------

  getLogs(count?: number): LogEntry[] {
    return count != null
      ? this.logBuffer.slice(-count)
      : [...this.logBuffer];
  }

  getAuditTrail(count?: number): AuditEntry[] {
    return count != null
      ? this.auditLog.slice(-count)
      : [...this.auditLog];
  }

  getLogsByLevel(level: LogLevel, count?: number): LogEntry[] {
    const filtered = this.logBuffer.filter((e) => e.level >= level);
    return count != null ? filtered.slice(-count) : filtered;
  }

  getAuditByEventType(
    eventType: AuditEventType,
    count?: number
  ): AuditEntry[] {
    const filtered = this.auditLog.filter((e) => e.eventType === eventType);
    return count != null ? filtered.slice(-count) : filtered;
  }

  clearLogs(): void {
    this.logBuffer = [];
  }

  clearAudit(): void {
    this.auditLog = [];
  }

  exportLogs(): string {
    return JSON.stringify(
      { logs: this.logBuffer, audit: this.auditLog, exportedAt: new Date().toISOString() },
      null,
      2
    );
  }

  /**
   * Clean up old log files older than specified days.
   * Useful for manual cleanup or scheduled maintenance.
   *
   * @param olderThanDays - Remove log files older than this many days (default: 90)
   * @returns Number of files deleted
   */
  cleanupOldLogs(olderThanDays = 90): number {
    if (!this.config.enableFile) {
      return 0;
    }

    try {
      const now = Date.now();
      const cutoffTime = now - olderThanDays * 24 * 60 * 60 * 1000;
      let deletedCount = 0;

      // Read all files in log directory
      const files = fs.readdirSync(this.config.fileDirectory);

      for (const file of files) {
        if (!file.startsWith('mcp-verify-') || !file.endsWith('.log')) {
          continue;
        }

        const filePath = path.join(this.config.fileDirectory, file);
        const stats = fs.statSync(filePath);

        if (stats.mtimeMs < cutoffTime) {
          fs.unlinkSync(filePath);
          deletedCount++;
        }
      }

      return deletedCount;
    } catch (error) {
      console.error(`Failed to cleanup old logs: ${error}`);
      return 0;
    }
  }

  getStats(): {
    totalLogs: number;
    totalAudit: number;
    byLevel: Record<string, number>;
    byEventType: Record<string, number>;
    criticalEvents: number;
    fileLogging: {
      enabled: boolean;
      currentFile: string | null;
      currentSize: number;
      totalFiles: number;
      totalSize: number;
    };
  } {
    const byLevel: Record<string, number> = {};
    const byEventType: Record<string, number> = {};

    for (const entry of this.logBuffer) {
      const levelName = LogLevel[entry.level];
      byLevel[levelName] = (byLevel[levelName] ?? 0) + 1;
    }

    for (const entry of this.auditLog) {
      byEventType[entry.eventType] =
        (byEventType[entry.eventType] ?? 0) + 1;
    }

    // Gather file logging stats
    let totalFiles = 0;
    let totalSize = 0;
    if (this.config.enableFile && fs.existsSync(this.config.fileDirectory)) {
      try {
        const files = fs.readdirSync(this.config.fileDirectory);
        for (const file of files) {
          if (file.startsWith('mcp-verify-') && file.endsWith('.log')) {
            totalFiles++;
            const filePath = path.join(this.config.fileDirectory, file);
            const stats = fs.statSync(filePath);
            totalSize += stats.size;
          }
        }
      } catch {
        // Ignore errors when reading directory
      }
    }

    return {
      totalLogs: this.logBuffer.length,
      totalAudit: this.auditLog.length,
      byLevel,
      byEventType,
      criticalEvents: this.auditLog.filter((e) => e.severity === 'critical')
        .length,
      fileLogging: {
        enabled: this.config.enableFile,
        currentFile: this.currentLogFile,
        currentSize: this.currentLogSize,
        totalFiles,
        totalSize,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Scoped logger factory
// ---------------------------------------------------------------------------

export type ScopedLogger = {
  debug: (message: string, context?: LogContext) => void;
  info: (message: string, context?: LogContext) => void;
  warn: (message: string, context?: LogContext) => void;
  error: (message: string, error?: Error, context?: LogContext) => void;
  critical: (message: string, context?: LogContext) => void;
  audit: (entry: Omit<AuditEntry, 'timestamp'>) => void;
};

/**
 * Create a scoped logger with a fixed component name pre-filled in the context.
 * All methods merge the provided context on top of the scoped default.
 */
export function createScopedLogger(
  component: string,
  defaultContext?: LogContext
): ScopedLogger {
  const instance = Logger.getInstance();
  const scopedContext: LogContext = { ...defaultContext, component };

  return {
    debug: (message, context) =>
      instance.debug(message, { ...scopedContext, ...context }),
    info: (message, context) =>
      instance.info(message, { ...scopedContext, ...context }),
    warn: (message, context) =>
      instance.warn(message, { ...scopedContext, ...context }),
    error: (message, error, context) =>
      instance.error(message, error, { ...scopedContext, ...context }),
    critical: (message, context) =>
      instance.critical(message, { ...scopedContext, ...context }),
    audit: (entry) =>
      instance.audit({
        ...entry,
        context: { ...scopedContext, ...entry.context },
      }),
  };
}

// ---------------------------------------------------------------------------
// Performance timer utility
// ---------------------------------------------------------------------------

export class PerformanceTimer {
  private readonly startTime: number;
  private readonly logger: ScopedLogger;
  private readonly operation: string;

  constructor(operation: string, component: string) {
    this.operation = operation;
    this.logger = createScopedLogger(component);
    this.startTime = Date.now();
  }

  /** End timer and log success with elapsed duration. */
  end(context?: LogContext): number {
    const duration = Date.now() - this.startTime;
    this.logger.info(`${this.operation} completed`, {
      ...context,
      operation: this.operation,
      duration,
    });
    return duration;
  }

  /** End timer and log failure with elapsed duration. */
  endWithError(error: Error, context?: LogContext): number {
    const duration = Date.now() - this.startTime;
    this.logger.error(`${this.operation} failed`, error, {
      ...context,
      operation: this.operation,
      duration,
    });
    return duration;
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

export const logger = Logger.getInstance();
