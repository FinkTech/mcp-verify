/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Command Normalization Utility
 *
 * Normalizes shell commands to detect obfuscated or hidden dangerous patterns.
 * Prevents bypasses using:
 * - Extra whitespace: "rm  -rf"
 * - Shell variables: "rm${IFS}-rf"
 * - Encoding: "r\x6d -rf"
 * - Quote variations: 'rm' -rf
 *
 * @module libs/shared/utils/command-normalizer
 */

export interface NormalizedCommand {
  original: string;
  normalized: string;
  detectedPatterns: string[];
}

/**
 * Normalizes a command string to detect obfuscated dangerous patterns.
 *
 * Transformations applied:
 * 1. Collapse all whitespace (spaces, tabs, newlines) to single spaces
 * 2. Remove quotes (single, double, backticks)
 * 3. Expand common shell variable patterns (${IFS}, $IFS, etc.)
 * 4. Decode hex escapes (\xNN)
 * 5. Decode unicode escapes (\uNNNN)
 * 6. Convert to lowercase for case-insensitive matching
 *
 * @param input - Command string or object to normalize
 * @returns Normalized string
 *
 * @example
 * normalizeCommand('rm  -rf') // 'rm -rf'
 * normalizeCommand('rm${IFS}-rf') // 'rm -rf'
 * normalizeCommand('r\\x6d -rf') // 'rm -rf'
 */
export function normalizeCommand(input: string | unknown): string {
  let str: string;

  if (typeof input !== 'string') {
    // For non-string inputs, stringify and then normalize
    try {
      str = JSON.stringify(input);
    } catch {
      return '';
    }
  } else {
    str = input;
  }

  let normalized: string = str;

  // 1. Collapse whitespace (spaces, tabs, newlines, carriage returns)
  normalized = normalized.replace(/[\s\t\n\r]+/g, ' ');

  // 2. Remove quotes (single, double, backticks)
  normalized = normalized.replace(/['"`]/g, '');

  // 3. Expand shell variables
  // ${IFS} -> space (Internal Field Separator)
  normalized = normalized.replace(/\$\{IFS\}/gi, ' ');
  normalized = normalized.replace(/\$IFS/gi, ' ');
  // ${} empty variable expansion
  normalized = normalized.replace(/\$\{\}/g, '');

  // 4. Decode hex escapes (\xNN)
  normalized = normalized.replace(/\\x([0-9a-fA-F]{2})/g, (_: string, hex: string) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // 5. Decode unicode escapes (\uNNNN)
  normalized = normalized.replace(/\\u([0-9a-fA-F]{4})/g, (_: string, hex: string) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // 6. Decode octal escapes (\NNN)
  normalized = normalized.replace(/\\([0-7]{1,3})/g, (_: string, octal: string) => {
    return String.fromCharCode(parseInt(octal, 8));
  });

  // 7. Remove backslash escapes (e.g., r\m -> rm)
  normalized = normalized.replace(/\\(.)/g, '$1');

  // 8. Collapse multiple spaces again (after expansions)
  normalized = normalized.replace(/\s+/g, ' ');

  // 9. Trim and lowercase
  normalized = normalized.trim().toLowerCase();

  return normalized;
}

/**
 * Normalizes multiple values (e.g., all arguments in a tool call)
 *
 * @param args - Object containing arguments to normalize
 * @returns Array of normalized strings
 */
export function normalizeArguments(args: Record<string, unknown>): string[] {
  const normalized: string[] = [];

  for (const [key, value] of Object.entries(args)) {
    // Normalize both the key and value
    normalized.push(normalizeCommand(key));
    normalized.push(normalizeCommand(value));
  }

  return normalized;
}

/**
 * Checks if a normalized command contains any dangerous patterns.
 *
 * This is a WHITELIST approach - we only allow safe command patterns.
 * Anything that looks like a shell command execution is flagged.
 *
 * @param normalized - Normalized command string
 * @returns Array of detected dangerous patterns
 */
export function detectDangerousPatterns(normalized: string): string[] {
  const detected: string[] = [];

  // File system operations
  if (/(^|\s)(rm|rmdir|del|delete|format|mkfs)(\s|$)/.test(normalized)) {
    detected.push('file_deletion');
  }

  // Disk operations
  if (/(^|\s)(dd|fdisk|parted)(\s|$)/.test(normalized)) {
    detected.push('disk_operation');
  }

  // Database operations
  if (/(drop\s+(table|database)|truncate|delete\s+from)/.test(normalized)) {
    detected.push('database_mutation');
  }

  // Network operations
  if (/(^|\s)(wget|curl|nc|netcat)(\s|$)/.test(normalized)) {
    detected.push('network_request');
  }

  // Process manipulation
  if (/(kill|pkill|killall)/.test(normalized)) {
    detected.push('process_kill');
  }

  // System commands
  if (/(shutdown|reboot|halt|poweroff)/.test(normalized)) {
    detected.push('system_control');
  }

  // Permission changes
  if (/(chmod|chown|chgrp|setfacl)/.test(normalized)) {
    detected.push('permission_change');
  }

  // Shell command injection patterns
  if (/[;&|`$()<>]/.test(normalized)) {
    detected.push('shell_metacharacters');
  }

  // Fork bombs and recursive patterns
  if (/:\(\)/.test(normalized)) {
    detected.push('fork_bomb');
  }

  // SQL injection patterns (basic)
  if (/(union\s+select|insert\s+into|update\s+.*\s+set)/.test(normalized)) {
    detected.push('sql_injection');
  }

  return detected;
}

/**
 * Full safety analysis of a command/payload.
 *
 * @param input - Command or payload to analyze
 * @returns Analysis result with normalized form and detected patterns
 */
export function analyzeCommandSafety(input: string | unknown): NormalizedCommand {
  const original = typeof input === 'string' ? input : JSON.stringify(input);
  const normalized = normalizeCommand(input);
  const detectedPatterns = detectDangerousPatterns(normalized);

  return {
    original,
    normalized,
    detectedPatterns
  };
}
