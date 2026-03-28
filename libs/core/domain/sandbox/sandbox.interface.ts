/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export interface SandboxOptions {
  allowRead?: string[];
  allowNet?: string[];
  allowEnv?: boolean;
}

/**
 * Result of sandbox environment validation
 */
export interface SandboxEnvironmentCheck {
  /** Whether the sandbox is available and ready to use */
  available: boolean;
  /** Detected binary path (if found) */
  binaryPath?: string;
  /** Detected version string */
  version?: string;
  /** Parsed semantic version for comparison */
  semver?: { major: number; minor: number; patch: number };
  /** Whether version meets minimum requirements */
  versionCompatible: boolean;
  /** Whether temp directory is writable */
  tempWritable: boolean;
  /** List of issues found during validation */
  issues: string[];
  /** Suggested actions for the user */
  suggestions: string[];
}

export interface ISandbox {
  /**
   * Envelops a command and its arguments into a sandboxed execution.
   * @returns A tuple of [sandboxedCommand, sandboxedArgs[]]
   */
  wrap(command: string, args: string[]): [string, string[]];
}
