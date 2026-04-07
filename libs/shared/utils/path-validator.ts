/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Path Validator - Prevents Path Traversal Attacks
 *
 * Validates user-provided paths to ensure they don't escape
 * intended directories through path traversal (../, etc).
 *
 * Security Fix: CRITICAL-2 from v1.0 audit
 *
 * @module libs/shared/utils/path-validator
 */

import path from "path";
import fs from "fs";

export class PathValidator {
  /**
   * Validate and sanitize output paths to prevent traversal
   *
   * @param userPath - Path provided by user (from CLI args)
   * @param baseDir - Base directory to restrict writes to (default: './reportes')
   * @returns Validated absolute path
   * @throws Error if path attempts to escape base directory
   *
   * @example
   * // Safe paths:
   * validateOutputPath('./reportes/custom.json') // ✅ OK
   * validateOutputPath('reports/test.html')      // ✅ OK
   *
   * // Blocked paths:
   * validateOutputPath('../../../etc/passwd')     // ❌ Throws
   * validateOutputPath('/etc/passwd')             // ❌ Throws
   */
  static validateOutputPath(
    userPath: string,
    baseDir: string = "./reportes",
  ): string {
    // Normalize path (removes .., ./, etc)
    const normalized = path.normalize(userPath);

    // Resolve to absolute path
    const resolved = path.resolve(baseDir, normalized);
    const baseDirResolved = path.resolve(baseDir);

    // Check if resolved path starts with baseDir
    if (!resolved.startsWith(baseDirResolved)) {
      throw new Error(
        `[Security] Invalid output path: "${userPath}" attempts to write outside allowed directory.\n` +
          `Allowed: ${baseDirResolved}\n` +
          `Attempted: ${resolved}\n\n` +
          `This is blocked to prevent path traversal attacks.`,
      );
    }

    // Create directory if it doesn't exist
    const dir = path.dirname(resolved);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    return resolved;
  }

  /**
   * Validate baseline paths (can be anywhere in project, but not outside)
   *
   * @param userPath - Path provided by user (from CLI args)
   * @returns Validated absolute path
   * @throws Error if path is outside project directory
   *
   * @example
   * // Safe paths:
   * validateBaselinePath('./baseline.json')           // ✅ OK
   * validateBaselinePath('config/baseline.json')      // ✅ OK
   *
   * // Blocked paths:
   * validateBaselinePath('../../outside/baseline.json') // ❌ Throws
   * validateBaselinePath('/tmp/baseline.json')          // ❌ Throws
   */
  static validateBaselinePath(userPath: string): string {
    const normalized = path.normalize(userPath);
    const resolved = path.resolve(normalized);
    const cwd = process.cwd();

    // Baseline must be within project directory
    if (!resolved.startsWith(cwd)) {
      throw new Error(
        `[Security] Invalid baseline path: "${userPath}" is outside project directory.\n` +
          `Project: ${cwd}\n` +
          `Attempted: ${resolved}\n\n` +
          `Baseline files must be within the project directory for security.`,
      );
    }

    return resolved;
  }

  /**
   * Check if a path is safe (for testing/validation purposes)
   * Returns true if path would pass validation
   */
  static isSafeOutputPath(
    userPath: string,
    baseDir: string = "./reportes",
  ): boolean {
    try {
      this.validateOutputPath(userPath, baseDir);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if a baseline path is safe (for testing/validation purposes)
   */
  static isSafeBaselinePath(userPath: string): boolean {
    try {
      this.validateBaselinePath(userPath);
      return true;
    } catch {
      return false;
    }
  }
}
