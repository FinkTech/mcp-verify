/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * .mcpverifyignore Parser
 *
 * Parses .mcpverifyignore files to suppress specific security rules or tools.
 * Uses simple .gitignore-style syntax.
 *
 * Supported formats:
 *   SEC-001                    - Ignore rule globally
 *   server.js                  - Ignore all findings in file/tool
 *   *.test.js                  - Ignore pattern (glob)
 *   server.js:45:SEC-001       - Ignore specific rule at specific location
 *   # Comment                  - Comments (ignored)
 *
 * @example
 * ```
 * # .mcpverifyignore
 *
 * # Ignore SQL injection globally
 * SEC-001
 *
 * # Ignore all warnings in test files
 * *.test.js
 * database/migrations/*.js
 *
 * # Ignore specific line
 * server.js:45:SEC-001
 * handlers/auth.js:23:SEC-002
 * ```
 *
 * @module libs/core/domain/security/mcpignore-parser
 */

export interface IgnoreRule {
  type: 'global' | 'file' | 'specific';
  ruleCode?: string;
  file?: string;
  line?: number;
  pattern?: RegExp; // For glob patterns like *.test.js
}

export class McpIgnoreParser {
  /**
   * Parse .mcpverifyignore file content
   */
  static parse(content: string): IgnoreRule[] {
    const rules: IgnoreRule[] = [];
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Format 1: file:line:rule (e.g., server.js:45:SEC-001)
      const specificMatch = trimmed.match(/^(.+):(\d+):([A-Z]+-\d+)$/);
      if (specificMatch) {
        rules.push({
          type: 'specific',
          file: specificMatch[1],
          line: parseInt(specificMatch[2], 10),
          ruleCode: specificMatch[3]
        });
        continue;
      }

      // Format 2: Rule code only (e.g., SEC-001)
      const ruleMatch = trimmed.match(/^([A-Z]+-\d+)$/);
      if (ruleMatch) {
        rules.push({
          type: 'global',
          ruleCode: ruleMatch[1]
        });
        continue;
      }

      // Format 3: File pattern (e.g., server.js or *.test.js)
      // Convert glob pattern to regex
      const pattern = this.globToRegex(trimmed);
      rules.push({
        type: 'file',
        file: trimmed,
        pattern
      });
    }

    return rules;
  }

  /**
   * Convert glob pattern to RegExp
   * Supports:
   * - * (matches any characters except /)
   * - ** (matches any characters including /)
   * - ? (matches single character)
   */
  private static globToRegex(glob: string): RegExp {
    // Escape special regex characters except * and ?
    let pattern = glob
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '___DOUBLE_STAR___')
      .replace(/\*/g, '[^/]*')
      .replace(/___DOUBLE_STAR___/g, '.*')
      .replace(/\?/g, '.');

    return new RegExp(`^${pattern}$`);
  }

  /**
   * Check if a finding should be ignored
   *
   * @param ruleCode - Security rule code (e.g., SEC-001)
   * @param toolName - Tool name (optional, extracted from component)
   * @param ignoreRules - Parsed ignore rules
   * @returns true if finding should be ignored
   */
  static shouldIgnore(
    ruleCode: string,
    toolName: string | undefined,
    ignoreRules: IgnoreRule[]
  ): boolean {
    for (const rule of ignoreRules) {
      // Global rule ignore (e.g., SEC-001)
      if (rule.type === 'global' && rule.ruleCode === ruleCode) {
        return true;
      }

      // File pattern ignore (e.g., *.test.js or server.js)
      if (rule.type === 'file' && toolName && rule.pattern) {
        if (rule.pattern.test(toolName)) {
          return true;
        }
      }

      // Specific location ignore (e.g., server.js:45:SEC-001)
      // Note: We don't have line numbers in MCP tool definitions,
      // so we match by file + rule code only
      if (rule.type === 'specific' && rule.ruleCode === ruleCode && toolName) {
        if (rule.file === toolName) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Generate example .mcpverifyignore content
   */
  static generateExample(): string {
    return `# .mcpverifyignore - Suppress specific security rules or tools
# Simple .gitignore-style syntax
#
# Supported formats:
#   SEC-001                    - Ignore rule globally
#   server.js                  - Ignore all findings in file/tool
#   *.test.js                  - Ignore pattern (glob)
#   server.js:45:SEC-001       - Ignore specific rule at specific location
#   # Comment                  - Comments (ignored)
#
# Example use cases:
#   - Intentional SQL tool: execute_sql or SEC-001
#   - Test files: *.test.js or **/__tests__/**
#   - False positive: server.js:45:SEC-001

# Ignore SQL injection globally (intentional database tools)
# SEC-001

# Ignore all warnings in test files
# *.test.js
# **/__tests__/**

# Ignore command injection for system administration tools
# SEC-002

# Ignore specific line in specific file
# server.js:45:SEC-001
# handlers/auth.js:23:SEC-002
`;
  }
}
