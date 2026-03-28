/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Input Sanitizer Guardrail
 *
 * Sanitizes potentially dangerous input by removing or encoding harmful
 * characters and patterns that could lead to injection attacks.
 *
 * Protects against:
 * - SQL Injection
 * - Command Injection
 * - Path Traversal
 * - XSS (Cross-Site Scripting)
 * - Script injection
 *
 * @module libs/core/use-cases/proxy/guardrails/input-sanitizer
 */

import { t } from '@mcp-verify/shared';
import type { IGuardrail, InterceptResult } from '../proxy.types';
import type { JsonValue } from '../../../domain/shared/common.types';

export class InputSanitizer implements IGuardrail {
  name = t('guardrail_input_sanitization');

  /**
   * Dangerous characters and their safe replacements
   */
  private dangerousChars = {
    // SQL injection characters
    sql: [
      { pattern: /['";]/g, replacement: '', description: t('guardrail_sanitizer_sql') },
      { pattern: /--/g, replacement: '', description: t('guardrail_sanitizer_sql') },
      { pattern: /\/\*/g, replacement: '', description: t('guardrail_sanitizer_sql') },
      { pattern: /\*\//g, replacement: '', description: t('guardrail_sanitizer_sql') }
    ],

    // Command injection characters
    command: [
      { pattern: /[;&|`$()]/g, replacement: '', description: t('guardrail_sanitizer_shell') },
      { pattern: /\n/g, replacement: ' ', description: t('guardrail_sanitizer_shell') },
      { pattern: /\r/g, replacement: ' ', description: t('guardrail_sanitizer_shell') }
    ],

    // Path traversal
    path: [
      { pattern: /\.\.\//g, replacement: '', description: t('guardrail_sanitizer_path') },
      { pattern: /\.\.\\/g, replacement: '', description: t('guardrail_sanitizer_path') },
      { pattern: /%2e%2e%2f/gi, replacement: '', description: t('guardrail_sanitizer_path') },
      { pattern: /%2e%2e%5c/gi, replacement: '', description: t('guardrail_sanitizer_path') }
    ],

    // XSS (basic)
    xss: [
      { pattern: /<script[^>]*>.*?<\/script>/gi, replacement: '', description: 'Script tags' },
      { pattern: /<iframe[^>]*>.*?<\/iframe>/gi, replacement: '', description: 'Iframe tags' },
      { pattern: /javascript:/gi, replacement: '', description: 'JavaScript protocol' },
      { pattern: /on\w+\s*=/gi, replacement: '', description: 'Event handlers' }
    ],

    // Null bytes
    nullBytes: [
      { pattern: /\x00/g, replacement: '', description: 'Null bytes' }
    ]
  };

  /**
   * Configuration
   */
  private config = {
    enableSqlSanitization: true,
    enableCommandSanitization: true,
    enablePathSanitization: true,
    enableXssSanitization: true,
    enableNullByteSanitization: true,
    logSanitizations: true,
    strictMode: false // If true, block instead of sanitize
  };

  inspectRequest(message: JsonValue): InterceptResult {
    const result = this.sanitizeMessage(message);

    // In strict mode, block if dangerous content detected
    if (this.config.strictMode && result.wasSanitized) {
      return {
        action: 'block',
        reason: `Blocked request with dangerous content: ${result.sanitizedTypes.join(', ')}`
      };
    }

    if (result.wasSanitized) {
      return {
        action: 'modify',
        modifiedMessage: result.message,
        reason: `Sanitized dangerous input: ${result.sanitizedTypes.join(', ')}`
      };
    }

    return { action: 'allow' };
  }

  inspectResponse(message: JsonValue): InterceptResult {
    // Typically we don't sanitize responses, but we could
    return { action: 'allow' };
  }

  /**
   * Sanitize a message recursively
   */
  private sanitizeMessage(message: JsonValue): {
    message: JsonValue;
    wasSanitized: boolean;
    sanitizedTypes: string[];
  } {
    const sanitizedTypes: string[] = [];

    // Deep clone with error handling
    let sanitized: JsonValue;
    try {
      sanitized = JSON.parse(JSON.stringify(message)) as JsonValue;
    } catch (error) {
      // If cloning fails, return original message (unlikely but safe)
      return { message, wasSanitized: false, sanitizedTypes: [] };
    }

    // Recursively sanitize all string values
    const sanitizeRecursive = (obj: JsonValue): boolean => {
      let modified = false;

      if (typeof obj === 'string') {
        // This shouldn't happen as we need to modify in parent
        return false;
      }

      if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) {
          if (typeof obj[i] === 'string') {
            const result = this.sanitizeString(obj[i] as string);
            if (result.wasSanitized) {
              obj[i] = result.value;
              result.types.forEach(t => {
                if (!sanitizedTypes.includes(t)) {
                  sanitizedTypes.push(t);
                }
              });
              modified = true;
            }
          } else if (typeof obj[i] === 'object' && obj[i] !== null) {
            if (sanitizeRecursive(obj[i])) {
              modified = true;
            }
          }
        }
      } else if (typeof obj === 'object' && obj !== null) {
        for (const key in obj) {
          if (typeof obj[key] === 'string') {
            const result = this.sanitizeString(obj[key]);
            if (result.wasSanitized) {
              obj[key] = result.value;
              result.types.forEach(t => {
                if (!sanitizedTypes.includes(t)) {
                  sanitizedTypes.push(t);
                }
              });
              modified = true;
            }
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            if (sanitizeRecursive(obj[key])) {
              modified = true;
            }
          }
        }
      }

      return modified;
    };

    const wasSanitized = sanitizeRecursive(sanitized);

    return {
      message: sanitized,
      wasSanitized,
      sanitizedTypes
    };
  }

  /**
   * Sanitize a single string value
   */
  private sanitizeString(value: string): {
    value: string;
    wasSanitized: boolean;
    types: string[];
  } {
    let sanitized = value;
    const types: string[] = [];
    let modified = false;

    // SQL sanitization
    if (this.config.enableSqlSanitization) {
      for (const rule of this.dangerousChars.sql) {
        if (rule.pattern.test(sanitized)) {
          sanitized = sanitized.replace(rule.pattern, rule.replacement);
          if (!types.includes('SQL')) types.push('SQL');
          modified = true;
          // Reset regex lastIndex
          rule.pattern.lastIndex = 0;
        }
      }
    }

    // Command sanitization
    if (this.config.enableCommandSanitization) {
      for (const rule of this.dangerousChars.command) {
        if (rule.pattern.test(sanitized)) {
          sanitized = sanitized.replace(rule.pattern, rule.replacement);
          if (!types.includes('Command')) types.push('Command');
          modified = true;
          rule.pattern.lastIndex = 0;
        }
      }
    }

    // Path sanitization
    if (this.config.enablePathSanitization) {
      for (const rule of this.dangerousChars.path) {
        if (rule.pattern.test(sanitized)) {
          sanitized = sanitized.replace(rule.pattern, rule.replacement);
          if (!types.includes('Path')) types.push('Path');
          modified = true;
          rule.pattern.lastIndex = 0;
        }
      }
    }

    // XSS sanitization
    if (this.config.enableXssSanitization) {
      for (const rule of this.dangerousChars.xss) {
        if (rule.pattern.test(sanitized)) {
          sanitized = sanitized.replace(rule.pattern, rule.replacement);
          if (!types.includes('XSS')) types.push('XSS');
          modified = true;
          rule.pattern.lastIndex = 0;
        }
      }
    }

    // Null byte sanitization
    if (this.config.enableNullByteSanitization) {
      for (const rule of this.dangerousChars.nullBytes) {
        if (rule.pattern.test(sanitized)) {
          sanitized = sanitized.replace(rule.pattern, rule.replacement);
          if (!types.includes('NullByte')) types.push('NullByte');
          modified = true;
          rule.pattern.lastIndex = 0;
        }
      }
    }

    return {
      value: sanitized,
      wasSanitized: modified,
      types
    };
  }

  /**
   * Configure the sanitizer
   */
  configure(options: Partial<typeof this.config>) {
    Object.assign(this.config, options);
  }

  /**
   * Add custom sanitization rule
   */
  addCustomRule(category: keyof typeof this.dangerousChars, rule: {
    pattern: RegExp;
    replacement: string;
    description: string;
  }) {
    this.dangerousChars[category].push(rule);
  }
}
