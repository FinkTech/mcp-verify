/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Classic Payloads Generator
 *
 * Adapter that wraps the existing attack payloads library
 * from libs/core/use-cases/fuzzer/payloads.ts
 *
 * This provides access to all classic security payloads:
 * - SQL Injection
 * - XSS
 * - Command Injection
 * - Path Traversal
 * - SSRF
 * - XXE
 * - Buffer Overflow
 * - Format String
 * - LDAP Injection
 * - NoSQL Injection
 * - Template Injection
 */

import { IPayloadGenerator, GeneratedPayload, GeneratorConfig } from './generator.interface';
import {
  ATTACK_PAYLOADS,
  AttackPayload,
  getAllPayloads,
  getPayloadsByType,
  getPayloadsBySeverity
} from '@mcp-verify/core/use-cases/fuzzer/payloads';

/** Available classic payload categories */
export type ClassicPayloadCategory = keyof typeof ATTACK_PAYLOADS;

export interface ClassicPayloadConfig {
  /** Which categories to include (default: all) */
  categories?: ClassicPayloadCategory[];
  /** Filter by severity (default: all) */
  severities?: Array<'critical' | 'high' | 'medium' | 'low'>;
  /** Max payloads per category (default: unlimited) */
  maxPerCategory?: number;
}

/**
 * Generator that wraps all classic security payloads
 */
export class ClassicPayloadGenerator implements IPayloadGenerator {
  readonly id = 'classic-payloads';
  readonly name = 'Classic Security Payloads';
  readonly description = 'Traditional security attack payloads (SQLi, XSS, Command Injection, etc.)';

  private config: ClassicPayloadConfig;

  constructor(config: ClassicPayloadConfig = {}) {
    this.config = config;
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // Get categories to use
    const categories = this.config.categories || (Object.keys(ATTACK_PAYLOADS) as ClassicPayloadCategory[]);

    for (const category of categories) {
      let categoryPayloads = getPayloadsByType(category);

      // Filter by severity if configured
      if (this.config.severities && this.config.severities.length > 0) {
        categoryPayloads = categoryPayloads.filter(p =>
          this.config.severities!.includes(p.severity)
        );
      }

      // Limit per category if configured
      if (this.config.maxPerCategory) {
        categoryPayloads = categoryPayloads.slice(0, this.config.maxPerCategory);
      }

      // Convert to GeneratedPayload format
      for (const payload of categoryPayloads) {
        payloads.push(this.convertPayload(payload, category));
      }
    }

    return payloads;
  }

  private convertPayload(payload: AttackPayload, category: string): GeneratedPayload {
    return {
      value: payload.value,
      category: category,
      type: payload.type,
      severity: payload.severity,
      description: payload.description,
      expectedVulnerableBehavior: payload.expectedBehavior,
      metadata: {
        source: 'classic-payloads'
      }
    };
  }
}

// ============================================================
// Convenience generators for specific attack types
// ============================================================

/**
 * SQL Injection Generator
 */
export class SqlInjectionGenerator implements IPayloadGenerator {
  readonly id = 'sqli';
  readonly name = 'SQL Injection';
  readonly description = 'SQL injection attack payloads';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['sqli'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * XSS Generator
 */
export class XssGenerator implements IPayloadGenerator {
  readonly id = 'xss';
  readonly name = 'Cross-Site Scripting';
  readonly description = 'XSS attack payloads';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['xss'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * Command Injection Generator
 */
export class CommandInjectionGenerator implements IPayloadGenerator {
  readonly id = 'cmd-injection';
  readonly name = 'Command Injection';
  readonly description = 'OS command injection payloads';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['cmdInjection'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * Path Traversal Generator
 */
export class PathTraversalGenerator implements IPayloadGenerator {
  readonly id = 'path-traversal';
  readonly name = 'Path Traversal';
  readonly description = 'Directory traversal attack payloads';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['pathTraversal'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * SSRF Generator
 */
export class SsrfGenerator implements IPayloadGenerator {
  readonly id = 'ssrf';
  readonly name = 'Server-Side Request Forgery';
  readonly description = 'SSRF attack payloads targeting internal services';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['ssrf'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * XXE Generator
 */
export class XxeGenerator implements IPayloadGenerator {
  readonly id = 'xxe';
  readonly name = 'XML External Entity';
  readonly description = 'XXE attack payloads for XML parsers';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['xxe'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * NoSQL Injection Generator
 */
export class NoSqlInjectionGenerator implements IPayloadGenerator {
  readonly id = 'nosql';
  readonly name = 'NoSQL Injection';
  readonly description = 'NoSQL injection payloads (MongoDB, etc.)';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['nosql'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * Template Injection Generator
 */
export class TemplateInjectionGenerator implements IPayloadGenerator {
  readonly id = 'template-injection';
  readonly name = 'Template Injection';
  readonly description = 'SSTI payloads for template engines';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['templateInjection'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * Buffer Overflow Generator
 */
export class BufferOverflowGenerator implements IPayloadGenerator {
  readonly id = 'overflow';
  readonly name = 'Buffer Overflow';
  readonly description = 'Large payload and buffer overflow attempts';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['overflow'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * LDAP Injection Generator
 */
export class LdapInjectionGenerator implements IPayloadGenerator {
  readonly id = 'ldap';
  readonly name = 'LDAP Injection';
  readonly description = 'LDAP injection payloads';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['ldap'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}

/**
 * Format String Generator
 */
export class FormatStringGenerator implements IPayloadGenerator {
  readonly id = 'format-string';
  readonly name = 'Format String';
  readonly description = 'Format string vulnerability payloads';

  private inner: ClassicPayloadGenerator;

  constructor() {
    this.inner = new ClassicPayloadGenerator({ categories: ['formatString'] });
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    return this.inner.generate(config);
  }
}
