/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Server Fingerprinter
 *
 * Intelligent reconnaissance module that identifies the server's technology stack
 * BEFORE fuzzing begins. This allows the engine to:
 *
 * - Disable irrelevant generators (e.g., no PrototypePollution for Rust)
 * - Prioritize high-value payloads for the detected stack
 * - Reduce fuzzing time by 30-50%
 * - Eliminate "impossible findings" noise
 *
 * Detection Methods:
 * 1. Error Signature Analysis: Stack traces reveal language/framework
 * 2. Response Pattern Analysis: Error message styles
 * 3. Behavioral Probing: How the server handles malformed input
 */

import type { FuzzTarget } from '../engine/fuzzer-engine';
import type { GeneratedPayload } from '../generators/generator.interface';

// ==================== TYPES ====================

export type ServerLanguage =
  | 'nodejs'
  | 'python'
  | 'rust'
  | 'go'
  | 'java'
  | 'csharp'
  | 'ruby'
  | 'php'
  | 'unknown';

export type ServerFramework =
  | 'fastmcp'      // Python FastMCP
  | 'mcp-sdk-ts'   // Official TypeScript SDK
  | 'mcp-sdk-py'   // Official Python SDK
  | 'express'      // Node.js Express
  | 'fastify'      // Node.js Fastify
  | 'flask'        // Python Flask
  | 'django'       // Python Django
  | 'actix'        // Rust Actix
  | 'axum'         // Rust Axum
  | 'gin'          // Go Gin
  | 'echo'         // Go Echo
  | 'spring'       // Java Spring
  | 'unknown';

export type DatabaseType =
  | 'postgresql'
  | 'mysql'
  | 'sqlite'
  | 'mongodb'
  | 'redis'
  | 'none'
  | 'unknown';

export interface ServerFingerprint {
  /** Detected programming language */
  language: ServerLanguage;
  /** Confidence level for language detection (0-1) */
  languageConfidence: number;

  /** Detected framework (if identifiable) */
  framework: ServerFramework;
  /** Confidence level for framework detection (0-1) */
  frameworkConfidence: number;

  /** Detected database type (if identifiable) */
  database: DatabaseType;

  /** Raw evidence collected during fingerprinting */
  evidence: FingerprintEvidence[];

  /** Recommended generators to ENABLE */
  recommendedGenerators: string[];
  /** Generators to DISABLE (irrelevant for this stack) */
  disabledGenerators: string[];

  /** Human-readable summary */
  summary: string;

  /** Fingerprinting duration in ms */
  durationMs: number;
}

export interface FingerprintEvidence {
  /** Probe that triggered this evidence */
  probe: string;
  /** The pattern that matched */
  pattern: string;
  /** What was detected */
  detection: string;
  /** Confidence (0-1) */
  confidence: number;
  /** Raw response excerpt */
  excerpt: string;
}

export interface FingerprintConfig {
  /** Timeout per probe in ms (default: 3000) */
  probeTimeout?: number;
  /** Minimum confidence to accept detection (default: 0.6) */
  minConfidence?: number;
  /** Enable verbose logging */
  verbose?: boolean;
}

// ==================== FINGERPRINTER ====================

export class Fingerprinter {
  private config: Required<FingerprintConfig>;

  constructor(config: FingerprintConfig = {}) {
    this.config = {
      probeTimeout: config.probeTimeout ?? 3000,
      minConfidence: config.minConfidence ?? 0.6,
      verbose: config.verbose ?? false
    };
  }

  // ==================== PROBE DEFINITIONS ====================

  /**
   * Probes designed to trigger informative error messages
   */
  private readonly probes: GeneratedPayload[] = [
    // 1. Type confusion - triggers TypeError in dynamic languages
    {
      value: JSON.stringify({ __proto__: null, toString: null }),
      category: 'fingerprint',
      type: 'type-confusion-probe',
      description: 'Type confusion probe',
      severity: 'low'
    },
    // 2. Invalid JSON-RPC - revela la implementación del protocolo
    {
      value: '{"jsonrpc": "invalid", "method": 123, "id": "test"}',
      category: 'fingerprint',
      type: 'invalid-jsonrpc-probe',
      description: 'Invalid JSON-RPC probe',
      severity: 'low'
    },
    // 3. Deeply nested object - triggers stack overflow in some parsers
    {
      value: JSON.stringify(this.generateDeepObject(50)),
      category: 'fingerprint',
      type: 'deep-nesting-probe',
      description: 'Deep nesting probe',
      severity: 'medium'
    },
    // 4. SQL-like string - puede disparar error SQL si el backend usa SQL
    {
      value: "' OR '1'='1",
      category: 'fingerprint',
      type: 'sql-probe',
      description: 'SQL probe',
      severity: 'low'
    },
    // 5. Path traversal - revela el estilo de error del sistema de archivos
    {
      value: '../../../etc/passwd',
      category: 'fingerprint',
      type: 'path-traversal-probe',
      description: 'Path traversal probe',
      severity: 'medium'
    },
    // 6. Unicode edge case - reveals encoding handling
    {
      value: '\u0000\uFFFF\uD800',
      category: 'fingerprint',
      type: 'unicode-probe',
      description: 'Unicode probe',
      severity: 'low'
    },
    // 7. Large number - triggers overflow errors
    {
      value: String(Number.MAX_SAFE_INTEGER + 1),
      category: 'fingerprint',
      type: 'large-number-probe',
      description: 'Large number probe',
      severity: 'low'
    }
  ];

  // ==================== SIGNATURE PATTERNS ====================

  private readonly languageSignatures: Array<{
    language: ServerLanguage;
    patterns: RegExp[];
    confidence: number;
  }> = [
    // Node.js / JavaScript
    {
      language: 'nodejs',
      patterns: [
        /TypeError:.*at\s+\S+\s+\(/i,
        /at\s+Object\.<anonymous>/,
        /at\s+Module\._compile/,
        /ReferenceError:.*is not defined/,
        /SyntaxError:.*Unexpected token/,
        /\.js:\d+:\d+\)/,
        /node_modules/,
        /Cannot read propert(y|ies) of/,
        /undefined is not a function/,
        /ENOENT|EACCES|EPERM/
      ],
      confidence: 0.9
    },
    // Python
    {
      language: 'python',
      patterns: [
        /Traceback \(most recent call last\)/,
        /File ".*\.py", line \d+/,
        /^\s+raise\s+\w+Error/m,
        /TypeError:.*expected.*got/,
        /AttributeError:/,
        /KeyError:/,
        /ValueError:/,
        /ImportError:/,
        /ModuleNotFoundError:/,
        /IndentationError:/
      ],
      confidence: 0.95
    },
    // Rust
    {
      language: 'rust',
      patterns: [
        /panicked at/,
        /thread '.*' panicked/,
        /note: run with `RUST_BACKTRACE=1`/,
        /src\/.*\.rs:\d+:\d+/,
        /called `Option::unwrap\(\)` on a `None` value/,
        /called `Result::unwrap\(\)` on an `Err` value/,
        /index out of bounds/,
        /assertion failed/
      ],
      confidence: 0.95
    },
    // Go
    {
      language: 'go',
      patterns: [
        /panic:.*runtime error/,
        /goroutine \d+ \[running\]/,
        /\.go:\d+\s+\+0x[0-9a-f]+/,
        /runtime\.goexit/,
        /nil pointer dereference/,
        /invalid memory address/
      ],
      confidence: 0.9
    },
    // Java
    {
      language: 'java',
      patterns: [
        /at\s+[\w.]+\([\w]+\.java:\d+\)/,
        /Exception in thread/,
        /java\.lang\.\w+Exception/,
        /NullPointerException/,
        /ArrayIndexOutOfBoundsException/,
        /ClassNotFoundException/,
        /\.class\)/
      ],
      confidence: 0.9
    },
    // C# / .NET
    {
      language: 'csharp',
      patterns: [
        /at\s+[\w.]+\sin\s+.*\.cs:line\s+\d+/,
        /System\.\w+Exception/,
        /NullReferenceException/,
        /ArgumentException/,
        /InvalidOperationException/,
        /Microsoft\.AspNetCore/
      ],
      confidence: 0.9
    },
    // Ruby
    {
      language: 'ruby',
      patterns: [
        /from\s+.*\.rb:\d+:in\s+`/,
        /NoMethodError/,
        /NameError/,
        /ArgumentError.*wrong number of arguments/,
        /RuntimeError/,
        /LoadError/
      ],
      confidence: 0.85
    },
    // PHP
    {
      language: 'php',
      patterns: [
        /PHP\s+(Fatal|Warning|Notice|Parse)\s+error/i,
        /on line \d+ in .*\.php/,
        /Stack trace:.*#\d+/s,
        /Uncaught\s+\w+Exception/,
        /Call to undefined function/,
        /Cannot use object of type/
      ],
      confidence: 0.9
    }
  ];

  private readonly frameworkSignatures: Array<{
    framework: ServerFramework;
    patterns: RegExp[];
    confidence: number;
  }> = [
    // FastMCP (Python)
    {
      framework: 'fastmcp',
      patterns: [
        /fastmcp/i,
        /FastMCP/,
        /mcp\.server\.fastmcp/
      ],
      confidence: 0.95
    },
    // Official MCP SDK (TypeScript)
    {
      framework: 'mcp-sdk-ts',
      patterns: [
        /@modelcontextprotocol\/sdk/,
        /mcp-typescript/i,
        /McpServer/
      ],
      confidence: 0.9
    },
    // Official MCP SDK (Python)
    {
      framework: 'mcp-sdk-py',
      patterns: [
        /mcp\.server/,
        /from mcp import/,
        /mcp-python/i
      ],
      confidence: 0.85
    },
    // Express
    {
      framework: 'express',
      patterns: [
        /express/i,
        /at Layer\.handle/,
        /at Route\./
      ],
      confidence: 0.8
    },
    // Fastify
    {
      framework: 'fastify',
      patterns: [
        /fastify/i,
        /at onSendEnd/
      ],
      confidence: 0.8
    },
    // Flask
    {
      framework: 'flask',
      patterns: [
        /flask/i,
        /werkzeug/i,
        /from flask import/
      ],
      confidence: 0.8
    },
    // Django
    {
      framework: 'django',
      patterns: [
        /django/i,
        /from django/,
        /django\.core/
      ],
      confidence: 0.85
    },
    // Actix (Rust)
    {
      framework: 'actix',
      patterns: [
        /actix_server/i,
        /actix_rt/i,
        /actix-web/i
      ],
      confidence: 0.9
    },
    // Axum (Rust)
    {
      framework: 'axum',
      patterns: [
        /\baxum::/i,
        /\bhyper::/i,
        /tokio::runtime/
      ],
      confidence: 0.85
    },
    // Gin (Go)
    {
      framework: 'gin',
      patterns: [
        /gin-gonic\/gin/i,
        /\[GIN\]/i,
        /GIN_MODE/
      ],
      confidence: 0.95
    },
    // Echo (Go)
    {
      framework: 'echo',
      patterns: [
        /labstack\/echo/i,
        /echo\.Context/
      ],
      confidence: 0.9
    },
    // Spring (Java)
    {
      framework: 'spring',
      patterns: [
        /org\.springframework\./i,
        /Spring\s+Framework/i,
        /SpringApplication/
      ],
      confidence: 0.95
    }
  ];

  private readonly databaseSignatures: Array<{
    database: DatabaseType;
    patterns: RegExp[];
    confidence: number;
  }> = [
    {
      database: 'postgresql',
      patterns: [
        /PostgreSQL/i,
        /pg_catalog/,
        /SQLSTATE/,
        /psycopg2/,
        /node-postgres/
      ],
      confidence: 0.9
    },
    {
      database: 'mysql',
      patterns: [
        /MySQL/i,
        /mysql2?:/,
        /ER_\w+:/,
        /SQLSTATE\[HY/
      ],
      confidence: 0.9
    },
    {
      database: 'sqlite',
      patterns: [
        /SQLite/i,
        /sqlite3/,
        /SQLITE_/
      ],
      confidence: 0.85
    },
    {
      database: 'mongodb',
      patterns: [
        /MongoDB/i,
        /MongoError/,
        /mongoose/i,
        /BSONTypeError/
      ],
      confidence: 0.9
    },
    {
      database: 'redis',
      patterns: [
        /Redis/i,
        /WRONGTYPE/,
        /ReplyError/
      ],
      confidence: 0.85
    }
  ];

  // ==================== MAIN FINGERPRINT METHOD ====================

  async fingerprint(target: FuzzTarget, toolName: string): Promise<ServerFingerprint> {
    const startTime = Date.now();
    const evidence: FingerprintEvidence[] = [];

    // Send all probes and collect responses
    for (const probe of this.probes) {
      try {
        const result = await target.execute(probe);
        const responseStr = this.stringifyResponse(result.response, result.error);

        // Analyze response for signatures
        const languageMatches = this.matchSignatures(responseStr, this.languageSignatures);
        const frameworkMatches = this.matchSignatures(responseStr, this.frameworkSignatures);
        const databaseMatches = this.matchSignatures(responseStr, this.databaseSignatures);

        // Collect evidence
        for (const match of [...languageMatches, ...frameworkMatches, ...databaseMatches]) {
          evidence.push({
            probe: probe.description,
            pattern: match.pattern,
            detection: match.type,
            confidence: match.confidence,
            excerpt: this.extractExcerpt(responseStr, match.pattern)
          });
        }

        if (this.config.verbose) {
          console.log(`[Fingerprint] Probe "${probe.description}": ${languageMatches.length} language, ${frameworkMatches.length} framework, ${databaseMatches.length} database matches`);
        }
      } catch (error) {
        // Even errors can provide fingerprinting info
        const errorStr = error instanceof Error ? error.message + (error.stack || '') : String(error);
        const languageMatches = this.matchSignatures(errorStr, this.languageSignatures);

        for (const match of languageMatches) {
          evidence.push({
            probe: probe.description,
            pattern: match.pattern,
            detection: match.type,
            confidence: match.confidence,
            excerpt: this.extractExcerpt(errorStr, match.pattern)
          });
        }
      }
    }

    // Aggregate results
    const language = this.aggregateDetection<ServerLanguage>(
      evidence.filter(e => this.isLanguage(e.detection)),
      'unknown'
    );

    const framework = this.aggregateDetection<ServerFramework>(
      evidence.filter(e => this.isFramework(e.detection)),
      'unknown'
    );

    const database = this.aggregateDetection<DatabaseType>(
      evidence.filter(e => this.isDatabase(e.detection)),
      'unknown'
    );

    // Determine generator recommendations
    const { recommended, disabled } = this.getGeneratorRecommendations(language.value, framework.value);

    const durationMs = Date.now() - startTime;

    return {
      language: language.value,
      languageConfidence: language.confidence,
      framework: framework.value,
      frameworkConfidence: framework.confidence,
      database: database.value,
      evidence,
      recommendedGenerators: recommended,
      disabledGenerators: disabled,
      summary: this.generateSummary(language, framework, database, disabled),
      durationMs
    };
  }

  // ==================== HELPER METHODS ====================

  private matchSignatures<T extends string>(
    text: string,
    signatures: Array<{ [key: string]: T | RegExp[] | number }>
  ): Array<{ type: T; pattern: string; confidence: number }> {
    const matches: Array<{ type: T; pattern: string; confidence: number }> = [];

    for (const sig of signatures) {
      const type = Object.values(sig)[0] as T;
      const patterns = sig.patterns as RegExp[];
      const baseConfidence = sig.confidence as number;

      for (const pattern of patterns) {
        if (pattern.test(text)) {
          matches.push({
            type,
            pattern: pattern.source,
            confidence: baseConfidence
          });
        }
      }
    }

    return matches;
  }

  private aggregateDetection<T extends string>(
    evidence: FingerprintEvidence[],
    defaultValue: T
  ): { value: T; confidence: number } {
    if (evidence.length === 0) {
      return { value: defaultValue, confidence: 0 };
    }

    // Count by detection type
    const counts: Record<string, { count: number; maxConfidence: number }> = {};

    for (const e of evidence) {
      if (!counts[e.detection]) {
        counts[e.detection] = { count: 0, maxConfidence: 0 };
      }
      counts[e.detection].count++;
      counts[e.detection].maxConfidence = Math.max(counts[e.detection].maxConfidence, e.confidence);
    }

    // Find the detection with highest weighted score
    let best: { type: string; score: number } = { type: defaultValue, score: 0 };

    for (const [type, data] of Object.entries(counts)) {
      // Score = count * maxConfidence
      const score = data.count * data.maxConfidence;
      if (score > best.score) {
        best = { type, score };
      }
    }

    // Calculate final confidence
    const finalConfidence = Math.min(1, best.score / evidence.length);

    return {
      value: best.type as T,
      confidence: finalConfidence >= this.config.minConfidence ? finalConfidence : 0
    };
  }

  private getGeneratorRecommendations(
    language: ServerLanguage,
    framework: ServerFramework
  ): { recommended: string[]; disabled: string[] } {
    const allGenerators = [
      'PromptInjectionGenerator',
      'JsonRpcGenerator',
      'SchemaConfusionGenerator',
      'ClassicPayloadGenerator',
      'SqlInjectionGenerator',
      'XssGenerator',
      'CommandInjectionGenerator',
      'PathTraversalGenerator',
      'SsrfGenerator',
      'XxeGenerator',
      'NoSqlInjectionGenerator',
      'TemplateInjectionGenerator',
      'BufferOverflowGenerator',
      'LdapInjectionGenerator',
      'FormatStringGenerator',
      'JwtAttackGenerator',
      'PrototypePollutionGenerator',
      'TimeBasedPayloadGenerator'
    ];

    const disabled: string[] = [];
    const recommended: string[] = [];

    // Language-specific filtering
    switch (language) {
      case 'rust':
      case 'go':
        // No prototype pollution in compiled languages
        disabled.push('PrototypePollutionGenerator');
        // Buffer overflows less likely in memory-safe languages
        disabled.push('BufferOverflowGenerator');
        // Format string attacks unlikely
        disabled.push('FormatStringGenerator');
        break;

      case 'nodejs':
        // Prototype pollution is HIGH priority
        recommended.push('PrototypePollutionGenerator');
        // NoSQL common in Node.js
        recommended.push('NoSqlInjectionGenerator');
        // Template injection (EJS, Handlebars)
        recommended.push('TemplateInjectionGenerator');
        break;

      case 'python':
        // Template injection (Jinja2)
        recommended.push('TemplateInjectionGenerator');
        // Command injection more common
        recommended.push('CommandInjectionGenerator');
        // No prototype pollution
        disabled.push('PrototypePollutionGenerator');
        break;

      case 'java':
        // XXE is common in Java
        recommended.push('XxeGenerator');
        // No prototype pollution
        disabled.push('PrototypePollutionGenerator');
        break;

      case 'php':
        // PHP has many classic vulns
        recommended.push('SqlInjectionGenerator');
        recommended.push('CommandInjectionGenerator');
        recommended.push('PathTraversalGenerator');
        // No prototype pollution
        disabled.push('PrototypePollutionGenerator');
        break;

      case 'csharp':
        // No prototype pollution
        disabled.push('PrototypePollutionGenerator');
        break;
    }

    // Always recommended (universal attacks)
    const universal = [
      'PromptInjectionGenerator',  // MCP-specific, always relevant
      'JsonRpcGenerator',          // Protocol-level
      'SchemaConfusionGenerator',  // Type attacks
      'JwtAttackGenerator',        // JWT is common
      'TimeBasedPayloadGenerator'  // Blind detection
    ];

    for (const gen of universal) {
      if (!recommended.includes(gen) && !disabled.includes(gen)) {
        recommended.push(gen);
      }
    }

    // Fill remaining
    for (const gen of allGenerators) {
      if (!recommended.includes(gen) && !disabled.includes(gen)) {
        recommended.push(gen);
      }
    }

    return { recommended, disabled };
  }

  private generateSummary(
    language: { value: ServerLanguage; confidence: number },
    framework: { value: ServerFramework; confidence: number },
    database: { value: DatabaseType; confidence: number },
    disabled: string[]
  ): string {
    const parts: string[] = [];

    if (language.value !== 'unknown' && language.confidence > 0) {
      parts.push(`Language: ${language.value} (${(language.confidence * 100).toFixed(0)}% confidence)`);
    } else {
      parts.push('Language: Unknown');
    }

    if (framework.value !== 'unknown' && framework.confidence > 0) {
      parts.push(`Framework: ${framework.value} (${(framework.confidence * 100).toFixed(0)}% confidence)`);
    }

    if (database.value !== 'unknown' && database.value !== 'none') {
      parts.push(`Database: ${database.value}`);
    }

    if (disabled.length > 0) {
      parts.push(`Disabled generators: ${disabled.join(', ')}`);
    }

    return parts.join(' | ');
  }

  private stringifyResponse(response: unknown, error?: { code: number; message: string }): string {
    let result = '';

    if (response) {
      try {
        result += typeof response === 'string' ? response : JSON.stringify(response);
      } catch {
        result += String(response);
      }
    }

    if (error) {
      result += ` ${error.message}`;
    }

    return result;
  }

  private extractExcerpt(text: string, pattern: string): string {
    const regex = new RegExp(pattern, 'i');
    const match = text.match(regex);

    if (!match) return '';

    const index = match.index || 0;
    const start = Math.max(0, index - 50);
    const end = Math.min(text.length, index + match[0].length + 50);

    let excerpt = text.substring(start, end);
    if (start > 0) excerpt = '...' + excerpt;
    if (end < text.length) excerpt += '...';

    return excerpt.replace(/\n/g, ' ').trim();
  }

  private generateDeepObject(depth: number): Record<string, unknown> {
    if (depth <= 0) return { value: 'leaf' };
    return { nested: this.generateDeepObject(depth - 1) };
  }

  private isLanguage(detection: string): boolean {
    return ['nodejs', 'python', 'rust', 'go', 'java', 'csharp', 'ruby', 'php'].includes(detection);
  }

  private isFramework(detection: string): boolean {
    return ['fastmcp', 'mcp-sdk-ts', 'mcp-sdk-py', 'express', 'fastify', 'flask', 'django', 'actix', 'axum', 'gin', 'echo', 'spring'].includes(detection);
  }

  private isDatabase(detection: string): boolean {
    return ['postgresql', 'mysql', 'sqlite', 'mongodb', 'redis'].includes(detection);
  }

  /**
   * Get a quick fingerprint (fewer probes, faster)
   */
  async quickFingerprint(target: FuzzTarget, toolName: string): Promise<ServerFingerprint> {
    // Use only first 3 probes for speed
    const originalProbes = [...this.probes];
    (this as unknown as { probes: GeneratedPayload[] }).probes = originalProbes.slice(0, 3);

    try {
      return await this.fingerprint(target, toolName);
    } finally {
      (this as unknown as { probes: GeneratedPayload[] }).probes = originalProbes;
    }
  }
}
