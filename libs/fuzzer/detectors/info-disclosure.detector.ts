/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Information Disclosure Detector
 *
 * Detects sensitive information leakage in server responses including:
 * - Stack traces and debug information
 * - API keys, tokens, and secrets
 * - Server/framework version disclosure
 * - Internal paths and configuration
 * - Database connection strings
 * - Cloud credentials
 *
 * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 * CWE-209: Generation of Error Message Containing Sensitive Information
 */

import {
  IVulnerabilityDetector,
  DetectorContext,
  DetectionResult,
  DetectionSeverity,
  DetectionConfidence
} from './detector.interface';

interface DisclosurePattern {
  pattern: RegExp;
  type: string;
  severity: DetectionSeverity;
  description: string;
  cwe?: string;
}

export interface InfoDisclosureConfig {
  /** Enable detection of stack traces */
  detectStackTraces?: boolean;
  /** Enable detection of API keys/secrets */
  detectSecrets?: boolean;
  /** Enable detection of server info */
  detectServerInfo?: boolean;
  /** Enable detection of internal paths */
  detectInternalPaths?: boolean;
  /** Custom patterns to detect */
  customPatterns?: DisclosurePattern[];
}

export class InformationDisclosureDetector implements IVulnerabilityDetector {
  readonly id = 'info-disclosure';
  readonly name = 'Information Disclosure Detector';
  readonly description = 'Detects sensitive information leakage in responses (CWE-200, CWE-209)';
  readonly categories = ['information-disclosure', 'security'];
  readonly enabledByDefault = true;

  private config: Required<InfoDisclosureConfig>;

  constructor(config: InfoDisclosureConfig = {}) {
    this.config = {
      detectStackTraces: config.detectStackTraces ?? true,
      detectSecrets: config.detectSecrets ?? true,
      detectServerInfo: config.detectServerInfo ?? true,
      detectInternalPaths: config.detectInternalPaths ?? true,
      customPatterns: config.customPatterns ?? []
    };
  }

  // ==================== PATTERN DEFINITIONS ====================

  /**
   * Stack trace patterns for various languages/runtimes
   */
  private readonly stackTracePatterns: DisclosurePattern[] = [
    // Node.js / JavaScript
    {
      pattern: /at\s+[\w$.]+\s+\([^)]+:\d+:\d+\)/,
      type: 'nodejs-stack-trace',
      severity: 'high',
      description: 'Node.js stack trace exposed',
      cwe: 'CWE-209'
    },
    {
      pattern: /at\s+(?:Object|Function|Module)\.<anonymous>\s+\([^)]+\)/,
      type: 'nodejs-stack-trace',
      severity: 'high',
      description: 'Node.js anonymous function stack trace',
      cwe: 'CWE-209'
    },
    // Python
    {
      pattern: /Traceback \(most recent call last\)/i,
      type: 'python-traceback',
      severity: 'high',
      description: 'Python traceback exposed',
      cwe: 'CWE-209'
    },
    {
      pattern: /File "([^"]+)", line \d+, in \w+/,
      type: 'python-traceback',
      severity: 'high',
      description: 'Python file path and line number exposed',
      cwe: 'CWE-209'
    },
    // Java
    {
      pattern: /at\s+[\w.$]+\([\w]+\.java:\d+\)/,
      type: 'java-stack-trace',
      severity: 'high',
      description: 'Java stack trace exposed',
      cwe: 'CWE-209'
    },
    {
      pattern: /java\.(lang|io|util|sql)\.\w+Exception/,
      type: 'java-exception',
      severity: 'medium',
      description: 'Java exception class exposed',
      cwe: 'CWE-209'
    },
    // .NET / C#
    {
      pattern: /at\s+[\w.]+\s+in\s+[A-Za-z]:\\[^:]+:\s*line\s+\d+/,
      type: 'dotnet-stack-trace',
      severity: 'high',
      description: '.NET stack trace with file path exposed',
      cwe: 'CWE-209'
    },
    {
      pattern: /System\.(IO|Data|Net|Web)\.\w+Exception/,
      type: 'dotnet-exception',
      severity: 'medium',
      description: '.NET exception class exposed',
      cwe: 'CWE-209'
    },
    // PHP
    {
      pattern: /Stack trace:[\s\S]*?#\d+\s+[^\n]+/,
      type: 'php-stack-trace',
      severity: 'high',
      description: 'PHP stack trace exposed',
      cwe: 'CWE-209'
    },
    {
      pattern: /Fatal error:.*in\s+\/[^\s]+\s+on line\s+\d+/i,
      type: 'php-fatal-error',
      severity: 'high',
      description: 'PHP fatal error with file path',
      cwe: 'CWE-209'
    },
    // Ruby
    {
      pattern: /from\s+\/[^:]+:\d+:in\s+`[^']+'/,
      type: 'ruby-backtrace',
      severity: 'high',
      description: 'Ruby backtrace exposed',
      cwe: 'CWE-209'
    },
    // Go
    {
      pattern: /goroutine\s+\d+\s+\[running\]:/,
      type: 'golang-panic',
      severity: 'high',
      description: 'Go panic/goroutine dump exposed',
      cwe: 'CWE-209'
    },
    // Generic
    {
      pattern: /ENOENT|EACCES|EPERM|ECONNREFUSED/,
      type: 'system-error-code',
      severity: 'medium',
      description: 'System error code exposed',
      cwe: 'CWE-209'
    }
  ];

  /**
   * API keys, tokens, and secrets patterns
   */
  private readonly secretPatterns: DisclosurePattern[] = [
    // AWS
    {
      pattern: /AKIA[0-9A-Z]{16}/,
      type: 'aws-access-key',
      severity: 'critical',
      description: 'AWS Access Key ID exposed',
      cwe: 'CWE-798'
    },
    {
      pattern: /aws[_-]?secret[_-]?access[_-]?key['":\s]*['"]?([A-Za-z0-9/+=]{40})/i,
      type: 'aws-secret-key',
      severity: 'critical',
      description: 'AWS Secret Access Key exposed',
      cwe: 'CWE-798'
    },
    // Google Cloud
    {
      pattern: /AIza[0-9A-Za-z_-]{35}/,
      type: 'google-api-key',
      severity: 'critical',
      description: 'Google API Key exposed',
      cwe: 'CWE-798'
    },
    // GitHub
    {
      pattern: /ghp_[0-9a-zA-Z]{36}/,
      type: 'github-pat',
      severity: 'critical',
      description: 'GitHub Personal Access Token exposed',
      cwe: 'CWE-798'
    },
    {
      pattern: /github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}/,
      type: 'github-fine-grained-pat',
      severity: 'critical',
      description: 'GitHub Fine-Grained PAT exposed',
      cwe: 'CWE-798'
    },
    // Slack
    {
      pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/,
      type: 'slack-token',
      severity: 'critical',
      description: 'Slack Token exposed',
      cwe: 'CWE-798'
    },
    // Stripe
    {
      pattern: /sk_live_[0-9a-zA-Z]{24,}/,
      type: 'stripe-secret-key',
      severity: 'critical',
      description: 'Stripe Secret Key exposed',
      cwe: 'CWE-798'
    },
    {
      pattern: /rk_live_[0-9a-zA-Z]{24,}/,
      type: 'stripe-restricted-key',
      severity: 'critical',
      description: 'Stripe Restricted Key exposed',
      cwe: 'CWE-798'
    },
    // Generic patterns
    {
      pattern: /api[_-]?key['":\s]*['"]?([a-zA-Z0-9_-]{20,})['"]/i,
      type: 'generic-api-key',
      severity: 'high',
      description: 'API key pattern detected',
      cwe: 'CWE-798'
    },
    {
      pattern: /secret[_-]?key['":\s]*['"]?([a-zA-Z0-9_-]{20,})['"]/i,
      type: 'generic-secret',
      severity: 'high',
      description: 'Secret key pattern detected',
      cwe: 'CWE-798'
    },
    {
      pattern: /password['":\s]*['"]?([^\s'"]{8,})['"]/i,
      type: 'password-in-response',
      severity: 'critical',
      description: 'Password exposed in response',
      cwe: 'CWE-200'
    },
    {
      pattern: /bearer\s+([a-zA-Z0-9_.-]{20,})/i,
      type: 'bearer-token',
      severity: 'high',
      description: 'Bearer token exposed',
      cwe: 'CWE-200'
    },
    // Database connection strings
    {
      pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s'"]+/i,
      type: 'mongodb-connection-string',
      severity: 'critical',
      description: 'MongoDB connection string with credentials',
      cwe: 'CWE-798'
    },
    {
      pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s'"]+/i,
      type: 'postgresql-connection-string',
      severity: 'critical',
      description: 'PostgreSQL connection string with credentials',
      cwe: 'CWE-798'
    },
    {
      pattern: /mysql:\/\/[^:]+:[^@]+@[^\s'"]+/i,
      type: 'mysql-connection-string',
      severity: 'critical',
      description: 'MySQL connection string with credentials',
      cwe: 'CWE-798'
    },
    // Private keys
    {
      pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
      type: 'private-key',
      severity: 'critical',
      description: 'Private key exposed',
      cwe: 'CWE-321'
    },
    {
      pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/,
      type: 'ssh-private-key',
      severity: 'critical',
      description: 'SSH private key exposed',
      cwe: 'CWE-321'
    }
  ];

  /**
   * Server and framework disclosure patterns
   */
  private readonly serverInfoPatterns: DisclosurePattern[] = [
    // Server headers in response body
    {
      pattern: /X-Powered-By['":\s]*['"]?([\w./-]+)/i,
      type: 'x-powered-by',
      severity: 'low',
      description: 'X-Powered-By header disclosed',
      cwe: 'CWE-200'
    },
    {
      pattern: /Server['":\s]*['"]?(Apache|nginx|IIS|Express|Kestrel)[^\s'"]*/i,
      type: 'server-header',
      severity: 'low',
      description: 'Server type disclosed',
      cwe: 'CWE-200'
    },
    // Framework versions
    {
      pattern: /Express\s*\/?\s*(\d+\.\d+\.\d+)/i,
      type: 'express-version',
      severity: 'medium',
      description: 'Express.js version disclosed',
      cwe: 'CWE-200'
    },
    {
      pattern: /Django\s*\/?\s*(\d+\.\d+)/i,
      type: 'django-version',
      severity: 'medium',
      description: 'Django version disclosed',
      cwe: 'CWE-200'
    },
    {
      pattern: /Laravel\s*\/?\s*(\d+\.\d+)/i,
      type: 'laravel-version',
      severity: 'medium',
      description: 'Laravel version disclosed',
      cwe: 'CWE-200'
    },
    {
      pattern: /Rails\s*\/?\s*(\d+\.\d+)/i,
      type: 'rails-version',
      severity: 'medium',
      description: 'Rails version disclosed',
      cwe: 'CWE-200'
    },
    // Debug mode indicators
    {
      pattern: /DEBUG\s*[=:]\s*true|debug[_-]?mode['":\s]*['"]?true/i,
      type: 'debug-mode-enabled',
      severity: 'high',
      description: 'Debug mode appears to be enabled',
      cwe: 'CWE-489'
    },
    {
      pattern: /NODE_ENV['":\s]*['"]?development/i,
      type: 'development-environment',
      severity: 'medium',
      description: 'Development environment detected',
      cwe: 'CWE-489'
    }
  ];

  /**
   * Internal path and configuration disclosure patterns
   */
  private readonly internalPathPatterns: DisclosurePattern[] = [
    // Absolute paths
    {
      pattern: /\/home\/[\w-]+\/[^\s'"]+/,
      type: 'unix-home-path',
      severity: 'medium',
      description: 'Unix home directory path exposed',
      cwe: 'CWE-200'
    },
    {
      pattern: /\/var\/(www|log|lib)\/[^\s'"]+/,
      type: 'unix-system-path',
      severity: 'medium',
      description: 'Unix system path exposed',
      cwe: 'CWE-200'
    },
    {
      pattern: /[A-Z]:\\(Users|Program Files|Windows)\\[^\s'"]+/i,
      type: 'windows-path',
      severity: 'medium',
      description: 'Windows file path exposed',
      cwe: 'CWE-200'
    },
    {
      pattern: /\/app\/[^\s'"]+|\/opt\/[^\s'"]+/,
      type: 'container-path',
      severity: 'low',
      description: 'Container/deployment path exposed',
      cwe: 'CWE-200'
    },
    // Internal IPs
    {
      pattern: /(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/,
      type: 'internal-ip',
      severity: 'medium',
      description: 'Internal IP address exposed',
      cwe: 'CWE-200'
    },
    // Internal hostnames
    {
      pattern: /(?:localhost|127\.0\.0\.1|::1):\d+/,
      type: 'localhost-reference',
      severity: 'low',
      description: 'Localhost reference exposed',
      cwe: 'CWE-200'
    },
    // Environment variables
    {
      pattern: /process\.env\.(\w+)/,
      type: 'env-var-reference',
      severity: 'medium',
      description: 'Environment variable reference exposed',
      cwe: 'CWE-200'
    },
    // SQL queries
    {
      pattern: /SELECT\s+.+\s+FROM\s+[\w.]+\s+WHERE/i,
      type: 'sql-query-exposed',
      severity: 'high',
      description: 'SQL query structure exposed',
      cwe: 'CWE-200'
    },
    // Configuration dumps
    {
      pattern: /"config":\s*\{[^}]*"(database|db|secret|key|password)"/i,
      type: 'config-dump',
      severity: 'high',
      description: 'Configuration object with sensitive fields exposed',
      cwe: 'CWE-200'
    }
  ];

  isApplicable(_category: string): boolean {
    // This detector should run on all responses - it's observational
    return true;
  }

  detect(context: DetectorContext): DetectionResult {
    const responseStr = this.stringifyResponse(context.response);
    const errorStr = context.error?.message || '';
    const combinedContent = `${responseStr} ${errorStr}`;

    const findings: Array<{
      pattern: DisclosurePattern;
      match: string;
    }> = [];

    // Check stack traces
    if (this.config.detectStackTraces) {
      for (const pattern of this.stackTracePatterns) {
        const match = combinedContent.match(pattern.pattern);
        if (match) {
          findings.push({ pattern, match: match[0] });
        }
      }
    }

    // Check secrets
    if (this.config.detectSecrets) {
      for (const pattern of this.secretPatterns) {
        const match = combinedContent.match(pattern.pattern);
        if (match) {
          findings.push({ pattern, match: this.redactSecret(match[0]) });
        }
      }
    }

    // Check server info
    if (this.config.detectServerInfo) {
      for (const pattern of this.serverInfoPatterns) {
        const match = combinedContent.match(pattern.pattern);
        if (match) {
          findings.push({ pattern, match: match[0] });
        }
      }
    }

    // Check internal paths
    if (this.config.detectInternalPaths) {
      for (const pattern of this.internalPathPatterns) {
        const match = combinedContent.match(pattern.pattern);
        if (match) {
          findings.push({ pattern, match: match[0] });
        }
      }
    }

    // Check custom patterns
    for (const pattern of this.config.customPatterns) {
      const match = combinedContent.match(pattern.pattern);
      if (match) {
        findings.push({ pattern, match: match[0] });
      }
    }

    if (findings.length === 0) {
      return this.createEmptyResult();
    }

    // Determine overall severity (use highest)
    const severityOrder: Record<DetectionSeverity, number> = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4
    };
    const highestSeverity = findings.reduce((max, f) => {
      return severityOrder[f.pattern.severity] > severityOrder[max]
        ? f.pattern.severity
        : max;
    }, 'low' as DetectionSeverity);

    // Determine confidence based on number and type of findings
    const confidence: DetectionConfidence = findings.length > 2
      ? 'high'
      : findings.some(f => f.pattern.severity === 'critical')
        ? 'high'
        : 'medium';

    // Group findings by type
    const findingTypes = [...new Set(findings.map(f => f.pattern.type))];
    const descriptions = findings
      .slice(0, 5) // Limit to 5 for readability
      .map(f => f.pattern.description);

    return {
      detectorId: this.id,
      detected: true,
      vulnerabilityType: 'Information Disclosure',
      severity: highestSeverity,
      confidence,
      description: `Sensitive information exposed: ${descriptions.join('; ')}`,
      evidence: {
        payload: context.payload,
        response: this.truncateResponse(context.response),
        matchedPatterns: findingTypes
      },
      remediation: this.generateRemediation(findings),
      cweId: this.getPrimaryCwe(findings),
      owaspCategory: 'A01:2021-Broken Access Control'
    };
  }

  private createEmptyResult(): DetectionResult {
    return {
      detectorId: this.id,
      detected: false,
      vulnerabilityType: 'Information Disclosure',
      severity: 'low',
      confidence: 'low',
      description: 'No sensitive information disclosure detected',
      evidence: {
        payload: '',
        response: null
      }
    };
  }

  private stringifyResponse(response: unknown): string {
    if (typeof response === 'string') return response;
    try {
      return JSON.stringify(response);
    } catch {
      return String(response);
    }
  }

  private truncateResponse(response: unknown): unknown {
    const str = this.stringifyResponse(response);
    if (str.length > 500) {
      return str.substring(0, 500) + '... [truncated]';
    }
    return response;
  }

  private redactSecret(secret: string): string {
    // Keep first 4 and last 4 characters, redact middle
    if (secret.length <= 12) {
      return secret.substring(0, 4) + '****';
    }
    return secret.substring(0, 4) + '****' + secret.substring(secret.length - 4);
  }

  private generateRemediation(findings: Array<{ pattern: DisclosurePattern }>): string {
    const types = [...new Set(findings.map(f => f.pattern.type))];
    const remedations: string[] = [];

    if (types.some(t => t.includes('stack-trace') || t.includes('traceback') || t.includes('exception'))) {
      remedations.push('Implement proper error handling that returns generic error messages to clients');
    }
    if (types.some(t => t.includes('key') || t.includes('secret') || t.includes('token') || t.includes('password'))) {
      remedations.push('Never expose credentials in responses. Use environment variables and secrets managers');
    }
    if (types.some(t => t.includes('path') || t.includes('internal-ip'))) {
      remedations.push('Sanitize responses to remove internal paths and network information');
    }
    if (types.some(t => t.includes('debug') || t.includes('development'))) {
      remedations.push('Ensure debug mode is disabled in production environments');
    }
    if (types.some(t => t.includes('version') || t.includes('server') || t.includes('powered'))) {
      remedations.push('Remove or obfuscate server version headers');
    }

    return remedations.join('. ') || 'Review and sanitize all error messages and responses for sensitive data';
  }

  private getPrimaryCwe(findings: Array<{ pattern: DisclosurePattern }>): string {
    // Find the most severe CWE
    const cwePriority = ['CWE-321', 'CWE-798', 'CWE-209', 'CWE-489', 'CWE-200'];
    for (const cwe of cwePriority) {
      if (findings.some(f => f.pattern.cwe === cwe)) {
        return cwe;
      }
    }
    return 'CWE-200';
  }
}
