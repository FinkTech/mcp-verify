/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-003: SQL Injection Detection Test
 *
 * Verifies that the validate command detects SQL injection vulnerabilities
 * in MCP server tool descriptions and input schemas.
 *
 * Test Strategy:
 * 1. Start configurable vulnerable server with 'sql-injection' profile
 * 2. Run validate command programmatically
 * 3. Parse generated JSON report
 * 4. Assert SEC-003 finding is present
 * 5. Verify severity is HIGH or CRITICAL
 * 6. Clean up server and report files
 */

import * as path from 'path';
import * as fs from 'fs';
import { runValidationAction } from '../../../apps/cli-verifier/src/commands/validate';
import { TestServerManager } from '../helpers/test-server-manager';

describe('SEC-003: SQL Injection Detection', () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(__dirname, '../../__test-reports__/sec-003');

  beforeAll(async () => {
    serverManager = new TestServerManager();
    await serverManager.start({
      profile: 'sql-injection',
      lang: 'en',
      transport: 'stdio',
      timeout: 30000,
    });

    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    await serverManager.stop();

    if (fs.existsSync(testReportDir)) {
      fs.rmSync(testReportDir, { recursive: true, force: true });
    }
  });

  it('should detect SQL injection vulnerability (SEC-003) via validate command', async () => {
    const target = serverManager.getTarget();

    const exitCode = await runValidationAction(target, {
      output: testReportDir,
      format: 'json',
      lang: 'en',
      quiet: true,
      html: false,
    });

    expect([0, 2]).toContain(exitCode);

    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    expect(fs.existsSync(jsonReportPath)).toBe(true);

    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    expect(reportFiles.length).toBeGreaterThan(0);

    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8');
    const report = JSON.parse(reportContent);

    expect(report).toHaveProperty('security');
    expect(report.security).toHaveProperty('findings');
    expect(Array.isArray(report.security.findings)).toBe(true);

    const sqliFinding = report.security.findings.find(
      (f: any) => f.ruleCode === 'SEC-003'
    );

    expect(sqliFinding).toBeDefined();
    expect(sqliFinding.ruleCode).toBe('SEC-003');
    expect(sqliFinding.severity).toMatch(/high|critical/i);
    expect(sqliFinding.message.toLowerCase()).toMatch(/sql|injection|query/);

    if (sqliFinding) {
      console.log('\n✓ SEC-003 detected:', sqliFinding.message);
    }
  });

  it('should detect SQL injection pattern in tool description', async () => {
    const target = serverManager.getTarget();

    const exitCode = await runValidationAction(target, {
      output: testReportDir,
      format: 'json',
      lang: 'en',
      quiet: true,
      html: false,
    });

    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8');
    const report = JSON.parse(reportContent);

    expect(report.tools).toHaveProperty('items');
    const executeSqlTool = report.tools.items.find((t: any) => t.name === 'execute_sql');

    expect(executeSqlTool).toBeDefined();
    expect(executeSqlTool.description.toLowerCase()).toMatch(/sql|query|select/);

    console.log('\n✓ Vulnerable tool discovered:', executeSqlTool.name);
  });

  it('should calculate security score penalty for SQL injection', async () => {
    const target = serverManager.getTarget();

    const exitCode = await runValidationAction(target, {
      output: testReportDir,
      format: 'json',
      lang: 'en',
      quiet: true,
      html: false,
    });

    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8');
    const report = JSON.parse(reportContent);

    expect(report.security).toHaveProperty('score');
    expect(report.security.score).toBeLessThan(100);

    const criticalOrHighCount = report.security.findings.filter(
      (f: any) => f.severity === 'critical' || f.severity === 'high'
    ).length;

    if (criticalOrHighCount > 0) {
      expect(report.security.score).toBeLessThan(70);
    }

    console.log('\n✓ Security score:', report.security.score);
    console.log('✓ Security level:', report.security.level);
  });
});
