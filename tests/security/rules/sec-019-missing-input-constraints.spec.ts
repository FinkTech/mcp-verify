/**
 * Copyright (c) 2026 FinkTech
 * SEC-019: Missing Input Constraints Detection Test
 */

import * as path from 'path';
import * as fs from 'fs';
import { runValidationAction } from '../../../apps/cli-verifier/src/commands/validate';
import { TestServerManager } from '../helpers/test-server-manager';

// Note: Test timeout is globally managed in jest.config.js
describe('SEC-019: Missing Input Constraints Detection', () => {
  const baseTestReportDir = path.resolve(__dirname, '../../__test-reports__/sec-019');

  // Cleanup logs from previous runs
  beforeAll(() => {
    if (fs.existsSync(baseTestReportDir)) {
      fs.rmSync(baseTestReportDir, { recursive: true, force: true });
    }
    fs.mkdirSync(baseTestReportDir, { recursive: true });
  });

  /**
   * Positive Test Case: Ensure the rule DETECTS the vulnerability
   * when the server profile is misconfigured.
   */
  it('should detect missing input constraints on a vulnerable server (SEC-019)', async () => {
    const serverManager = new TestServerManager();
    const testReportDir = path.join(baseTestReportDir, 'positive');
    fs.mkdirSync(testReportDir, { recursive: true });

    let finding;
    try {
      await serverManager.start({ profile: 'missing-input-constraints', lang: 'en', transport: 'stdio', timeout: 30000 });
      const target = serverManager.getTarget();
      await runValidationAction(target, { output: testReportDir, format: 'json', lang: 'en', quiet: true, html: false });

      const dateStr = new Date().toISOString().split('T')[0];
      const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
      const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
      const latestReport = reportFiles.sort().reverse()[0];
      const report = JSON.parse(fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8'));

      finding = report.security.findings.find((f: any) => f.ruleCode === 'SEC-019');
    } finally {
      await serverManager.stop();
    }

    expect(finding).toBeDefined();
    expect(finding.severity).toMatch(/high|critical|medium|low/i);
    expect(finding.message).toMatch(/Parameter data in tool process_data lacks maxLength constraint/);
    console.log('SEC-019 Positive case passed:', finding.message);
  });

  /**
   * Negative Test Case: Ensure the rule DOES NOT fire
   * when the server profile is correctly configured with constraints.
   */
  it('should NOT detect missing input constraints on a secure server', async () => {
    const serverManager = new TestServerManager();
    const testReportDir = path.join(baseTestReportDir, 'negative');
    fs.mkdirSync(testReportDir, { recursive: true });
    
    let finding;
    try {
      await serverManager.start({ profile: 'input-constraints-ok', lang: 'en', transport: 'stdio', timeout: 30000 });
      const target = serverManager.getTarget();
      await runValidationAction(target, { output: testReportDir, format: 'json', lang: 'en', quiet: true, html: false });

      const dateStr = new Date().toISOString().split('T')[0];
      const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
      const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
      
      // If a report is generated, check its contents
      if (reportFiles.length > 0) {
        const latestReport = reportFiles.sort().reverse()[0];
        const report = JSON.parse(fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8'));
        finding = report.security.findings.find((f: any) => f.ruleCode === 'SEC-019');
      }
    } finally {
      await serverManager.stop();
    }

    expect(finding).toBeUndefined();
    console.log('SEC-019 Negative case passed: No finding reported.');
  });
});
