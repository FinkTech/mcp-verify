/**
 * Copyright (c) 2026 FinkTech
 * SEC-055: Insecure Default Configuration Detection Test
 */

import * as path from 'path';
import * as fs from 'fs';
import { runValidationAction } from '../../../apps/cli-verifier/src/commands/validate';
import { TestServerManager } from '../helpers/test-server-manager';

describe('SEC-055: Insecure Default Configuration Detection', () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(__dirname, '../../__test-reports__/sec-055');

  beforeAll(async () => {
    serverManager = new TestServerManager();
    await serverManager.start({ profile: 'insecure-defaults', lang: 'en', transport: 'stdio', timeout: 30000 });
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    await serverManager.stop();
    if (fs.existsSync(testReportDir)) fs.rmSync(testReportDir, { recursive: true, force: true });
  });

  it('should detect insecure default configuration (SEC-055)', async () => {
    const target = serverManager.getTarget();
    await runValidationAction(target, { output: testReportDir, format: 'json', lang: 'en', quiet: true, html: false });

    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const report = JSON.parse(fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8'));

    const finding = report.security.findings.find((f: any) => f.ruleCode === 'SEC-055');
    expect(finding).toBeDefined();
    expect(finding.severity).toMatch(/high|critical|medium/i);
    expect(finding.message.toLowerCase()).toMatch(/default|insecure|debug|cors.*\*/);
    console.log('\n✓ SEC-055 detected:', finding.message);
  });
});
