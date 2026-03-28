/**
 * Copyright (c) 2026 FinkTech
 * SEC-020: Prompt Injection Detection Test (Static Validation)
 */

import * as path from 'path';
import * as fs from 'fs';
import { runValidationAction } from '../../../apps/cli-verifier/src/commands/validate';
import { TestServerManager } from '../helpers/test-server-manager';

describe('SEC-020: Prompt Injection Detection (Static)', () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(__dirname, '../../__test-reports__/sec-020');

  beforeAll(async () => {
    serverManager = new TestServerManager();
    await serverManager.start({ profile: 'prompt-injection', lang: 'en', transport: 'stdio', timeout: 30000 });
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    await serverManager.stop();
    if (fs.existsSync(testReportDir)) fs.rmSync(testReportDir, { recursive: true, force: true });
  });

  it('should detect prompt injection vulnerability (SEC-020)', async () => {
    const target = serverManager.getTarget();
    await runValidationAction(target, { output: testReportDir, format: 'json', lang: 'en', quiet: true, html: false });

    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const report = JSON.parse(fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8'));

    const finding = report.security.findings.find((f: any) => f.ruleCode === 'SEC-020');
    expect(finding).toBeDefined();
    expect(finding.severity).toMatch(/high|critical/i);
    expect(finding.message.toLowerCase()).toMatch(/prompt|injection|llm|sanitiz/);
    console.log('\n✓ SEC-020 detected:', finding.message);
  });
});
