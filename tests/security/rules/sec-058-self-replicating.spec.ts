/**
 * Copyright (c) 2026 FinkTech
 * SEC-058: Self-Replicating MCP Detection Test
 */

import * as path from 'path';
import * as fs from 'fs';
import { runValidationAction } from '../../../apps/cli-verifier/src/commands/validate';
import { TestServerManager } from '../helpers/test-server-manager';

describe('SEC-058: Self-Replicating MCP Detection', () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(__dirname, '../../__test-reports__/sec-058');

  beforeAll(async () => {
    serverManager = new TestServerManager();
    await serverManager.start({ profile: 'self-replicating', lang: 'en', transport: 'stdio', timeout: 30000 });
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    await serverManager.stop();
    if (fs.existsSync(testReportDir)) fs.rmSync(testReportDir, { recursive: true, force: true });
  });

  it('should detect self-replicating mcp (SEC-058)', async () => {
    const target = serverManager.getTarget();
    await runValidationAction(target, { output: testReportDir, format: 'json', lang: 'en', quiet: true, html: false });

    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const report = JSON.parse(fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8'));

    const finding = report.security.findings.find((f: any) => f.ruleCode === 'SEC-058');
    expect(finding).toBeDefined();
    expect(finding.severity).toMatch(/high|critical|medium|low/i);
    expect(finding.message).toBeDefined();
    expect(typeof finding.message).toBe('string');
    expect(finding.message.length).toBeGreaterThan(0);
    console.log('\n✓ SEC-058 detected:', finding.message);
  });
});
