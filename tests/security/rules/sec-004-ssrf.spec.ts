/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-004: SSRF Detection Test
 *
 * Verifies that the validate command detects Server-Side Request Forgery (SSRF)
 * vulnerabilities in MCP server tool descriptions.
 *
 * Test Strategy:
 * 1. Start configurable vulnerable server with 'ssrf' profile
 * 2. Run validate command programmatically
 * 3. Parse generated JSON report
 * 4. Assert SEC-004 finding is present
 * 5. Verify severity is HIGH or CRITICAL
 * 6. Clean up server and report files
 */

import * as path from 'path';
import * as fs from 'fs';
import { runValidationAction } from '../../../apps/cli-verifier/src/commands/validate';
import { TestServerManager } from '../helpers/test-server-manager';

describe('SEC-004: SSRF Detection', () => {
  let serverManager: TestServerManager;
  const testReportDir = path.resolve(__dirname, '../../__test-reports__/sec-004');

  beforeAll(async () => {
    // Start vulnerable test server with SSRF profile
    serverManager = new TestServerManager();
    await serverManager.start({
      profile: 'ssrf',
      lang: 'en',
      transport: 'stdio',
      timeout: 30000,
    });

    // Ensure test report directory exists
    fs.mkdirSync(testReportDir, { recursive: true });
  });

  afterAll(async () => {
    // Stop server gracefully
    await serverManager.stop();

    // Clean up test reports (optional - comment out for debugging)
    if (fs.existsSync(testReportDir)) {
      fs.rmSync(testReportDir, { recursive: true, force: true });
    }
  });

  it('should detect SSRF vulnerability (SEC-004) via validate command', async () => {
    // Get target string for validation
    const target = serverManager.getTarget();

    // Run validation programmatically
    const exitCode = await runValidationAction(target, {
      output: testReportDir,
      format: 'json',
      lang: 'en',
      quiet: true, // Suppress spinner output
      html: false, // Skip HTML report generation
    });

    // Validation should succeed (server is reachable), but report should contain findings
    // Exit code 2 indicates critical security findings were detected
    expect([0, 2]).toContain(exitCode);

    // Load generated JSON report
    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    expect(fs.existsSync(jsonReportPath)).toBe(true);

    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    expect(reportFiles.length).toBeGreaterThan(0);

    const latestReport = reportFiles.sort().reverse()[0]; // Get most recent report
    const reportContent = fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8');
    const report = JSON.parse(reportContent);

    // Verify report structure
    expect(report).toHaveProperty('security');
    expect(report.security).toHaveProperty('findings');
    expect(Array.isArray(report.security.findings)).toBe(true);

    // Find SEC-004 finding
    const ssrfFinding = report.security.findings.find(
      (f: any) => f.ruleCode === 'SEC-004'
    );

    expect(ssrfFinding).toBeDefined();
    expect(ssrfFinding.ruleCode).toBe('SEC-004');
    expect(ssrfFinding.severity).toMatch(/high|critical/i);

    // Verify the finding mentions SSRF or internal network access
    expect(ssrfFinding.message.toLowerCase()).toMatch(/url input without validation|ssrf|server-side request forgery|internal network|localhost|192\.168/);

    // Log finding for debugging
    if (ssrfFinding) {
      console.log('\n✓ SEC-004 detected:', ssrfFinding.message);
    }
  });

  it('should detect SSRF in tool description containing internal IP patterns', async () => {
    const target = serverManager.getTarget();

    const exitCode = await runValidationAction(target, {
      output: testReportDir,
      format: 'json',
      lang: 'en',
      quiet: true,
      html: false,
    });

    // Load report
    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8');
    const report = JSON.parse(reportContent);

    // Verify that the vulnerable tool 'fetch_url' was discovered
    expect(report.tools).toHaveProperty('items');
    const fetchUrlTool = report.tools.items.find((t: any) => t.name === 'fetch_url');

    expect(fetchUrlTool).toBeDefined();
    expect(fetchUrlTool.description.toLowerCase()).toMatch(/internal|localhost|192\.168|private/);

    console.log('\n✓ Vulnerable tool discovered:', fetchUrlTool.name);
  });

  it('should calculate security score based on SSRF findings', async () => {
    const target = serverManager.getTarget();

    const exitCode = await runValidationAction(target, {
      output: testReportDir,
      format: 'json',
      lang: 'en',
      quiet: true,
      html: false,
    });

    // Load report
    const dateStr = new Date().toISOString().split('T')[0];
    const jsonReportPath = path.join(testReportDir, dateStr, 'validate', 'json', 'en');
    const reportFiles = fs.readdirSync(jsonReportPath).filter(f => f.startsWith('mcp-report-') && f.endsWith('.json'));
    const latestReport = reportFiles.sort().reverse()[0];
    const reportContent = fs.readFileSync(path.join(jsonReportPath, latestReport), 'utf8');
    const report = JSON.parse(reportContent);

    // Security score should be penalized for SSRF vulnerability
    expect(report.security).toHaveProperty('score');
    expect(report.security.score).toBeLessThan(100);

    // If HIGH/CRITICAL findings exist, score should be significantly reduced
    const criticalOrHighCount = report.security.findings.filter(
      (f: any) => f.severity === 'critical' || f.severity === 'high'
    ).length;

    if (criticalOrHighCount > 0) {
      expect(report.security.score).toBeLessThan(70); // Significant penalty
    }

    console.log('\n✓ Security score:', report.security.score);
    console.log('✓ Security level:', report.security.level);
  });
});

