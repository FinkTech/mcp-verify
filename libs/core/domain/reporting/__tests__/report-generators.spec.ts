/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { SarifGenerator } from '../sarif-generator';
import { HtmlReportGenerator } from '../html-generator';
import { Report } from '../../mcp-server/entities/validation.types';

describe('Report Generators Smoke Test', () => {
    const mockReport: Report = {
        server_name: 'test-server',
        url: 'stdio://test',
        status: 'valid',
        protocol_version: '2024-11-05',
        duration_ms: 100,
        timestamp: new Date().toISOString(),
        tools: {
            count: 1,
            valid: 1,
            invalid: 0,
            items: [{
                name: 'test-tool',
                description: 'A test tool',
                inputSchema: { type: 'object' },
                status: 'valid'
            }]
        },
        resources: { count: 0, valid: 0, invalid: 0, items: [] },
        prompts: { count: 0, valid: 0, invalid: 0, items: [] },
        security: {
            score: 95,
            // Fixed: Must be one of 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical Risk'
            level: 'Low Risk',
            findings: [
                {
                    ruleCode: 'SEC-001',
                    severity: 'medium',
                    message: 'Test finding',
                    component: 'test-tool',
                    remediation: 'Fix it'
                }
            ]
        },
        quality: {
            score: 100,
            issues: []
        },
        protocolCompliance: {
            passed: true,
            score: 100,
            issues: [],
            testsPassed: 10,
            testsFailed: 0,
            totalTests: 10
        }
    };

    describe('SarifGenerator', () => {
        it('should generate valid JSON SARIF output', () => {
            const output = SarifGenerator.generate(mockReport);
            expect(output).toBeDefined();

            const parsed = JSON.parse(output);
            expect(parsed.$schema).toContain('sarif');
            expect(parsed.runs).toHaveLength(1);
            expect(parsed.runs[0].tool.driver.name).toBe('mcp-verify');
            expect(parsed.runs[0].results).toHaveLength(1);
            expect(parsed.runs[0].results[0].ruleId).toBe('SEC-001');
        });
    });

    describe('HtmlReportGenerator', () => {
        it('should generate HTML with correct title and structure', () => {
            const output = HtmlReportGenerator.generate(mockReport, 'en');
            expect(output).toBeDefined();
            expect(output).toContain('<!DOCTYPE html>');
            expect(output).toContain('mcp-verify');
            expect(output).toContain('test-server');
            expect(output).toContain('95'); // Security score
        });

        it('should support spanish language', () => {
            const output = HtmlReportGenerator.generate(mockReport, 'es');
            // Check for lang attribute instead of specific title to be robust
            expect(output).toContain('lang="es"');
        });
    });
});
