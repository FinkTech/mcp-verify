/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * XXE Injection Rule Tests (SEC-005)
 * 
 * Tests for XML External Entity vulnerability detection.
 */

import { XXEInjectionRule } from './xxe-injection.rule';
import { DiscoveryResult } from '../../mcp-server/entities/validation.types';

describe('XXEInjectionRule', () => {
    let rule: XXEInjectionRule;

    beforeEach(() => {
        rule = new XXEInjectionRule();
    });

    describe('Rule Metadata', () => {
        it('should have correct code SEC-005', () => {
            expect(rule.code).toBe('SEC-005');
        });

        it('should have valid tags for CWE and OWASP mapping', () => {
            expect(rule.tags).toContain('CWE-611');
            expect(rule.tags).toContain('OWASP-A05:2021');
        });

        it('should have a helpUri pointing to OWASP resource', () => {
            expect(rule.helpUri).toContain('owasp.org');
            expect(rule.helpUri).toContain('XXE');
        });
    });

    describe('should detect vulnerabilities', () => {
        it('should detect dangerous DTD configuration (Critical)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'parse_xml_unsafe',
                        description: 'Parses XML with DTD enabled for flexibility',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                data: { type: 'string' }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            expect(findings.length).toBeGreaterThan(0);
            expect(findings[0].severity).toBe('critical');
            expect((findings[0].evidence as any).configuration.toLowerCase()).toContain('dtd processing enabled');
        });

        it('should detect XML tools without safe configuration (High)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'xml_processor',
                        description: 'Process various XML files',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                content: { type: 'string' }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            // Finds "doesn't mention XXE protection" (High) 
            // AND likely "Parameter 'content' accepts XML without validation" (Critical)
            // Because 'content' is in isXMLParameter list? yes.
            // And no safe config -> Critical for param.

            const paramFinding = findings.find(f => f.location?.parameter === 'content');
            expect(paramFinding).toBeDefined();
            expect(paramFinding!.severity).toBe('critical');

            const toolFinding = findings.find(f => !f.location?.parameter);
            expect(toolFinding).toBeDefined();
            expect(toolFinding!.severity).toBe('high');
            expect(toolFinding!.message).toContain('does not explicitly disable external entities');
        });

        it('should detect file uploads allowing XML (Critical)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'upload_document_xml',
                        description: 'Upload an XML document',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                file: {
                                    type: 'string',
                                    description: 'File to upload. Accepts .xml, .txt'
                                }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            const fileFinding = findings.find(f => f.message.includes('accepts XML file uploads'));
            expect(fileFinding).toBeDefined();
            expect(fileFinding!.severity).toBe('critical');
            expect(fileFinding!.message).toContain('accepts XML file uploads');
        });

        it('should detect SVG processing (High)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'render_image',
                        description: 'Renders SVG images',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                svg_content: { type: 'string' }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            // Param name contains 'svg', tool matches XML keywords (svg).
            const finding = findings.find(f => f.message.includes('SVG'));
            expect(finding).toBeDefined();
            expect(finding!.severity).toBe('high');
        });
    });

    describe('should pass for safe implementations', () => {
        it('should pass if external entities are explicitly disabled', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'safe_parser',
                        description: 'Parses XML. Note: disable external entities is set to true.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                xml_data: {
                                    type: 'string',
                                    pattern: '^<.*>$' // Some validation
                                }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            // Should have 0 findings because:
            // 1. Has safe indicator -> No Tool Level warning.
            // 2. Param has pattern -> No Param Level warning (or reduced to medium if pattern absent, but here present).
            // Actually rule says: if (!config.pattern) ...
            // Here pattern is present. So loop continues.
            // So should be 0.
            expect(findings.length).toBe(0);
        });

        it('should ignore non-XML tools', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'json_parser',
                        description: 'Parses JSON files',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                data: { type: 'string' }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            expect(findings.length).toBe(0);
        });
    });

    describe('Edge Cases', () => {
        it('should handle undefined tools', () => {
            const discovery = { tools: undefined } as unknown as DiscoveryResult;
            expect(() => rule.evaluate(discovery)).not.toThrow();
        });

        it('should handle empty discovery', () => {
            const discovery = { tools: [], resources: [], prompts: [] };
            const findings = rule.evaluate(discovery);
            expect(findings.length).toBe(0);
        });
    });
});
