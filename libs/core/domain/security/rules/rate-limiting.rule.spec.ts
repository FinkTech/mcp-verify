/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Rate Limiting Rule Tests (SEC-011)
 * 
 * Tests for Missing Rate Limiting vulnerability detection.
 */

import { RateLimitingRule } from './rate-limiting.rule';
import { DiscoveryResult } from '../../mcp-server/entities/validation.types';

describe('RateLimitingRule', () => {
    let rule: RateLimitingRule;

    beforeEach(() => {
        rule = new RateLimitingRule();
    });

    describe('Rule Metadata', () => {
        it('should have correct code SEC-010', () => {
            expect(rule.code).toBe('SEC-010');
        });

        it('should have valid tags for CWE and OWASP mapping', () => {
            expect(rule.tags).toContain('CWE-770');
            expect(rule.tags).toContain('OWASP-A04:2021');
        });

        it('should have a helpUri pointing to OWASP resource', () => {
            expect(rule.helpUri).toContain('owasp.org');
        });
    });

    describe('should detect vulnerabilities', () => {
        it('should detect unthrottled expensive operations (Medium)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'db_query',
                        description: 'Executes SQL query against database', // 'query', 'database' -> expensive
                        inputSchema: {
                            type: 'object',
                            properties: {
                                sql: { type: 'string' }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            expect(findings.length).toBeGreaterThan(0);
            const finding = findings.find(f => f.message.toLowerCase().includes('rate limiting not implemented'));
            expect(finding).toBeDefined();
            expect(finding!.severity).toBe('medium'); // Database = medium
        });

        it('should detect unthrottled authentication (High)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'user_login',
                        description: 'Authenticates user with password', // 'login', 'authenticate' -> auth
                        inputSchema: {
                            type: 'object',
                            properties: {
                                username: { type: 'string' },
                                password: { type: 'string' }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            // Should trigger High severity finding for Auth
            const highFinding = findings.find(f => f.message.toLowerCase().includes('must implement') && f.message.toLowerCase().includes('rate limiting'));
            expect(highFinding).toBeDefined();
            expect(highFinding!.severity).toBe('high');

            // Might also find the generic "rate limiting not implemented" one
            const genericFinding = findings.find(f => f.message.toLowerCase().includes('rate limiting not implemented'));
            expect(genericFinding).toBeDefined();
        });

        it('should detect missing file size limits (Medium)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'upload_document',
                        description: 'Uploads a file to storage', // 'upload', 'file' -> file
                        inputSchema: {
                            type: 'object',
                            properties: {
                                file_blob: {
                                    type: 'string',
                                    // No maxLength or maxSize
                                }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            const sizeFinding = findings.find(f => f.message.includes('lacks size limit'));
            expect(sizeFinding).toBeDefined();
            expect(sizeFinding!.severity).toBe('medium');
        });
    });

    describe('should pass for safe implementations', () => {
        it('should pass if tool description mentions rate limiting', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'safe_api_call',
                        description: 'Fetches external data. Rate limit: 60 requests per minute.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                url: { type: 'string' }
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

        it('should pass if schema has x-rate-limit extension', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'ext_throttled_tool',
                        description: 'Heavy computation tool',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                data: { type: 'string' }
                            },
                            // Mocking extension in standard schema object (needs cast if strict types)
                            ...({ 'x-rate-limit': '100 rpm' } as any)
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            expect(findings.length).toBe(0);
        });

        it('should pass if file parameter has size limit', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'safe_upload',
                        description: 'Uploads file. Rate limited 10/hour.', // Rate limiting present
                        inputSchema: {
                            type: 'object',
                            properties: {
                                attachment: {
                                    type: 'string',
                                    maxLength: 5000000 // 5MB limit
                                }
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

        it('should ignore cheap operations', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'simple_format',
                        description: 'Formats a date string', // Not in expensive keywords
                        inputSchema: {
                            type: 'object',
                            properties: {
                                date: { type: 'string' }
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
