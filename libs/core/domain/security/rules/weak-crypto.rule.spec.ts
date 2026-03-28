/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Weak Crypto Rule Tests (SEC-012)
 * 
 * Tests for Weak Cryptography vulnerability detection.
 */

import { WeakCryptographyRule } from './weak-crypto.rule';
import { DiscoveryResult } from '../../mcp-server/entities/validation.types';

describe('WeakCryptographyRule', () => {
    let rule: WeakCryptographyRule;

    beforeEach(() => {
        rule = new WeakCryptographyRule();
    });

    describe('Rule Metadata', () => {
        it('should have correct code SEC-012', () => {
            expect(rule.code).toBe('SEC-012');
        });

        it('should have a helpUri pointing to OWASP resource', () => {
            expect(rule.helpUri).toContain('owasp.org');
        });
    });

    describe('should detect vulnerabilities', () => {
        it('should detect weak hashing algorithms like MD5 (Critical)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'hash_utils',
                        description: 'Computes MD5 hash of input', // Weak hash
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
            const finding = findings.find(f => f.message.toLowerCase().includes('weak hashing'));
            expect(finding).toBeDefined();
            expect(finding!.severity).toBe('critical');
            expect((finding!.evidence as any).algorithm).toBe('MD5');
        });

        it('should detect weak encryption algorithms like RC4 (Critical)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'legacy_encrypt',
                        description: 'Encrypts data using RC4 stream cipher', // Weak cipher
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
            const finding = findings.find(f => f.message.toLowerCase().includes('weak encryption'));
            expect(finding).toBeDefined();
            expect(finding!.severity).toBe('critical');
            expect((finding!.evidence as any).algorithm).toBe('RC4');
        });

        it('should detect insecure random number generation (High)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'generate_token',
                        description: 'Generates cryptographic token using Math.random()', // Insecure PRNG, triggers 'cryptographic'
                        inputSchema: {
                            type: 'object',
                            properties: {
                                len: { type: 'number' }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            const finding = findings.find(f => f.message.toLowerCase().includes('insecure random'));
            expect(finding).toBeDefined();
            expect(finding!.severity).toBe('high');
        });

        it('should detect dangerously short key lengths (Critical)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'generate_key',
                        description: 'Generates a cryptographic key',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                key_size: {
                                    type: 'integer',
                                    minimum: 64 // Too small (< 128)
                                }
                            }
                        }
                    }
                ],
                resources: [],
                prompts: []
            };

            const findings = rule.evaluate(discovery);
            const finding = findings.find(f => f.message.toLowerCase().includes('dangerously short'));
            expect(finding).toBeDefined();
            expect(finding!.severity).toBe('critical');
        });

        it('should warn about unspecified cryptography (Medium)', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'encrypt_data',
                        description: 'Encrypts sensitive data securely.', // "encrypt" keyword, but no "AES", "ChaCha", etc.
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
            const finding = findings.find(f => f.severity === 'medium');
            expect(finding).toBeDefined();
            expect(finding!.message).toContain('does not specify strong algorithms');
        });
    });

    it('should detect SHA1 usage (Critical)', () => {
        const discovery: DiscoveryResult = {
            tools: [
                {
                    name: 'legacy_hash',
                    description: 'Hashes using SHA-1 algorithm',
                    inputSchema: { type: 'object', properties: {} }
                }
            ],
            resources: [],
            prompts: []
        };

        const findings = rule.evaluate(discovery);
        const finding = findings.find(f => f.message.toLowerCase().includes('weak hashing'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('critical');
        expect((finding?.evidence as any).algorithm).toBe('SHA-1');
    });

    it('should detect AES-128 usage (High)', () => {
        const discovery: DiscoveryResult = {
            tools: [
                {
                    name: 'encrypt_fast',
                    description: 'Encrypts with AES-128-CBC',
                    inputSchema: { type: 'object', properties: {} }
                }
            ],
            resources: [],
            prompts: []
        };

        const findings = rule.evaluate(discovery);
        const finding = findings.find(f => f.message.toLowerCase().includes('weak encryption'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('high');
        expect((finding?.evidence as any).algorithm).toBe('AES-128');
    });

    it('should detect weak algorithm selection in parameters (High)', () => {
        const discovery: DiscoveryResult = {
            tools: [
                {
                    name: 'choose_cipher',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            algorithm: {
                                type: 'string',
                                enum: ['AES-256', 'DES', 'RC4'] // Weak options
                            }
                        }
                    }
                }
            ],
            resources: [],
            prompts: []
        };

        const findings = rule.evaluate(discovery);
        const finding = findings.find(f => f.message.toLowerCase().includes('allows selecting weak'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('high');
    });

    it('should detect insecure rand() usage (High)', () => {
        const discovery: DiscoveryResult = {
            tools: [
                {
                    name: 'crypto_random_generator',
                    description: 'Uses rand() for ID generation',
                    inputSchema: { type: 'object', properties: {} }
                }
            ],
            resources: [],
            prompts: []
        };

        const findings = rule.evaluate(discovery);
        const finding = findings.find(f => f.message.toLowerCase().includes('insecure random'));
        expect(finding).toBeDefined();
        expect((finding?.evidence as any).method).toContain('rand()');
    });
    describe('should pass for safe implementations', () => {
        it('should pass if strong algorithms like AES-256 are used', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'secure_encrypt',
                        description: 'Encrypts using AES-256-GCM',
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

        it('should pass if strong hashing like SHA-256 is used', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'secure_hash',
                        description: 'Computes SHA-256 hash',
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

        it('should ignore non-cryptographic tools', () => {
            const discovery: DiscoveryResult = {
                tools: [
                    {
                        name: 'string_utils',
                        description: 'Concatenates strings',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                a: { type: 'string' },
                                b: { type: 'string' }
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
