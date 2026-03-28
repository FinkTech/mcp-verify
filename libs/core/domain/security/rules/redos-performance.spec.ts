/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { ReDoSDetectionRule } from './redos-detection.rule';
import { DiscoveryResult } from '../../mcp-server/entities/validation.types';

describe('ReDoS Detection Rule - Performance & Stress Tests', () => {
    let rule: ReDoSDetectionRule;

    beforeEach(() => {
        rule = new ReDoSDetectionRule();
    });

    const generateComplexSchema = (count: number, complexity: 'low' | 'high') => {
        const properties: any = {};
        for (let i = 0; i < count; i++) {
            // Generate patterns that appear vulnerable to stress the analyzer
            const pattern = complexity === 'high'
                ? `^([a-zA-Z0-9]+)*${i}$` // Evil pattern style
                : `^[a-z]{1,${i}}$`;       // Simple pattern

            properties[`prop_${i}`] = {
                type: 'string',
                pattern: pattern
            };
        }
        return { type: 'object', properties };
    };

    it('should analyze 1000 simple regex patterns in under 200ms', () => {
        const discovery: DiscoveryResult = {
            tools: [{
                name: 'massive_tool',
                inputSchema: generateComplexSchema(1000, 'low')
            }],
            resources: [],
            prompts: []
        };

        const start = performance.now();
        rule.evaluate(discovery);
        const end = performance.now();

        const duration = end - start;
        console.log(`Performance (Simple): 1000 patterns took ${duration.toFixed(2)}ms`);
        expect(duration).toBeLessThan(200);
    });

    it('should analyze 100 complex/evil regex patterns in under 500ms', () => {
        // These patterns force the analyzer (safe-regex or similar) to work harder
        const discovery: DiscoveryResult = {
            tools: [{
                name: 'complex_tool',
                inputSchema: generateComplexSchema(100, 'high')
            }],
            resources: [],
            prompts: []
        };

        const start = performance.now();
        rule.evaluate(discovery);
        const end = performance.now();

        const duration = end - start;
        console.log(`Performance (Complex): 100 patterns took ${duration.toFixed(2)}ms`);
        expect(duration).toBeLessThan(500);
    });

    it('should handle deeply nested schemas with patterns', () => {
        // Deep nesting stress test
        let currentLevel: any = { type: 'string', pattern: '(a+)+' };
        for (let i = 0; i < 50; i++) {
            currentLevel = {
                type: 'object',
                properties: {
                    nested: currentLevel,
                    sibling: { type: 'string', pattern: '(b+)+' }
                }
            };
        }

        const discovery: DiscoveryResult = {
            tools: [{
                name: 'nested_tool',
                inputSchema: currentLevel
            }],
            resources: [],
            prompts: []
        };

        const start = performance.now();
        const findings = rule.evaluate(discovery);
        const end = performance.now();

        const duration = end - start;
        console.log(`Performance (Nested): 50 levels took ${duration.toFixed(2)}ms`);

        expect(duration).toBeLessThan(500);
        expect(findings.length).toBeGreaterThan(0); // Should still find the ReDoS
    });
});
