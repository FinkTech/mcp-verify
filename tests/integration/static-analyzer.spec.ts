/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { SafeJSStaticAnalyzer } from '@mcp-verify/core/use-cases/sandbox/static-analyzer';

describe('SafeJSStaticAnalyzer', () => {
  let analyzer: SafeJSStaticAnalyzer;

  beforeEach(() => {
    analyzer = new SafeJSStaticAnalyzer();
  });

  test('✅ Should accept safe standard code', () => {
    const code = `
      function add(a, b) { return a + b; }
      const res = add(1, 2);
      console.log(res);
    `;
    const result = analyzer.analyze(code);
    expect(result.isSafe).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  test('✅ Should accept modern ES features', () => {
    const code = `
      const sum = (a, b) => a + b;
      async function main() {
        await Promise.resolve();
        const obj = { x: 1, ...{y: 2} };
      }
    `;
    const result = analyzer.analyze(code);
    expect(result.isSafe).toBe(true);
  });

  test('❌ Should detect "eval()"', () => {
    const code = `
      const x = 10;
      eval("console.log(x)");
    `;
    const result = analyzer.analyze(code);
    expect(result.isSafe).toBe(false);
    expect(result.violations[0]).toContain("eval");
  });

  test('❌ Should detect "new Function()"', () => {
    const code = `
      const func = new Function("a", "return a + 1");
    `;
    const result = analyzer.analyze(code);
    expect(result.isSafe).toBe(false);
    expect(result.violations[0]).toContain("new Function");
  });

  test('❌ Should detect "__proto__" access', () => {
    const code = `
      const obj = {};
      obj.__proto__.polluted = true;
    `;
    const result = analyzer.analyze(code);
    expect(result.isSafe).toBe(false);
    expect(result.violations[0]).toContain("__proto__");
  });

  test('❌ Should detect "prototype" access', () => {
    const code = `
      Array.prototype.push = function() {};
    `;
    const result = analyzer.analyze(code);
    expect(result.isSafe).toBe(false);
    expect(result.violations[0]).toContain("prototype");
  });

  test('❌ Should handle Syntax Errors gracefully', () => {
    const code = `function broken( {`; // Syntax error
    const result = analyzer.analyze(code);
    expect(result.isSafe).toBe(false);
    expect(result.violations[0]).toContain("Syntax Error");
  });
});
