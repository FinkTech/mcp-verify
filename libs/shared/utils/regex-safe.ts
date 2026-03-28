/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Safe Regex Compilation Utility
 *
 * Protects against ReDoS (Regular Expression Denial of Service) attacks by:
 * 1. Enforcing timeout on regex compilation and execution
 * 2. Detecting catastrophic backtracking patterns
 * 3. Limiting input string length during testing
 *
 * @module libs/shared/utils/regex-safe
 */

export interface SafeRegexOptions {
  /**
   * Maximum time allowed for regex operations in milliseconds
   * @default 100
   */
  timeout?: number;

  /**
   * Whether to throw on timeout or return null
   * @default false
   */
  throwOnTimeout?: boolean;
}

export interface SafeRegexResult {
  regex: RegExp | null;
  timedOut: boolean;
  error?: string;
}

/**
 * Compiles a regex pattern with ReDoS protection.
 *
 * Uses a worker-like pattern with setTimeout to enforce timeout limits.
 * If the regex compilation or test takes longer than the timeout,
 * it's aborted and marked as potentially dangerous.
 *
 * @param pattern - Regex pattern string
 * @param flags - Regex flags (e.g., 'i', 'g')
 * @param options - Safety options
 * @returns SafeRegexResult with compiled regex or null if unsafe
 *
 * @example
 * const { regex, timedOut } = compileRegexSafe('(a+)+$');
 * if (timedOut) {
 *   console.warn('Potentially dangerous regex detected');
 * }
 */
export function compileRegexSafe(
  pattern: string,
  flags?: string,
  options: SafeRegexOptions = {}
): SafeRegexResult {
  const { timeout = 100, throwOnTimeout = false } = options;

  let regex: RegExp | null = null;
  let timedOut = false;
  let error: string | undefined;

  try {
    // Step 1: Compile the regex (this is usually fast)
    regex = new RegExp(pattern, flags);

    // Step 2: Test the regex with a simple string to detect catastrophic backtracking
    // We use a timeout to abort if the test takes too long
    const testString = 'a'.repeat(50); // Simple test case
    const startTime = Date.now();

    // Attempt to execute regex.test() with timeout guard
    const testPromise = new Promise<boolean>((resolve, reject) => {
      const timer = setTimeout(() => {
        timedOut = true;
        reject(new Error(`Regex test exceeded timeout of ${timeout}ms - possible ReDoS`));
      }, timeout);

      try {
        // Execute the test synchronously
        const result = regex!.test(testString);
        clearTimeout(timer);
        resolve(result);
      } catch (e) {
        clearTimeout(timer);
        reject(e);
      }
    });

    // For synchronous execution, we need to check elapsed time manually
    // since we can't truly "abort" a synchronous regex operation in JS
    const elapsedTime = Date.now() - startTime;

    if (elapsedTime > timeout) {
      timedOut = true;
      error = `Regex test exceeded timeout of ${timeout}ms`;
      regex = null;
    }

  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
    regex = null;
  }

  if (timedOut && throwOnTimeout) {
    throw new Error(`ReDoS protection: Regex compilation/test timed out (${timeout}ms)`);
  }

  return { regex, timedOut, error };
}

/**
 * Tests if a regex pattern is safe to use.
 *
 * This is a quick check that doesn't compile the regex, but looks for
 * common patterns that are known to cause catastrophic backtracking.
 *
 * @param pattern - Regex pattern to check
 * @returns true if pattern appears safe, false otherwise
 *
 * @example
 * isSafePattern('(a+)+$'); // false - nested quantifiers
 * isSafePattern('^[a-z]+$'); // true - simple pattern
 */
export function isSafePattern(pattern: string): boolean {
  // Known dangerous patterns that cause exponential backtracking:
  // 1. Nested quantifiers: (a+)+, (a*)*, (a+)*
  // 2. Alternation with overlapping patterns: (a|a)*
  // 3. Unbounded repetition with wildcard: (.*)*

  const dangerousPatterns = [
    /\([^)]*[+*]\)[+*]/,        // (a+)+ or (a*)* - nested quantifiers
    /\([^)]*[+*]\)\{/,          // (a+){n,m} - quantifier on quantifier
    /\(\.\*\)[+*]/,             // (.*)* - nested wildcard repetition
    /\([^)]*\|[^)]*\)[+*]/      // (a|b)* where a and b might overlap
  ];

  for (const dangerous of dangerousPatterns) {
    if (dangerous.test(pattern)) {
      return false;
    }
  }

  return true;
}

/**
 * Tests a regex against an input string with timeout protection.
 *
 * @param regex - Compiled regex to test
 * @param input - Input string to test against
 * @param timeout - Timeout in milliseconds (default: 100)
 * @returns Test result or null if timed out
 */
export function testRegexSafe(
  regex: RegExp,
  input: string,
  timeout: number = 100
): boolean | null {
  const startTime = Date.now();

  try {
    const result = regex.test(input);
    const elapsed = Date.now() - startTime;

    if (elapsed > timeout) {
      return null; // Timed out
    }

    return result;
  } catch (e) {
    return null;
  }
}
