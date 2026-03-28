/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Deep Merge Utility
 *
 * Recursively merges objects, ensuring nested properties are preserved.
 * Used for merging user configuration with defaults without losing properties.
 *
 * @module libs/shared/utils/deep-merge
 */

/**
 * Check if a value is a plain object (not array, null, Date, etc.)
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    !(value instanceof Date) &&
    !(value instanceof RegExp)
  );
}

/**
 * Deep merge two objects recursively.
 *
 * Rules:
 * - Arrays are replaced (not merged)
 * - Plain objects are recursively merged
 * - Primitives from source override target
 * - undefined in source does not override target
 *
 * @example
 * ```ts
 * const defaults = {
 *   security: {
 *     enabled: true,
 *     rules: { A: true, B: true }
 *   }
 * };
 * const user = {
 *   security: {
 *     rules: { A: false }
 *   }
 * };
 *
 * deepMerge(defaults, user);
 * // Result: { security: { enabled: true, rules: { A: false, B: true } } }
 * ```
 */
export function deepMerge<T extends Record<string, unknown>>(
  target: T,
  source: Record<string, unknown>
): T {
  const result: Record<string, unknown> = { ...target };

  for (const key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) {
      continue;
    }

    const sourceValue = source[key];

    // undefined in source should not override target
    if (sourceValue === undefined) {
      continue;
    }

    const targetValue = result[key];

    // If both are plain objects, merge recursively
    if (isPlainObject(targetValue) && isPlainObject(sourceValue)) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as Record<string, unknown>
      );
    } else {
      // Otherwise, source value replaces target value
      result[key] = sourceValue;
    }
  }

  return result as T;
}

/**
 * Deep merge multiple objects from left to right.
 *
 * @example
 * ```ts
 * deepMergeAll({ a: 1 }, { b: 2 }, { c: 3 })
 * // Result: { a: 1, b: 2, c: 3 }
 * ```
 */
export function deepMergeAll<T extends Record<string, unknown>>(
  ...objects: Record<string, unknown>[]
): T {
  return objects.reduce((acc, obj) => deepMerge(acc, obj), {} as Record<string, unknown>) as T;
}
