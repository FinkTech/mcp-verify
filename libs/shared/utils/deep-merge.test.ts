/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Tests for Deep Merge Utility
 */

import { deepMerge, deepMergeAll } from "./deep-merge";

describe("deepMerge", () => {
  it("should merge flat objects", () => {
    const target = { a: 1, b: 2 };
    const source = { b: 3, c: 4 };
    const result = deepMerge(target, source);

    expect(result).toEqual({ a: 1, b: 3, c: 4 });
  });

  it("should merge nested objects recursively", () => {
    const target = {
      security: {
        enabled: true,
        rules: { A: true, B: true, C: true },
      },
    };

    const source = {
      security: {
        rules: { A: false },
      },
    };

    const result = deepMerge(target, source);

    expect(result).toEqual({
      security: {
        enabled: true,
        rules: { A: false, B: true, C: true },
      },
    });
  });

  it("should preserve target properties when source has undefined", () => {
    const target = { a: 1, b: 2 };
    const source = { b: undefined, c: 3 };
    const result = deepMerge(target, source);

    expect(result).toEqual({ a: 1, b: 2, c: 3 });
  });

  it("should replace arrays (not merge them)", () => {
    const target = { arr: [1, 2, 3] };
    const source = { arr: [4, 5] };
    const result = deepMerge(target, source);

    expect(result).toEqual({ arr: [4, 5] });
  });

  it("should handle deep nesting (3+ levels)", () => {
    const target = {
      level1: {
        level2: {
          level3: {
            a: 1,
            b: 2,
          },
        },
      },
    };

    const source = {
      level1: {
        level2: {
          level3: {
            b: 99,
          },
        },
      },
    };

    const result = deepMerge(target, source);

    expect(result).toEqual({
      level1: {
        level2: {
          level3: {
            a: 1,
            b: 99,
          },
        },
      },
    });
  });

  it("should not merge Date objects", () => {
    const date1 = new Date("2020-01-01");
    const date2 = new Date("2021-01-01");
    const target = { date: date1 };
    const source = { date: date2 };
    const result = deepMerge(target, source);

    expect(result.date).toBe(date2);
  });

  it("should not merge RegExp objects", () => {
    const regex1 = /abc/;
    const regex2 = /xyz/;
    const target = { regex: regex1 };
    const source = { regex: regex2 };
    const result = deepMerge(target, source);

    expect(result.regex).toBe(regex2);
  });

  it("should handle null values correctly", () => {
    const target = { a: { b: 1 } };
    const source = { a: null };
    const result = deepMerge(target, source);

    expect(result).toEqual({ a: null });
  });

  it("should not mutate original objects", () => {
    const target = { a: { b: 1 } };
    const source = { a: { c: 2 } };
    const targetCopy = JSON.parse(JSON.stringify(target));

    deepMerge(target, source);

    expect(target).toEqual(targetCopy);
  });
});

describe("deepMergeAll", () => {
  it("should merge multiple objects from left to right", () => {
    const result = deepMergeAll({ a: 1, b: 2 }, { b: 3, c: 4 }, { c: 5, d: 6 });

    expect(result).toEqual({ a: 1, b: 3, c: 5, d: 6 });
  });

  it("should handle nested objects in multiple merges", () => {
    const result = deepMergeAll(
      { security: { rules: { A: true, B: true } } },
      { security: { rules: { B: false, C: true } } },
      { security: { enabled: false } },
    );

    expect(result).toEqual({
      security: {
        enabled: false,
        rules: { A: true, B: false, C: true },
      },
    });
  });
});

describe("Config Merge Scenarios (Real Use Cases)", () => {
  it("should handle partial user config (only one security rule)", () => {
    const DEFAULT_CONFIG = {
      security: {
        enabled: true,
        level: "strict",
        rules: {
          "SEC-001": { enabled: true, severity: "critical" },
          "SEC-002": { enabled: true, severity: "critical" },
          "SEC-003": { enabled: true, severity: "high" },
        },
      },
    };

    const userConfig = {
      security: {
        rules: {
          "SEC-001": { enabled: false },
        },
      },
    };

    const result = deepMerge(DEFAULT_CONFIG, userConfig);

    expect(result.security.enabled).toBe(true);
    expect(result.security.level).toBe("strict");
    expect(result.security.rules["SEC-001"].enabled).toBe(false);
    expect(result.security.rules["SEC-001"].severity).toBe("critical");
    expect(result.security.rules["SEC-002"].enabled).toBe(true);
    expect(result.security.rules["SEC-003"].enabled).toBe(true);
  });

  it("should handle empty user config", () => {
    const DEFAULT_CONFIG = {
      security: { enabled: true },
      proxy: { port: 8080 },
    };

    const userConfig = {};

    const result = deepMerge(DEFAULT_CONFIG, userConfig);

    expect(result).toEqual(DEFAULT_CONFIG);
  });

  it("should handle user config with new properties", () => {
    const DEFAULT_CONFIG = {
      security: { enabled: true },
    };

    const userConfig = {
      security: { enabled: false },
      custom: { feature: "enabled" },
    };

    const result = deepMerge(DEFAULT_CONFIG, userConfig);

    expect(result).toEqual({
      security: { enabled: false },
      custom: { feature: "enabled" },
    });
  });
});
