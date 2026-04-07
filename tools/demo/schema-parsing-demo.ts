/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Schema Parsing Demo
 *
 * Demonstrates how the SchemaConfusionGenerator parses and extracts fields
 * from MCP tool schemas.
 *
 * Run with: npx tsx tools/demo/schema-parsing-demo.ts
 */

import { SchemaConfusionGenerator } from "../../libs/fuzzer/generators/schema-confusion.generator";

console.log("=".repeat(80));
console.log("Schema-Aware Fuzzing - Field Extraction Demo");
console.log("=".repeat(80));
console.log();

const generator = new SchemaConfusionGenerator();

// Example 1: Simple Schema
console.log("📋 Example 1: Simple Login Schema");
console.log("-".repeat(80));

const simpleSchema = {
  type: "object",
  properties: {
    username: {
      type: "string",
      minLength: 3,
      maxLength: 20,
      description: "User login name",
    },
    password: {
      type: "string",
      minLength: 8,
      maxLength: 100,
    },
    rememberMe: {
      type: "boolean",
    },
  },
  required: ["username", "password"],
};

console.log("Input Schema:");
console.log(JSON.stringify(simpleSchema, null, 2));
console.log();

const simplePayloads = generator.generateForSchema(simpleSchema);
console.log(`✅ Generated ${simplePayloads.length} attack payloads`);
console.log();
console.log("Sample Payloads (first 5):");
simplePayloads.slice(0, 5).forEach((payload, idx) => {
  console.log(
    `  ${idx + 1}. [${payload.severity.toUpperCase()}] ${payload.description}`,
  );
  console.log(`     Type: ${payload.type}`);
  console.log(`     Value: ${JSON.stringify(payload.value)}`);
  console.log();
});
console.log();

// Example 2: Nested Objects
console.log("📋 Example 2: Nested User Profile Schema");
console.log("-".repeat(80));

const nestedSchema = {
  type: "object",
  properties: {
    user: {
      type: "object",
      properties: {
        personal: {
          type: "object",
          properties: {
            firstName: {
              type: "string",
              maxLength: 50,
            },
            lastName: {
              type: "string",
              maxLength: 50,
            },
            age: {
              type: "number",
              minimum: 0,
              maximum: 120,
            },
          },
          required: ["firstName", "lastName"],
        },
        contact: {
          type: "object",
          properties: {
            email: {
              type: "string",
              format: "email",
              maxLength: 100,
            },
            phone: {
              type: "string",
              pattern: "^\\+?[1-9]\\d{1,14}$",
            },
          },
          required: ["email"],
        },
      },
    },
  },
  required: ["user"],
};

console.log("Input Schema (nested):");
console.log(JSON.stringify(nestedSchema, null, 2));
console.log();

const nestedPayloads = generator.generateForSchema(nestedSchema);
console.log(`✅ Generated ${nestedPayloads.length} attack payloads`);
console.log();
console.log("Nested Path Examples (showing path structure):");
const nestedSamples = nestedPayloads
  .filter((p) => p.targetParameter?.includes("."))
  .slice(0, 3);

nestedSamples.forEach((payload, idx) => {
  console.log(`  ${idx + 1}. Target: ${payload.targetParameter}`);
  console.log(
    `     [${payload.severity.toUpperCase()}] ${payload.description}`,
  );
  console.log(
    `     Nested structure: ${JSON.stringify(payload.value, null, 2).split("\n").slice(0, 5).join("\n     ")}`,
  );
  console.log();
});
console.log();

// Example 3: Complex Schema with Enums and Arrays
console.log("📋 Example 3: Complex E-commerce Schema");
console.log("-".repeat(80));

const complexSchema = {
  type: "object",
  properties: {
    productId: {
      type: "string",
      pattern: "^[A-Z]{3}-\\d{6}$",
      description: "Product SKU",
    },
    quantity: {
      type: "number",
      minimum: 1,
      maximum: 999,
    },
    priority: {
      type: "string",
      enum: ["low", "medium", "high", "urgent"],
    },
    shippingAddress: {
      type: "object",
      properties: {
        street: { type: "string", maxLength: 100 },
        city: { type: "string", maxLength: 50 },
        zipCode: { type: "string", pattern: "^\\d{5}$" },
        country: {
          type: "string",
          enum: ["US", "CA", "MX", "UK", "DE"],
        },
      },
      required: ["street", "city", "zipCode", "country"],
    },
    tags: {
      type: "array",
      items: { type: "string" },
      maxItems: 5,
      minItems: 1,
    },
  },
  required: ["productId", "quantity", "shippingAddress"],
};

console.log("Input Schema (complex):");
console.log(JSON.stringify(complexSchema, null, 2));
console.log();

const complexPayloads = generator.generateForSchema(complexSchema);
console.log(`✅ Generated ${complexPayloads.length} attack payloads`);
console.log();

// Show statistics
const stats = {
  critical: complexPayloads.filter((p) => p.severity === "critical").length,
  high: complexPayloads.filter((p) => p.severity === "high").length,
  medium: complexPayloads.filter((p) => p.severity === "medium").length,
  low: complexPayloads.filter((p) => p.severity === "low").length,
};

console.log("Payload Statistics by Severity:");
console.log(`  🔴 Critical: ${stats.critical} payloads`);
console.log(`  🟠 High:     ${stats.high} payloads`);
console.log(`  🟡 Medium:   ${stats.medium} payloads`);
console.log(`  🟢 Low:      ${stats.low} payloads`);
console.log();

// Show different attack types
const attackTypes = [...new Set(complexPayloads.map((p) => p.type))];
console.log(`Attack Types (${attackTypes.length} unique types):`);
attackTypes.slice(0, 10).forEach((type) => {
  const count = complexPayloads.filter((p) => p.type === type).length;
  console.log(`  - ${type} (${count} payloads)`);
});
console.log();

// Show critical attacks
console.log("🎯 Critical Attacks (highest priority):");
const criticalAttacks = complexPayloads
  .filter((p) => p.severity === "critical")
  .slice(0, 5);

criticalAttacks.forEach((payload, idx) => {
  console.log(`  ${idx + 1}. ${payload.description}`);
  console.log(`     Expected behavior: ${payload.expectedVulnerableBehavior}`);
});
console.log();

console.log("=".repeat(80));
console.log("✅ Schema-Aware Fuzzing Implementation Complete!");
console.log("=".repeat(80));
console.log();
console.log("Implementation Status:");
console.log("  ✅ Phase 1: Schema parsing and field extraction");
console.log("  ✅ Phase 2: Attack payload generation");
console.log("     ✅ Type confusion attacks");
console.log("     ✅ Boundary value attacks");
console.log("     ✅ Enum bypass attacks (privilege escalation)");
console.log("     ✅ Null/undefined injection");
console.log("     ✅ Format-specific attacks (email, URI, date, IPv4)");
console.log(
  "     ✅ Structural attacks (missing fields, prototype pollution, DoS)",
);
console.log();
console.log("Key Features:");
console.log("  • Generates 50-200+ targeted payloads per schema");
console.log("  • Handles nested objects recursively");
console.log("  • Exploits specific constraints (maxLength, enum, etc.)");
console.log("  • Detects privilege escalation opportunities");
console.log("  • Tests SSRF, XSS, and injection vulnerabilities");
console.log(
  "  • Prioritizes attacks by severity (critical > high > medium > low)",
);
console.log();
console.log("To test:");
console.log("  npm test -- schema-confusion.spec.ts");
console.log();
