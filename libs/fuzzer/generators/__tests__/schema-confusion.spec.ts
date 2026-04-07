/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Tests for Schema-Aware Fuzzing
 * Verifies that schema parsing and payload generation work correctly
 */

import { SchemaConfusionGenerator } from "../schema-confusion.generator";

describe("SchemaConfusionGenerator - Schema-Aware Fuzzing", () => {
  let generator: SchemaConfusionGenerator;

  beforeEach(() => {
    generator = new SchemaConfusionGenerator();
  });

  describe("Basic Payload Generation", () => {
    it("should generate type confusion attacks for string field", () => {
      const schema = {
        type: "object",
        properties: {
          username: {
            type: "string",
            minLength: 3,
            maxLength: 20,
          },
        },
        required: ["username"],
      };

      const payloads = generator.generateForSchema(schema);

      expect(payloads).toBeDefined();
      expect(Array.isArray(payloads)).toBe(true);
      expect(payloads.length).toBeGreaterThan(0);

      // Should have type confusion attacks (number, boolean, array, etc.)
      const typeConfusionPayloads = payloads.filter(
        (p) => p.type === "type-confusion",
      );
      expect(typeConfusionPayloads.length).toBeGreaterThan(0);

      // Should have boundary attacks
      const boundaryPayloads = payloads.filter((p) =>
        p.type.includes("boundary"),
      );
      expect(boundaryPayloads.length).toBeGreaterThan(0);

      // Verify payload structure
      const firstPayload = payloads[0];
      expect(firstPayload).toHaveProperty("value");
      expect(firstPayload).toHaveProperty("category", "schema");
      expect(firstPayload).toHaveProperty("severity");
      expect(firstPayload).toHaveProperty("description");
    });

    it("should generate boundary attacks for number field", () => {
      const schema = {
        type: "object",
        properties: {
          age: {
            type: "number",
            minimum: 0,
            maximum: 120,
          },
        },
      };

      const payloads = generator.generateForSchema(schema);

      // Should have attacks testing boundaries
      const overflowPayloads = payloads.filter(
        (p) =>
          p.description.includes("maximum + 1") ||
          p.description.includes("overflow"),
      );
      expect(overflowPayloads.length).toBeGreaterThan(0);

      const underflowPayloads = payloads.filter(
        (p) =>
          p.description.includes("minimum - 1") ||
          p.description.includes("underflow"),
      );
      expect(underflowPayloads.length).toBeGreaterThan(0);

      // Should have special number values (NaN, Infinity)
      const specialPayloads = payloads.filter((p) =>
        p.type.includes("special"),
      );
      expect(specialPayloads.length).toBeGreaterThan(0);
    });

    it("should generate enum bypass attacks", () => {
      const schema = {
        type: "object",
        properties: {
          role: {
            type: "string",
            enum: ["user", "admin", "guest"],
          },
        },
        required: ["role"],
      };

      const payloads = generator.generateForSchema(schema);

      // Should have enum-specific attacks
      const enumPayloads = payloads.filter((p) => p.type.includes("enum"));
      expect(enumPayloads.length).toBeGreaterThan(0);

      // Should include invalid enum value (CRITICAL attack)
      const invalidEnumPayload = payloads.find(
        (p) => p.type === "enum-invalid",
      );
      expect(invalidEnumPayload).toBeDefined();
      expect(invalidEnumPayload?.severity).toBe("critical");

      // Should have privilege escalation attempts
      const privEscPayloads = payloads.filter((p) =>
        p.type.includes("enum-privilege"),
      );
      expect(privEscPayloads.length).toBeGreaterThan(0);
    });
  });

  describe("Nested Object Attacks", () => {
    it("should generate attacks for nested fields with correct paths", () => {
      const schema = {
        type: "object",
        properties: {
          user: {
            type: "object",
            properties: {
              profile: {
                type: "object",
                properties: {
                  name: {
                    type: "string",
                    maxLength: 50,
                  },
                },
                required: ["name"],
              },
            },
          },
        },
      };

      const payloads = generator.generateForSchema(schema);
      expect(payloads.length).toBeGreaterThan(0);

      // Should have attacks targeting nested path
      const nestedPayloads = payloads.filter((p) =>
        p.targetParameter?.includes("user.profile.name"),
      );
      expect(nestedPayloads.length).toBeGreaterThan(0);

      // Verify nested structure in payload value
      const firstNested = nestedPayloads[0];
      expect(firstNested.value).toHaveProperty("user");
      expect(firstNested.value).toMatchObject({
        user: expect.objectContaining({
          profile: expect.objectContaining({
            name: expect.anything(),
          }),
        }),
      });
    });
  });

  describe("Format-Specific Attacks", () => {
    it("should generate email format attacks", () => {
      const schema = {
        type: "object",
        properties: {
          email: {
            type: "string",
            format: "email",
          },
        },
      };

      const payloads = generator.generateForSchema(schema);

      // Should have format-email attacks
      const emailPayloads = payloads.filter((p) =>
        p.type.includes("format-email"),
      );
      expect(emailPayloads.length).toBeGreaterThan(0);
    });

    it("should generate URI/URL attacks including SSRF", () => {
      const schema = {
        type: "object",
        properties: {
          webhook: {
            type: "string",
            format: "uri",
          },
        },
      };

      const payloads = generator.generateForSchema(schema);

      // Should have URI attacks
      const uriPayloads = payloads.filter((p) => p.type.includes("format-uri"));
      expect(uriPayloads.length).toBeGreaterThan(0);

      // Should include SSRF attacks
      const ssrfPayloads = payloads.filter((p) => p.type.includes("ssrf"));
      expect(ssrfPayloads.length).toBeGreaterThan(0);

      // Should include XSS attacks
      const xssPayloads = payloads.filter(
        (p) => p.description.includes("XSS") || p.type.includes("javascript"),
      );
      expect(xssPayloads.length).toBeGreaterThan(0);
    });
  });

  describe("Structural Attacks", () => {
    it("should generate missing required field attacks", () => {
      const schema = {
        type: "object",
        properties: {
          username: { type: "string" },
          password: { type: "string" },
        },
        required: ["username", "password"],
      };

      const payloads = generator.generateForSchema(schema);

      // Should have structural attacks
      const structuralPayloads = payloads.filter((p) =>
        p.type.includes("structural"),
      );
      expect(structuralPayloads.length).toBeGreaterThan(0);

      // Should have empty object attack
      const emptyPayload = payloads.find((p) => p.type === "structural-empty");
      expect(emptyPayload).toBeDefined();
      expect(emptyPayload?.value).toEqual({});

      // Should have missing required field attacks
      const missingRequired = payloads.filter(
        (p) => p.type === "structural-missing-required",
      );
      expect(missingRequired.length).toBe(2); // One for each required field
    });

    it("should generate prototype pollution attacks when additionalProperties=false", () => {
      const schema = {
        type: "object",
        properties: {
          name: { type: "string" },
        },
        additionalProperties: false,
      };

      const payloads = generator.generateForSchema(schema);

      // Should have prototype pollution attack
      const pollutionPayload = payloads.find(
        (p) => p.type === "structural-additional-props",
      );
      expect(pollutionPayload).toBeDefined();
      expect(pollutionPayload?.severity).toBe("critical");

      // Should have dangerous properties
      expect(pollutionPayload?.value).toHaveProperty("__proto__");
      expect(pollutionPayload?.value).toHaveProperty("constructor");
    });

    it("should generate deep nesting DoS attack", () => {
      const schema = {
        type: "object",
        properties: {
          data: { type: "string" },
        },
      };

      const payloads = generator.generateForSchema(schema);

      // Should have deep nesting attack
      const nestingPayload = payloads.find(
        (p) => p.type === "structural-deep-nesting",
      );
      expect(nestingPayload).toBeDefined();
      expect(nestingPayload?.severity).toBe("high");
    });
  });

  describe("Real-World Scenarios", () => {
    it("should generate comprehensive attacks for e-commerce schema", () => {
      const schema = {
        type: "object",
        properties: {
          productId: {
            type: "string",
            pattern: "^[A-Z]{3}-\\d{6}$",
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
          email: {
            type: "string",
            format: "email",
          },
        },
        required: ["productId", "quantity"],
      };

      const payloads = generator.generateForSchema(schema);
      expect(payloads.length).toBeGreaterThan(50); // Should generate many attacks

      // Should have attacks for all fields
      const productIdAttacks = payloads.filter(
        (p) => p.targetParameter === "productId",
      );
      const quantityAttacks = payloads.filter(
        (p) => p.targetParameter === "quantity",
      );
      const priorityAttacks = payloads.filter(
        (p) => p.targetParameter === "priority",
      );
      const emailAttacks = payloads.filter(
        (p) => p.targetParameter === "email",
      );

      expect(productIdAttacks.length).toBeGreaterThan(0);
      expect(quantityAttacks.length).toBeGreaterThan(0);
      expect(priorityAttacks.length).toBeGreaterThan(0);
      expect(emailAttacks.length).toBeGreaterThan(0);

      // Should have different severity levels
      const criticalAttacks = payloads.filter((p) => p.severity === "critical");
      const highAttacks = payloads.filter((p) => p.severity === "high");
      const mediumAttacks = payloads.filter((p) => p.severity === "medium");

      expect(criticalAttacks.length).toBeGreaterThan(0);
      expect(highAttacks.length).toBeGreaterThan(0);
      expect(mediumAttacks.length).toBeGreaterThan(0);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty schema gracefully", () => {
      const schema = {
        type: "object",
        properties: {},
      };

      const payloads = generator.generateForSchema(schema);
      expect(payloads).toBeDefined();
      expect(Array.isArray(payloads)).toBe(true);
      // Should at least have structural attacks
      expect(payloads.length).toBeGreaterThan(0);
    });

    it("should handle invalid schema by falling back to generic", () => {
      // Intentionally pass invalid input to test error handling
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const schema = null as any as Record<string, unknown>;

      const payloads = generator.generateForSchema(schema);
      expect(payloads).toBeDefined();
      expect(Array.isArray(payloads)).toBe(true);
      expect(payloads.length).toBeGreaterThan(0); // Should fall back to generic
    });
  });
});
