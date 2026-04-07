/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Schema Confusion Generator
 *
 * Generates payloads that exploit type confusion and schema validation gaps.
 * Sends unexpected types, boundary values, and malformed data structures.
 */

import {
  IPayloadGenerator,
  GeneratorConfig,
  GeneratedPayload,
} from "./generator.interface";

// ==================== SCHEMA PARSING TYPES ====================

/**
 * Parsed and normalized JSON Schema
 */
interface ParsedSchema {
  type: string;
  properties: Record<string, PropertySchema>;
  required: string[];
  additionalProperties: boolean;
}

/**
 * Schema definition for a single property
 */
interface PropertySchema {
  type: string;
  description?: string;
  // Constraints
  maxLength?: number;
  minLength?: number;
  maximum?: number;
  minimum?: number;
  pattern?: string;
  format?: string;
  enum?: unknown[];
  maxItems?: number;
  minItems?: number;
  // Nested objects
  properties?: Record<string, PropertySchema>;
  required?: string[];
  // Arrays
  items?: PropertySchema;
  // Additional properties
  additionalProperties?: boolean | PropertySchema;
}

/**
 * Descriptor for a field with its full path and constraints
 */
interface FieldDescriptor {
  /** Path to the field (e.g., ['user', 'profile', 'name']) */
  path: string[];
  /** JSON Schema type */
  type: string;
  /** All constraints from the schema */
  constraints: PropertySchema;
  /** Whether this field is required */
  required: boolean;
  /** Allowed values (for enum) */
  allowedValues?: unknown[];
}

// ==================== GENERATOR CLASS ====================

export class SchemaConfusionGenerator implements IPayloadGenerator {
  readonly id = "schema-confusion";
  readonly name = "Schema Confusion Generator";
  readonly category = "schema";
  readonly description =
    "Generates payloads to exploit type confusion and schema validation gaps";

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    payloads.push(...this.generateTypeConfusion());
    payloads.push(...this.generateBoundaryValues());
    payloads.push(...this.generateNestedAttacks());

    return payloads;
  }

  generateForSchema(
    toolSchema: Record<string, unknown>,
    config?: GeneratorConfig,
  ): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    try {
      // STEP 1: Parse and normalize the schema
      const schema = this.parseSchema(toolSchema);

      // STEP 2: Extract all fields with their constraints (including nested)
      const fields = this.extractFields(schema);

      // If no fields found, fall back to generic payloads
      if (fields.length === 0) {
        return this.generate(config);
      }

      // STEP 3: Generate attacks for each field
      for (const field of fields) {
        // Skip object type fields (they're just containers)
        if (field.type === "object") continue;

        payloads.push(...this.generateFieldAttacks(field));
      }

      // STEP 4: Generate structural attacks (schema-level, not field-specific)
      payloads.push(...this.generateStructuralAttacks(schema));
    } catch (error) {
      // If schema parsing fails, fall back to generic payloads
      console.warn("[SchemaConfusionGenerator] Schema parsing failed:", error);
      return this.generate(config);
    }

    return payloads;
  }

  private generateTypeConfusion(): GeneratedPayload[] {
    return [
      {
        value: { expected_string: 12345 },
        category: "schema",
        type: "type-confusion",
        severity: "medium",
        description: "Number where string expected",
        expectedVulnerableBehavior: "Server coerces type unsafely",
        tags: ["type", "coercion"],
      },
      {
        value: { expected_number: "12345" },
        category: "schema",
        type: "type-confusion",
        severity: "medium",
        description: "String where number expected",
        expectedVulnerableBehavior: "Server parses string as number unsafely",
        tags: ["type", "coercion"],
      },
      {
        value: { expected_boolean: "true" },
        category: "schema",
        type: "type-confusion",
        severity: "low",
        description: "String where boolean expected",
        expectedVulnerableBehavior: "Server coerces truthy values",
        tags: ["type", "coercion"],
      },
      {
        value: { expected_array: { "0": "a", "1": "b", length: 2 } },
        category: "schema",
        type: "type-confusion",
        severity: "medium",
        description: "Array-like object where array expected",
        expectedVulnerableBehavior: "Server treats object as array",
        tags: ["type", "array-like"],
      },
      {
        value: { expected_object: [["key", "value"]] },
        category: "schema",
        type: "type-confusion",
        severity: "medium",
        description: "Array where object expected",
        expectedVulnerableBehavior: "Server converts array to object",
        tags: ["type", "array-to-object"],
      },
    ];
  }

  private generateBoundaryValues(): GeneratedPayload[] {
    return [
      {
        value: { number: Number.MAX_VALUE },
        category: "schema",
        type: "boundary",
        severity: "medium",
        description: "Maximum number value",
        expectedVulnerableBehavior: "Server has overflow issues",
        tags: ["boundary", "overflow"],
      },
      {
        value: { number: Number.MIN_VALUE },
        category: "schema",
        type: "boundary",
        severity: "low",
        description: "Minimum positive number value",
        expectedVulnerableBehavior: "Server has precision issues",
        tags: ["boundary", "precision"],
      },
      {
        value: { number: Number.NEGATIVE_INFINITY },
        category: "schema",
        type: "boundary",
        severity: "medium",
        description: "Negative infinity",
        expectedVulnerableBehavior: "Server mishandles infinity",
        tags: ["boundary", "infinity"],
      },
      {
        value: { number: NaN },
        category: "schema",
        type: "boundary",
        severity: "medium",
        description: "NaN value",
        expectedVulnerableBehavior: "Server mishandles NaN",
        tags: ["boundary", "nan"],
      },
      {
        value: { string: "" },
        category: "schema",
        type: "boundary",
        severity: "low",
        description: "Empty string",
        expectedVulnerableBehavior: "Server crashes on empty string",
        tags: ["boundary", "empty"],
      },
      {
        value: { string: "\u0000\u0001\u0002" },
        category: "schema",
        type: "boundary",
        severity: "medium",
        description: "Null bytes and control characters",
        expectedVulnerableBehavior: "Server mishandles control chars",
        tags: ["boundary", "control-chars"],
      },
      {
        value: { string: "a".repeat(1000000) },
        category: "schema",
        type: "boundary",
        severity: "high",
        description: "Extremely long string (1MB)",
        expectedVulnerableBehavior: "Server has memory issues",
        tags: ["boundary", "dos", "memory"],
      },
    ];
  }

  private generateNestedAttacks(): GeneratedPayload[] {
    // Generate deeply nested object
    let deepObject: Record<string, unknown> = { value: "deep" };
    for (let i = 0; i < 100; i++) {
      deepObject = { nested: deepObject };
    }

    return [
      {
        value: deepObject,
        category: "schema",
        type: "deep-nesting",
        severity: "high",
        description: "Deeply nested object (100 levels)",
        expectedVulnerableBehavior: "Server has stack overflow",
        tags: ["nesting", "dos", "stack-overflow"],
      },
      {
        value: {
          a: {
            b: { c: { d: { e: { f: { g: { h: { i: { j: "end" } } } } } } } },
          },
        },
        category: "schema",
        type: "nesting",
        severity: "low",
        description: "Moderately nested object",
        expectedVulnerableBehavior: "Server traverses without limit",
        tags: ["nesting"],
      },
      {
        value: { items: Array(10000).fill({ id: 1, name: "item" }) },
        category: "schema",
        type: "large-array",
        severity: "high",
        description: "Array with 10000 items",
        expectedVulnerableBehavior: "Server has memory issues",
        tags: ["array", "dos", "memory"],
      },
    ];
  }

  // ==================== SCHEMA PARSING METHODS ====================

  /**
   * STEP 1: Parse and normalize the JSON Schema
   * Converts the raw toolSchema into a consistent ParsedSchema structure
   */
  private parseSchema(
    toolSchema: Record<string, unknown> | null | undefined,
  ): ParsedSchema {
    if (
      !toolSchema ||
      typeof toolSchema !== "object" ||
      Array.isArray(toolSchema)
    ) {
      throw new Error(
        "Invalid toolSchema: must be a non-null, non-array object.",
      );
    }
    // Extract type (default to 'object' for MCP tool schemas)
    const type = (toolSchema.type as string) || "object";

    // Extract properties
    const properties = (toolSchema.properties as Record<string, unknown>) || {};
    const parsedProperties: Record<string, PropertySchema> = {};

    for (const [propName, propDef] of Object.entries(properties)) {
      if (typeof propDef === "object" && propDef !== null) {
        parsedProperties[propName] = this.parsePropertySchema(
          propDef as Record<string, unknown>,
        );
      }
    }

    // Extract required fields
    const required = Array.isArray(toolSchema.required)
      ? (toolSchema.required as string[])
      : [];

    // Extract additionalProperties (default to true if not specified)
    const additionalProperties =
      toolSchema.additionalProperties !== undefined
        ? Boolean(toolSchema.additionalProperties)
        : true;

    return {
      type,
      properties: parsedProperties,
      required,
      additionalProperties,
    };
  }

  /**
   * Parse a single property schema with all its constraints
   */
  private parsePropertySchema(
    propDef: Record<string, unknown>,
  ): PropertySchema {
    const schema: PropertySchema = {
      type: (propDef.type as string) || "string",
      description: propDef.description as string | undefined,
    };

    // Extract constraints
    if (propDef.maxLength !== undefined)
      schema.maxLength = propDef.maxLength as number;
    if (propDef.minLength !== undefined)
      schema.minLength = propDef.minLength as number;
    if (propDef.maximum !== undefined)
      schema.maximum = propDef.maximum as number;
    if (propDef.minimum !== undefined)
      schema.minimum = propDef.minimum as number;
    if (propDef.pattern !== undefined)
      schema.pattern = propDef.pattern as string;
    if (propDef.format !== undefined) schema.format = propDef.format as string;
    if (propDef.enum !== undefined) schema.enum = propDef.enum as unknown[];
    if (propDef.maxItems !== undefined)
      schema.maxItems = propDef.maxItems as number;
    if (propDef.minItems !== undefined)
      schema.minItems = propDef.minItems as number;

    // Handle nested objects
    if (schema.type === "object" && propDef.properties) {
      const nestedProps = propDef.properties as Record<string, unknown>;
      schema.properties = {};

      for (const [nestedName, nestedDef] of Object.entries(nestedProps)) {
        if (typeof nestedDef === "object" && nestedDef !== null) {
          schema.properties[nestedName] = this.parsePropertySchema(
            nestedDef as Record<string, unknown>,
          );
        }
      }

      // Nested required fields
      if (Array.isArray(propDef.required)) {
        schema.required = propDef.required as string[];
      }

      // Nested additionalProperties
      if (propDef.additionalProperties !== undefined) {
        schema.additionalProperties = propDef.additionalProperties as boolean;
      }
    }

    // Handle arrays
    if (schema.type === "array" && propDef.items) {
      if (typeof propDef.items === "object" && propDef.items !== null) {
        schema.items = this.parsePropertySchema(
          propDef.items as Record<string, unknown>,
        );
      }
    }

    return schema;
  }

  /**
   * STEP 2: Extract all fields from the schema (including nested)
   * Returns a flat list of FieldDescriptors with full paths
   */
  private extractFields(
    schema: ParsedSchema,
    basePath: string[] = [],
    parentRequired: string[] = [],
  ): FieldDescriptor[] {
    const fields: FieldDescriptor[] = [];
    const requiredFields = schema.required || parentRequired;

    for (const [propName, propSchema] of Object.entries(schema.properties)) {
      const currentPath = [...basePath, propName];
      const isRequired = requiredFields.includes(propName);

      // Check if this is a nested object with properties
      if (propSchema.type === "object" && propSchema.properties) {
        // Recursively extract nested fields
        const nestedSchema: ParsedSchema = {
          type: "object",
          properties: propSchema.properties,
          required: propSchema.required || [],
          additionalProperties: propSchema.additionalProperties !== false,
        };

        const nestedFields = this.extractFields(
          nestedSchema,
          currentPath,
          propSchema.required || [],
        );
        fields.push(...nestedFields);

        // Also add the parent object itself as a field
        fields.push({
          path: currentPath,
          type: propSchema.type,
          constraints: propSchema,
          required: isRequired,
          allowedValues: propSchema.enum,
        });
      } else {
        // Terminal field (string, number, boolean, array, etc.)
        fields.push({
          path: currentPath,
          type: propSchema.type,
          constraints: propSchema,
          required: isRequired,
          allowedValues: propSchema.enum,
        });
      }
    }

    return fields;
  }

  // ==================== ATTACK GENERATION METHODS ====================

  /**
   * STEP 3: Generate all attack payloads for a specific field
   */
  private generateFieldAttacks(field: FieldDescriptor): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // A. Type confusion attacks (always applicable)
    payloads.push(...this.typeConfusionAttacks(field));

    // B. Boundary attacks (if constraints exist)
    if (this.hasConstraints(field.constraints)) {
      payloads.push(...this.boundaryAttacks(field));
    }

    // C. Null/undefined injection
    payloads.push(...this.nullAttacks(field));

    // D. Enum attacks (if enum exists)
    if (field.allowedValues && field.allowedValues.length > 0) {
      payloads.push(...this.enumAttacks(field));
    }

    // E. Format-specific attacks (email, uri, date, etc.)
    if (field.constraints.format) {
      payloads.push(...this.formatAttacks(field));
    }

    return payloads;
  }

  /**
   * A. Type Confusion Attacks
   * Send wrong types to trigger unsafe type coercion
   */
  private typeConfusionAttacks(field: FieldDescriptor): GeneratedPayload[] {
    const fieldName = field.path.join(".");
    const wrongTypes: Record<string, unknown[]> = {
      string: [
        123, // number
        true, // boolean
        [], // empty array
        ["str"], // array with string
        {}, // empty object
        { toString: () => '<script>alert("XSS")</script>' }, // malicious toString
      ],
      number: [
        "123", // string number
        "0xFF", // hex string
        "Infinity", // infinity string
        "NaN", // NaN string
        [], // empty array
        {}, // empty object
      ],
      boolean: [
        "true", // string 'true'
        "false", // string 'false'
        1, // number 1
        0, // number 0
        [], // empty array
        {}, // empty object
      ],
      array: [
        "not an array", // string
        123, // number
        { 0: "item", length: 1 }, // array-like object
        { toString: () => "item1,item2" }, // object with toString
      ],
      object: [
        "not an object", // string
        123, // number
        [], // array
        JSON.stringify({ key: "value" }), // stringified JSON
      ],
    };

    const invalidValues = wrongTypes[field.type] || [];

    return invalidValues.map((value) =>
      this.createPayload(
        field,
        value,
        "type-confusion",
        "medium",
        `${typeof value} instead of ${field.type} for ${fieldName}`,
      ),
    );
  }

  /**
   * B. Boundary Value Attacks
   * Test exact boundaries and off-by-one errors
   */
  private boundaryAttacks(field: FieldDescriptor): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const fieldName = field.path.join(".");

    // STRING boundaries
    if (field.type === "string") {
      const { maxLength, minLength } = field.constraints;

      if (maxLength !== undefined) {
        payloads.push(
          this.createPayload(
            field,
            "A".repeat(maxLength),
            "boundary-max-exact",
            "low",
            `Exact maxLength (${maxLength}) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "A".repeat(maxLength + 1),
            "boundary-overflow",
            "high",
            `maxLength + 1 (${maxLength + 1}) overflow for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "A".repeat(maxLength * 10),
            "boundary-dos",
            "critical",
            `10x maxLength DoS attack for ${fieldName}`,
          ),
        );
      }

      if (minLength !== undefined) {
        payloads.push(
          this.createPayload(
            field,
            "A".repeat(minLength),
            "boundary-min-exact",
            "low",
            `Exact minLength (${minLength}) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "A".repeat(Math.max(0, minLength - 1)),
            "boundary-underflow",
            "medium",
            `minLength - 1 (${minLength - 1}) underflow for ${fieldName}`,
          ),
        );
      }

      // Always test empty string
      payloads.push(
        this.createPayload(
          field,
          "",
          "boundary-empty",
          "medium",
          `Empty string for ${fieldName}`,
        ),
      );
    }

    // NUMBER boundaries
    if (field.type === "number") {
      const { maximum, minimum } = field.constraints;

      if (maximum !== undefined) {
        payloads.push(
          this.createPayload(
            field,
            maximum,
            "boundary-max-exact",
            "low",
            `Exact maximum (${maximum}) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            maximum + 1,
            "boundary-overflow",
            "high",
            `maximum + 1 (${maximum + 1}) overflow for ${fieldName}`,
          ),
          this.createPayload(
            field,
            maximum + 1000,
            "boundary-overflow-large",
            "high",
            `Large overflow (${maximum + 1000}) for ${fieldName}`,
          ),
        );
      }

      if (minimum !== undefined) {
        payloads.push(
          this.createPayload(
            field,
            minimum,
            "boundary-min-exact",
            "low",
            `Exact minimum (${minimum}) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            minimum - 1,
            "boundary-underflow",
            "high",
            `minimum - 1 (${minimum - 1}) underflow for ${fieldName}`,
          ),
          this.createPayload(
            field,
            minimum - 1000,
            "boundary-underflow-large",
            "high",
            `Large underflow (${minimum - 1000}) for ${fieldName}`,
          ),
        );
      }

      // Special number values
      payloads.push(
        this.createPayload(
          field,
          0,
          "special-zero",
          "low",
          `Zero value for ${fieldName}`,
        ),
        this.createPayload(
          field,
          -0,
          "special-negative-zero",
          "low",
          `Negative zero for ${fieldName}`,
        ),
        this.createPayload(
          field,
          Infinity,
          "special-infinity",
          "high",
          `Infinity for ${fieldName}`,
        ),
        this.createPayload(
          field,
          -Infinity,
          "special-neg-infinity",
          "high",
          `Negative infinity for ${fieldName}`,
        ),
        this.createPayload(
          field,
          NaN,
          "special-nan",
          "medium",
          `NaN for ${fieldName}`,
        ),
        this.createPayload(
          field,
          Number.MAX_SAFE_INTEGER,
          "special-max-safe-int",
          "medium",
          `MAX_SAFE_INTEGER for ${fieldName}`,
        ),
        this.createPayload(
          field,
          Number.MIN_SAFE_INTEGER,
          "special-min-safe-int",
          "medium",
          `MIN_SAFE_INTEGER for ${fieldName}`,
        ),
      );
    }

    // ARRAY boundaries
    if (field.type === "array") {
      const { maxItems, minItems } = field.constraints;

      if (maxItems !== undefined) {
        payloads.push(
          this.createPayload(
            field,
            Array(maxItems).fill("item"),
            "boundary-max-items",
            "low",
            `Exact maxItems (${maxItems}) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            Array(maxItems + 1).fill("item"),
            "boundary-overflow-items",
            "high",
            `maxItems + 1 (${maxItems + 1}) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            Array(maxItems * 100).fill("item"),
            "boundary-dos-items",
            "critical",
            `100x maxItems DoS for ${fieldName}`,
          ),
        );
      }

      if (minItems !== undefined) {
        payloads.push(
          this.createPayload(
            field,
            Array(minItems).fill("item"),
            "boundary-min-items",
            "low",
            `Exact minItems (${minItems}) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            Array(Math.max(0, minItems - 1)).fill("item"),
            "boundary-underflow-items",
            "medium",
            `minItems - 1 (${minItems - 1}) for ${fieldName}`,
          ),
        );
      }

      // Always test empty array
      payloads.push(
        this.createPayload(
          field,
          [],
          "boundary-empty-array",
          "medium",
          `Empty array for ${fieldName}`,
        ),
      );
    }

    return payloads;
  }

  /**
   * C. Null/Undefined Injection Attacks
   * Test how the server handles missing/null values
   */
  private nullAttacks(field: FieldDescriptor): GeneratedPayload[] {
    const fieldName = field.path.join(".");

    return [
      this.createPayload(
        field,
        null,
        "null-injection",
        "medium",
        `Null value for ${fieldName}`,
      ),
      this.createPayload(
        field,
        undefined,
        "undefined-injection",
        "medium",
        `Undefined value for ${fieldName}`,
      ),
    ];
  }

  /**
   * D. Enum Bypass Attacks
   * Attempt to bypass enum validation (privilege escalation vector!)
   */
  private enumAttacks(field: FieldDescriptor): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const fieldName = field.path.join(".");
    const allowedValues = field.allowedValues!;

    // 1. Value not in enum (most critical!)
    payloads.push(
      this.createPayload(
        field,
        "INVALID_ENUM_VALUE",
        "enum-invalid",
        "critical",
        `Value outside enum for ${fieldName} (privilege escalation test)`,
      ),
    );

    // If enum contains string values, test variations
    const stringValues = allowedValues.filter(
      (v) => typeof v === "string",
    ) as string[];

    if (stringValues.length > 0) {
      const firstString = stringValues[0];

      // 2. Case sensitivity bypass
      if (firstString !== firstString.toUpperCase()) {
        payloads.push(
          this.createPayload(
            field,
            firstString.toUpperCase(),
            "enum-case-upper",
            "high",
            `Uppercase enum value for ${fieldName}`,
          ),
        );
      }
      if (firstString !== firstString.toLowerCase()) {
        payloads.push(
          this.createPayload(
            field,
            firstString.toLowerCase(),
            "enum-case-lower",
            "high",
            `Lowercase enum value for ${fieldName}`,
          ),
        );
      }

      // 3. Whitespace variations
      payloads.push(
        this.createPayload(
          field,
          ` ${firstString}`,
          "enum-leading-space",
          "high",
          `Leading space in enum for ${fieldName}`,
        ),
        this.createPayload(
          field,
          `${firstString} `,
          "enum-trailing-space",
          "high",
          `Trailing space in enum for ${fieldName}`,
        ),
        this.createPayload(
          field,
          `\t${firstString}`,
          "enum-tab",
          "medium",
          `Tab character in enum for ${fieldName}`,
        ),
      );

      // 4. If enum looks like roles, test privilege escalation
      const isRoleEnum = stringValues.some((v) =>
        ["user", "admin", "guest", "moderator", "root", "superuser"].includes(
          v.toLowerCase(),
        ),
      );

      if (isRoleEnum) {
        payloads.push(
          this.createPayload(
            field,
            "admin",
            "enum-privilege-admin",
            "critical",
            `Privilege escalation attempt: admin for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "superadmin",
            "enum-privilege-superadmin",
            "critical",
            `Privilege escalation attempt: superadmin for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "root",
            "enum-privilege-root",
            "critical",
            `Privilege escalation attempt: root for ${fieldName}`,
          ),
        );
      }
    }

    // 5. Type confusion with enum
    payloads.push(
      this.createPayload(
        field,
        [allowedValues[0]],
        "enum-array",
        "high",
        `Array instead of enum value for ${fieldName}`,
      ),
      this.createPayload(
        field,
        { value: allowedValues[0] },
        "enum-object",
        "high",
        `Object instead of enum value for ${fieldName}`,
      ),
      this.createPayload(
        field,
        allowedValues,
        "enum-all-values",
        "medium",
        `All enum values as array for ${fieldName}`,
      ),
    );

    return payloads;
  }

  /**
   * E. Format-Specific Attacks
   * Exploit format validators (email, uri, date, etc.)
   */
  private formatAttacks(field: FieldDescriptor): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const fieldName = field.path.join(".");
    const format = field.constraints.format!;

    switch (format) {
      case "email":
        payloads.push(
          this.createPayload(
            field,
            "invalid",
            "format-email-invalid",
            "medium",
            `Invalid email for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "@example.com",
            "format-email-no-local",
            "medium",
            `Email without local part for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "user@",
            "format-email-no-domain",
            "medium",
            `Email without domain for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "user@localhost",
            "format-email-localhost",
            "low",
            `Email with localhost for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "user+tag@example.com",
            "format-email-plus",
            "low",
            `Email with + character for ${fieldName}`,
          ),
          this.createPayload(
            field,
            '"()<>[]:,;@\\"!#$%&\'*+-/=?^_`{}|~.a"@example.org',
            "format-email-special",
            "medium",
            `Email with special characters for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "user@" + "a".repeat(255) + ".com",
            "format-email-long-domain",
            "high",
            `Email with very long domain for ${fieldName}`,
          ),
        );
        break;

      case "uri":
      case "url":
        payloads.push(
          this.createPayload(
            field,
            "not a url",
            "format-uri-invalid",
            "medium",
            `Invalid URI for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "javascript:alert(1)",
            "format-uri-javascript",
            "critical",
            `JavaScript URI (XSS) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "data:text/html,<script>alert(1)</script>",
            "format-uri-data-xss",
            "critical",
            `Data URI with XSS for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "file:///etc/passwd",
            "format-uri-file",
            "high",
            `File URI (path traversal) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "http://169.254.169.254/latest/meta-data/",
            "format-uri-ssrf-aws",
            "critical",
            `SSRF attempt (AWS metadata) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "http://localhost:8080/admin",
            "format-uri-ssrf-localhost",
            "high",
            `SSRF attempt (localhost) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "http://" + "a".repeat(2000) + ".com",
            "format-uri-long",
            "high",
            `Very long URI for ${fieldName}`,
          ),
        );
        break;

      case "date":
      case "date-time":
        payloads.push(
          this.createPayload(
            field,
            "not a date",
            "format-date-invalid",
            "medium",
            `Invalid date for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "9999-12-31",
            "format-date-far-future",
            "low",
            `Far future date for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "0000-01-01",
            "format-date-year-zero",
            "medium",
            `Year zero for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "2024-02-30",
            "format-date-invalid-day",
            "medium",
            `Invalid day (Feb 30) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "2024-13-01",
            "format-date-invalid-month",
            "medium",
            `Invalid month (13) for ${fieldName}`,
          ),
        );
        break;

      case "ipv4":
        payloads.push(
          this.createPayload(
            field,
            "999.999.999.999",
            "format-ipv4-overflow",
            "medium",
            `Invalid IPv4 (overflow) for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "127.0.0.1",
            "format-ipv4-localhost",
            "low",
            `Localhost IPv4 for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "0.0.0.0",
            "format-ipv4-zero",
            "medium",
            `0.0.0.0 for ${fieldName}`,
          ),
          this.createPayload(
            field,
            "169.254.169.254",
            "format-ipv4-metadata",
            "high",
            `AWS metadata IP for ${fieldName}`,
          ),
        );
        break;

      default:
        // Generic format bypass
        payloads.push(
          this.createPayload(
            field,
            "invalid_format",
            "format-generic-invalid",
            "medium",
            `Invalid ${format} format for ${fieldName}`,
          ),
        );
    }

    return payloads;
  }

  /**
   * STEP 4: Structural Attacks (schema-level, not field-specific)
   */
  private generateStructuralAttacks(schema: ParsedSchema): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // 1. Empty object
    payloads.push({
      value: {},
      category: "schema",
      type: "structural-empty",
      severity: "medium",
      description: "Empty object to test required field validation",
      expectedVulnerableBehavior: "Server accepts missing required fields",
      tags: ["structural", "missing-fields"],
    });

    // 2. Missing required fields (test each required field individually)
    for (const requiredField of schema.required) {
      const payload = this.buildValidPayloadExcept(schema, requiredField);

      if (Object.keys(payload).length > 0) {
        payloads.push({
          value: payload,
          category: "schema",
          type: "structural-missing-required",
          severity: "high",
          description: `Missing required field: ${requiredField}`,
          expectedVulnerableBehavior: `Server accepts request without ${requiredField}`,
          tags: ["structural", "missing-required", requiredField],
          targetParameter: requiredField,
        });
      }
    }

    // 3. Additional properties (mass assignment / prototype pollution)
    if (schema.additionalProperties === false) {
      const payload = this.buildValidPayload(schema);

      // Add dangerous additional properties
      (payload as Record<string, unknown>)["__proto__"] = { isAdmin: true };
      (payload as Record<string, unknown>)["constructor"] = {
        prototype: { isAdmin: true },
      };
      (payload as Record<string, unknown>)["isAdmin"] = true;
      (payload as Record<string, unknown>)["role"] = "admin";
      (payload as Record<string, unknown>)["__injected__"] = "malicious";

      payloads.push({
        value: payload,
        category: "schema",
        type: "structural-additional-props",
        severity: "critical",
        description: "Additional properties + prototype pollution test",
        expectedVulnerableBehavior:
          "Mass assignment or prototype pollution vulnerability",
        tags: ["structural", "mass-assignment", "prototype-pollution"],
      });
    }

    // 4. Deep nesting (DoS)
    payloads.push({
      value: this.createDeeplyNested(100),
      category: "schema",
      type: "structural-deep-nesting",
      severity: "high",
      description:
        "Deeply nested object (100 levels) to test parser DoS limits",
      expectedVulnerableBehavior: "Stack overflow or excessive memory usage",
      tags: ["structural", "dos", "nesting"],
    });

    return payloads;
  }

  // ==================== HELPER METHODS ====================

  /**
   * Build nested payload from path and value
   * Example: ['user', 'profile', 'name'], 'John' → { user: { profile: { name: 'John' } } }
   */
  private buildNestedPayload(
    path: string[],
    value: unknown,
  ): Record<string, unknown> {
    if (path.length === 0) {
      return typeof value === "object" && value !== null
        ? (value as Record<string, unknown>)
        : { value };
    }

    const result: Record<string, unknown> = {};
    let current = result;

    for (let i = 0; i < path.length - 1; i++) {
      current[path[i]] = {};
      current = current[path[i]] as Record<string, unknown>;
    }

    current[path[path.length - 1]] = value;
    return result;
  }

  /**
   * Create a payload with full metadata
   */
  private createPayload(
    field: FieldDescriptor,
    value: unknown,
    type: string,
    severity: "low" | "medium" | "high" | "critical",
    description: string,
  ): GeneratedPayload {
    return {
      value: this.buildNestedPayload(field.path, value),
      category: "schema",
      type,
      severity,
      description,
      targetParameter: field.path.join("."),
      expectedVulnerableBehavior: this.getExpectedBehavior(type),
      tags: [type, field.type, ...field.path],
    };
  }

  /**
   * Get expected vulnerable behavior for a given attack type
   */
  private getExpectedBehavior(type: string): string {
    const behaviors: Record<string, string> = {
      "type-confusion": "Unsafe type coercion or casting",
      "boundary-overflow": "Buffer overflow or memory corruption",
      "boundary-underflow": "Integer underflow or validation bypass",
      "boundary-dos": "Memory exhaustion or performance degradation",
      "null-injection": "Null pointer dereference or crash",
      "undefined-injection": "Undefined value handling error",
      "enum-invalid": "Enum validation bypass",
      "enum-privilege-admin": "Privilege escalation to admin",
      "enum-privilege-superadmin": "Privilege escalation to superadmin",
      "enum-privilege-root": "Privilege escalation to root",
      "format-uri-javascript": "XSS via JavaScript URI",
      "format-uri-ssrf-aws": "SSRF to AWS metadata endpoint",
      "format-uri-ssrf-localhost": "SSRF to localhost services",
      "structural-additional-props": "Mass assignment or prototype pollution",
      "structural-missing-required": "Required field validation bypass",
    };

    return behaviors[type] || "Server mishandles invalid input";
  }

  /**
   * Check if field has any constraints
   */
  private hasConstraints(constraints: PropertySchema): boolean {
    return !!(
      constraints.maxLength ||
      constraints.minLength ||
      constraints.maximum ||
      constraints.minimum ||
      constraints.maxItems ||
      constraints.minItems ||
      constraints.pattern ||
      constraints.format
    );
  }

  /**
   * Build a valid payload based on schema (for structural tests)
   */
  private buildValidPayload(schema: ParsedSchema): Record<string, unknown> {
    const payload: Record<string, unknown> = {};

    for (const [propName, propSchema] of Object.entries(schema.properties)) {
      payload[propName] = this.getDefaultValue(propSchema);
    }

    return payload;
  }

  /**
   * Build a valid payload except for one field
   */
  private buildValidPayloadExcept(
    schema: ParsedSchema,
    exceptField: string,
  ): Record<string, unknown> {
    const payload: Record<string, unknown> = {};

    for (const [propName, propSchema] of Object.entries(schema.properties)) {
      if (propName !== exceptField) {
        payload[propName] = this.getDefaultValue(propSchema);
      }
    }

    return payload;
  }

  /**
   * Get a default/valid value for a property type
   */
  private getDefaultValue(propSchema: PropertySchema): unknown {
    switch (propSchema.type) {
      case "string":
        return propSchema.enum ? propSchema.enum[0] : "valid_string";
      case "number":
        return propSchema.enum ? propSchema.enum[0] : 42;
      case "boolean":
        return true;
      case "array":
        return [];
      case "object":
        return {};
      default:
        return null;
    }
  }

  /**
   * Create deeply nested object for DoS testing
   */
  private createDeeplyNested(depth: number): Record<string, unknown> {
    if (depth <= 0) return { value: "leaf" };
    return { nested: this.createDeeplyNested(depth - 1) };
  }
}
