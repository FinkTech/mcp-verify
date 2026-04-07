/**
 * Mock discovery profile for testing Insecure Deserialization (SEC-006)
 * This profile contains a tool with a parameter that accepts an arbitrary object,
 * which should be flagged by the InsecureDeserializationRule.
 */
import type { DiscoveryResult } from "@mcp-verify/core";

export const discovery: DiscoveryResult = {
  serverInfo: {
    name: "vulnerable-test-server-insecure-deserialization",
  },
  tools: [
    {
      name: "deserialize_object_from_any",
      description:
        "Deserializes an arbitrary object from JSON. No schema validation is performed, which is a high-risk practice.",
      inputSchema: {
        type: "object",
        properties: {
          data: {
            type: "object",
            description:
              "Arbitrary object data to deserialize. The lack of a defined schema for this object is a security risk.",
          },
        },
        required: ["data"],
      },
    },
  ],
  resources: [],
  prompts: [],
};
