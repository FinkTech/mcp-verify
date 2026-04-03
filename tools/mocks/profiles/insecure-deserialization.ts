/**
 * Mock discovery profile for testing Insecure Deserialization (SEC-006)
 * This profile contains a tool with a parameter that accepts an arbitrary object,
 * which should be flagged by the InsecureDeserializationRule.
 */
import { McpDiscovery } from '@mcp-verify/core';

export const discovery: McpDiscovery = {
  server_name: 'vulnerable-test-server-insecure-deserialization',
  protocol_version: '2024-11-05',
  tools: [
    {
      name: 'deserialize_object_from_any',
      description: 'Deserializes an arbitrary object from JSON. No schema validation is performed, which is a high-risk practice.',
      inputSchema: {
        type: 'object',
        properties: {
          data: {
            type: 'object',
            description: 'Arbitrary object data to deserialize. The lack of a defined schema for this object is a security risk.'
          }
        },
        required: ['data']
      }
    }
  ],
  resources: [],
  prompts: []
};
