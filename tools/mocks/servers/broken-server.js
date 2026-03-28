#!/usr/bin/env node
/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */

/**
 * Broken MCP Server Mock
 *
 * A server with protocol violations for testing mcp-verify's
 * protocol compliance detection.
 *
 * Issues included:
 * - Invalid JSON-RPC responses
 * - Missing required fields
 * - Invalid schema structures
 * - Wrong protocol version
 * - Malformed tool definitions
 */

const readline = require('readline');

const serverInfo = {
  name: 'broken-test-server',
  version: '0.1.0'
};

// Malformed tools (missing required fields, invalid schemas)
const tools = [
  {
    // Missing 'name' field
    description: 'This tool is missing a name field',
    inputSchema: {
      type: 'object'
    }
  },
  {
    name: 'invalid_schema',
    description: 'Tool with invalid input schema',
    inputSchema: 'this should be an object, not a string'
  },
  {
    name: 'incomplete_tool',
    // Missing description field
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'bad_parameters',
    description: 'Tool with malformed parameters',
    inputSchema: {
      type: 'object',
      properties: {
        param1: 'invalid type definition'
      }
    }
  }
];

// Malformed resources
const resources = [
  {
    // Missing 'name' and 'uri'
    description: 'Incomplete resource',
    mimeType: 'text/plain'
  },
  {
    name: 'invalid_uri',
    uri: 'not-a-valid-uri',
    description: 'Resource with invalid URI'
  }
];

// Malformed prompts
const prompts = [
  {
    // Missing name
    description: 'Prompt without name'
  },
  {
    name: 'bad_arguments',
    description: 'Prompt with invalid arguments structure',
    arguments: 'should be an array'
  }
];

let requestCount = 0;

function handleMessage(message) {
  requestCount++;

  const { jsonrpc, id, method, params } = message;

  // Sometimes return invalid JSON-RPC
  if (requestCount % 5 === 0) {
    return {
      // Missing jsonrpc field
      id,
      result: {
        message: 'Invalid response - missing jsonrpc field'
      }
    };
  }

  // Sometimes use wrong protocol version
  if (requestCount % 7 === 0) {
    return {
      jsonrpc: '1.0', // Wrong version
      id,
      result: {
        message: 'Wrong JSON-RPC version'
      }
    };
  }

  switch (method) {
    case 'initialize':
      // Return invalid initialize response
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2023-01-01', // Wrong protocol version
          // Missing capabilities field
          serverInfo: {
            name: 'broken-server'
            // Missing version field
          }
        }
      };

    case 'tools/list':
      // Sometimes return invalid structure
      if (requestCount % 3 === 0) {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            // Wrong field name
            toolsList: tools
          }
        };
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools // Returns malformed tools
        }
      };

    case 'resources/list':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          resources // Returns malformed resources
        }
      };

    case 'prompts/list':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          prompts // Returns malformed prompts
        }
      };

    case 'tools/call':
      const { name, arguments: args } = params;

      // Return malformed tool response
      return {
        jsonrpc: '2.0',
        id,
        result: {
          // Missing 'content' array
          text: 'This should be in a content array',
          type: 'text'
        }
      };

    default:
      // Return error without proper structure
      return {
        jsonrpc: '2.0',
        id,
        error: {
          // Missing 'code' field
          message: `Method not found: ${method}`
        }
      };
  }
}

// Start stdio server
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const message = JSON.parse(line);
    const response = handleMessage(message);

    // Sometimes output invalid JSON
    if (requestCount % 11 === 0) {
      console.log('{ invalid json response }');
    } else {
      console.log(JSON.stringify(response));
    }
  } catch (error) {
    // Return malformed error
    console.log('{"error": "parse error but missing jsonrpc field"}');
  }
});

process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
