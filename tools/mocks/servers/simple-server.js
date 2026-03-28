/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Simple MCP Server Mock
 *
 * A basic, valid MCP server for testing mcp-verify.
 * This server follows best practices and should pass all validations.
 */

const readline = require('readline');

// MCP Server state
const serverInfo = {
  name: 'simple-test-server',
  version: '1.0.0'
};

// Available tools
const tools = [
  {
    name: 'get_weather',
    description: 'Get current weather for a location',
    inputSchema: {
      type: 'object',
      properties: {
        location: {
          type: 'string',
          description: 'City name or coordinates'
        }
      },
      required: ['location']
    }
  },
  {
    name: 'calculate',
    description: 'Perform basic mathematical calculations',
    inputSchema: {
      type: 'object',
      properties: {
        operation: {
          type: 'string',
          enum: ['add', 'subtract', 'multiply', 'divide'],
          description: 'Mathematical operation to perform'
        },
        a: {
          type: 'number',
          description: 'First operand'
        },
        b: {
          type: 'number',
          description: 'Second operand'
        }
      },
      required: ['operation', 'a', 'b']
    }
  }
];

// Available resources
const resources = [
  {
    name: 'documentation',
    uri: 'file:///docs/readme.md',
    mimeType: 'text/markdown',
    description: 'Server documentation'
  }
];

// Available prompts
const prompts = [
  {
    name: 'greeting',
    description: 'A friendly greeting prompt',
    arguments: [
      {
        name: 'name',
        description: 'Name of the person to greet',
        required: true
      }
    ]
  }
];

// JSON-RPC message handler
function handleMessage(message) {
  const { jsonrpc, id, method, params } = message;

  // Validate JSON-RPC 2.0
  if (jsonrpc !== '2.0') {
    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32600,
        message: 'Invalid Request - jsonrpc must be "2.0"'
      }
    };
  }

  // Handle different methods
  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
            resources: {},
            prompts: {}
          },
          serverInfo
        }
      };

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools
        }
      };

    case 'resources/list':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          resources
        }
      };

    case 'prompts/list':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          prompts
        }
      };

    case 'tools/call':
      const { name, arguments: args } = params;

      if (name === 'get_weather') {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: `Weather in ${args.location}: Sunny, 22°C`
              }
            ]
          }
        };
      }

      if (name === 'calculate') {
        let result;
        switch (args.operation) {
          case 'add': result = args.a + args.b; break;
          case 'subtract': result = args.a - args.b; break;
          case 'multiply': result = args.a * args.b; break;
          case 'divide': result = args.a / args.b; break;
        }

        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: `Result: ${result}`
              }
            ]
          }
        };
      }

      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32601,
          message: `Tool not found: ${name}`
        }
      };

    default:
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32601,
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
    console.log(JSON.stringify(response));
  } catch (error) {
    console.log(JSON.stringify({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32700,
        message: 'Parse error'
      }
    }));
  }
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  process.exit(0);
});

process.on('SIGTERM', () => {
  process.exit(0);
});
