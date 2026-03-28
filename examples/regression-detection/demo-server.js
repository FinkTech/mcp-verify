#!/usr/bin/env node

/**
 * Demo MCP Server v1.0.0 - SECURE VERSION
 *
 * This is a simple MCP server with GOOD security practices:
 * - Input validation
 * - Safe command execution
 * - No path traversal
 * - Proper error handling
 *
 * Expected Security Score: ~95/100
 */

const readline = require('readline');

// Language support
const lang = process.argv.includes('--lang') ? process.argv[process.argv.indexOf('--lang') + 1] : 'en';
const isEs = lang === 'es';

// Server info
const SERVER_INFO = {
  name: 'demo-mcp-server',
  version: '1.0.0',
  protocolVersion: '2024-11-05',
};

// Tools with proper validation
const TOOLS = [
  {
    name: 'echo',
    description: isEs 
      ? 'Devolver un mensaje (implementación segura)' 
      : 'Echo back a message (safe implementation)',
    inputSchema: {
      type: 'object',
      properties: {
        message: { 
          type: 'string', 
          description: isEs ? 'Mensaje a devolver' : 'Message to echo' 
        },
      },
      required: ['message'],
    },
  },
  {
    name: 'add_numbers',
    description: isEs ? 'Sumar dos números' : 'Add two numbers together',
    inputSchema: {
      type: 'object',
      properties: {
        a: { type: 'number', description: isEs ? 'Primer número' : 'First number' },
        b: { type: 'number', description: isEs ? 'Segundo número' : 'Second number' },
      },
      required: ['a', 'b'],
    },
  },
  {
    name: 'get_time',
    description: isEs ? 'Obtener la hora actual del servidor' : 'Get current server time',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

// JSON-RPC message handler
function handleMessage(msg) {
  const { id, method, params } = msg;

  // Initialize response
  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: SERVER_INFO.protocolVersion,
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: SERVER_INFO.name,
          version: SERVER_INFO.version,
        },
      },
    };
  }

  // List tools
  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: TOOLS,
      },
    };
  }

  // Execute tool with PROPER VALIDATION
  if (method === 'tools/call') {
    const { name, arguments: args } = params;

    // Validate tool exists
    const tool = TOOLS.find((t) => t.name === name);
    if (!tool) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Tool not found: ${name}` },
      };
    }

    // Execute tool SAFELY
    try {
      let result;

      if (name === 'echo') {
        // Validate input
        if (!args.message || typeof args.message !== 'string') {
          throw new Error('Invalid message parameter');
        }
        // Safe - just echo back
        result = { message: args.message };
      } else if (name === 'add_numbers') {
        // Validate inputs
        if (typeof args.a !== 'number' || typeof args.b !== 'number') {
          throw new Error('Parameters must be numbers');
        }
        result = { sum: args.a + args.b };
      } else if (name === 'get_time') {
        result = { time: new Date().toISOString() };
      } else {
        throw new Error('Tool implementation not found');
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result) }],
        },
      };
    } catch (error) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32603, message: error.message },
      };
    }
  }

  // Unknown method
  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not found: ${method}` },
  };
}

// Main stdio loop
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    const response = handleMessage(msg);
    console.log(JSON.stringify(response));
  } catch (error) {
    console.error(
      JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      })
    );
  }
});

process.on('SIGINT', () => {
  process.exit(0);
});

// Indicate ready
if (process.send) {
  process.send({ type: 'ready' });
}
