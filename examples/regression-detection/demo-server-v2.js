#!/usr/bin/env node

/**
 * Demo MCP Server v2.0.0 - INSECURE VERSION (⚠️ WITH VULNERABILITIES)
 *
 * This version introduces SECURITY ISSUES:
 * - ❌ No input validation
 * - ❌ Command injection vulnerability
 * - ❌ Path traversal risk
 * - ❌ Missing error handling
 *
 * Expected Security Score: ~45/100
 *
 * DO NOT USE IN PRODUCTION - FOR DEMO PURPOSES ONLY
 */

const readline = require("readline");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// Server info
const SERVER_INFO = {
  name: "demo-mcp-server",
  version: "2.0.0",
  protocolVersion: "2024-11-05",
};

// Tools with NEW vulnerable features
const TOOLS = [
  {
    name: "echo",
    description: "Echo back a message",
    inputSchema: {
      type: "object",
      properties: {
        message: { type: "string" },
      },
      required: ["message"],
    },
  },
  {
    name: "add_numbers",
    description: "Add two numbers together",
    inputSchema: {
      type: "object",
      properties: {
        a: { type: "number" },
        b: { type: "number" },
      },
      required: ["a", "b"],
    },
  },
  {
    name: "get_time",
    description: "Get current server time",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  // NEW VULNERABLE TOOL #1
  {
    name: "execute_command",
    description: "Execute a system command",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Command to execute" },
      },
      required: ["command"],
    },
  },
  // NEW VULNERABLE TOOL #2
  {
    name: "read_file",
    description: "Read a file from disk",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "File path to read" },
      },
      required: ["path"],
    },
  },
];

// JSON-RPC message handler
function handleMessage(msg) {
  const { id, method, params } = msg;

  // Initialize response
  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
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
  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        tools: TOOLS,
      },
    };
  }

  // Execute tool WITHOUT VALIDATION (VULNERABLE!)
  if (method === "tools/call") {
    const { name, arguments: args } = params;

    try {
      let result;

      if (name === "echo") {
        // ❌ No validation - accepts any input
        result = { message: args.message };
      } else if (name === "add_numbers") {
        // ❌ No type checking
        result = { sum: args.a + args.b };
      } else if (name === "get_time") {
        result = { time: new Date().toISOString() };
      } else if (name === "execute_command") {
        // ⚠️ CRITICAL VULNERABILITY: Command Injection
        // Directly executes user input without sanitization
        const output = execSync(args.command, { encoding: "utf-8" });
        result = { output };
      } else if (name === "read_file") {
        // ⚠️ CRITICAL VULNERABILITY: Path Traversal
        // Reads any file without path validation
        const content = fs.readFileSync(args.path, "utf-8");
        result = { content };
      } else {
        throw new Error("Tool not found");
      }

      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(result) }],
        },
      };
    } catch (error) {
      // ❌ Exposes error details (information leakage)
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: error.message, stack: error.stack },
      };
    }
  }

  // Unknown method
  return {
    jsonrpc: "2.0",
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

rl.on("line", (line) => {
  try {
    const msg = JSON.parse(line);
    const response = handleMessage(msg);
    console.log(JSON.stringify(response));
  } catch (error) {
    console.error(
      JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      }),
    );
  }
});

process.on("SIGINT", () => {
  process.exit(0);
});

// Indicate ready
if (process.send) {
  process.send({ type: "ready" });
}
