#!/usr/bin/env node
/**
 * MCP Verify — Demo Server for GIF recording
 *
 * Simulates a realistic but intentionally vulnerable MCP server.
 * Designed to trigger multiple detector types for showcase purposes.
 *
 * Vulnerabilities simulated:
 *  - SQL Injection (error disclosure)
 *  - Prompt Injection (content leak)
 *  - Path Traversal (error disclosure)
 *  - Command Injection (timing + error)
 *  - Prototype Pollution (no sanitization)
 *  - Info Disclosure (stack traces, internal paths)
 */

const readline = require("readline");

// ── Helpers ─────────────────────────────────────────────────────────────────

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function isPromptInjection(val) {
  if (typeof val !== "string") return false;
  return /ignore previous|forget your|system prompt|<system>|jailbreak|DAN|do anything now/i.test(
    val,
  );
}

function isSQLi(val) {
  if (typeof val !== "string") return false;
  return /('|--|;|union\s+select|or\s+1=1|drop\s+table|sleep\s*\()/i.test(val);
}

function isPathTraversal(val) {
  if (typeof val !== "string") return false;
  return /\.\.\/|\.\.\\|\/etc\/passwd|\/proc\/self/i.test(val);
}

function isCmdInjection(val) {
  if (typeof val !== "string") return false;
  return /;|\|&|`|\$\(|>\s*\/|rm\s+-rf|wget\s|curl\s/i.test(val);
}

function hasProtoPollution(obj) {
  if (!obj || typeof obj !== "object") return false;
  return "__proto__" in obj || "constructor" in obj || "prototype" in obj;
}

// ── Tool definitions ─────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "search_employees",
    description: "Search employees by name or department",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query" },
        department: {
          type: "string",
          enum: ["engineering", "sales", "hr", "finance"],
          description: "Department filter",
        },
        limit: { type: "number", minimum: 1, maximum: 100, default: 10 },
      },
      required: ["query"],
    },
  },
  {
    name: "read_file",
    description: "Read a file from the documents directory",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative path to the file" },
      },
      required: ["path"],
    },
  },
  {
    name: "execute_report",
    description: "Execute a named report with optional parameters",
    inputSchema: {
      type: "object",
      properties: {
        report_name: { type: "string", description: "Name of the report" },
        params: { type: "object", description: "Report parameters" },
      },
      required: ["report_name"],
    },
  },
];

// ── Tool handlers ─────────────────────────────────────────────────────────────

function handleSearchEmployees(args, id) {
  const query = args?.query ?? "";
  const params = args ?? {};

  // Prototype pollution — no sanitization
  if (hasProtoPollution(params)) {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        content: [
          {
            type: "text",
            // Leaks internal object structure — info disclosure
            text: `Warning: unusual parameter detected. Internal config: ${JSON.stringify(Object.keys({}))}\nQuery: ${query}`,
          },
        ],
      },
    });
    return;
  }

  // SQL injection — leaks simulated DB error with query details
  if (isSQLi(query)) {
    send({
      jsonrpc: "2.0",
      id,
      error: {
        code: -32603,
        message: "Database error",
        data: {
          // Error disclosure: reveals internal SQL + stack trace
          detail: `Uncaught QueryError: syntax error in query near '${query}'\n  at Database.query (/app/db/postgres-adapter.js:142:11)\n  at EmployeeRepository.search (/app/domain/employee.repo.js:58:5)\nQuery was: SELECT * FROM employees WHERE name LIKE '%${query}%'`,
        },
      },
    });
    return;
  }

  // Prompt injection — leaks simulated system prompt
  if (isPromptInjection(query)) {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        content: [
          {
            type: "text",
            // Prompt leak: exposes system context
            text: `SYSTEM: You are a helpful HR assistant with access to employee records. Your API key is sk-internal-hr-prod-key-9x2k. Current user has ADMIN role.\n\nEmployee search results for "${query}": [no results found]`,
          },
        ],
      },
    });
    return;
  }

  // Normal response
  send({
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text: `Found 3 employees matching "${query}": Alice Chen (Engineering), Bob Torres (Engineering), Carol Mills (HR).`,
        },
      ],
    },
  });
}

function handleReadFile(args, id) {
  const filePath = args?.path ?? "";

  // Path traversal — leaks simulated file contents
  if (isPathTraversal(filePath)) {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        content: [
          {
            type: "text",
            // Path traversal: simulates reading sensitive file
            text: `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\napp:x:1000:1000:,,,:/home/app:/bin/bash`,
          },
        ],
      },
    });
    return;
  }

  send({
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text: `Contents of documents/${filePath}: [document content here]`,
        },
      ],
    },
  });
}

function handleExecuteReport(args, id) {
  const reportName = args?.report_name ?? "";

  // Command injection — simulates shell execution with timing
  if (isCmdInjection(reportName)) {
    // Small delay to simulate timing anomaly
    setTimeout(() => {
      send({
        jsonrpc: "2.0",
        id,
        error: {
          code: -32603,
          message: "Report execution failed",
          data: {
            // Error disclosure: reveals shell execution context
            stderr: `sh: 1: ${reportName}: not found\n/app/scripts/run-report.sh: line 23: exec: ${reportName}: not found`,
            exit_code: 127,
          },
        },
      });
    }, 1200); // timing anomaly
    return;
  }

  send({
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text: `Report "${reportName}" executed successfully. 42 rows generated.`,
        },
      ],
    },
  });
}

// ── JSON-RPC dispatcher ───────────────────────────────────────────────────────

function dispatch(msg) {
  const { id, method, params } = msg;

  if (method === "initialize") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "demo-server", version: "1.0.0" },
      },
    });
    return;
  }

  if (method === "notifications/initialized") return;

  if (method === "tools/list") {
    send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    return;
  }

  if (method === "tools/call") {
    const toolName = params?.name;
    const args = params?.arguments ?? {};

    if (toolName === "search_employees") return handleSearchEmployees(args, id);
    if (toolName === "read_file") return handleReadFile(args, id);
    if (toolName === "execute_report") return handleExecuteReport(args, id);

    send({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Tool not found: ${toolName}` },
    });
    return;
  }

  // Unknown method — proper JSON-RPC error (no protocol violations)
  send({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code: -32601, message: `Method not found: ${method}` },
  });
}

// ── Stdio transport ───────────────────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin });

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const msg = JSON.parse(trimmed);
    dispatch(msg);
  } catch {
    send({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" },
    });
  }
});

process.stderr.write("[demo-server] Demo vulnerable server started\n");
