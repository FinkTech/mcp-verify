#!/usr/bin/env node
/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Vulnerable MCP Server Mock
 *
 * ⚠️ WARNING: This server contains INTENTIONAL security vulnerabilities
 * for testing mcp-verify's security detection capabilities.
 *
 * DO NOT use this as a template for real servers!
 *
 * Vulnerabilities included:
 * - SQL Injection (SEC-001)
 * - Command Injection (SEC-002)
 * - SSRF (SEC-003)
 * - Data Leakage (SEC-004)
 * - Path Traversal (SEC-005)
 * - Sensitive Data Exposure (SEC-010)
 */

const readline = require("readline");

// Language support
const lang = process.argv.includes("--lang")
  ? process.argv[process.argv.indexOf("--lang") + 1]
  : "en";
const isEs = lang === "es";

const serverInfo = {
  name: "vulnerable-test-server",
  version: "1.0.0",
};

// Tools with security vulnerabilities (localized)
const tools = [
  {
    name: "execute_sql",
    description: isEs
      ? "Ejecutar consulta SQL: SELECT * FROM users WHERE id = ${user_id}"
      : "Execute SQL query: SELECT * FROM users WHERE id = ${user_id}",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: isEs
            ? "Consulta SQL a ejecutar"
            : "SQL query to execute",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "run_command",
    description: isEs
      ? "Ejecutar comando del sistema: exec(command)"
      : "Run system command: exec(command)",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string",
          description: isEs
            ? "Comando del sistema a ejecutar"
            : "System command to execute",
        },
      },
      required: ["command"],
    },
  },
  {
    name: "fetch_url",
    description: isEs
      ? "Obtener datos de cualquier URL, incluyendo direcciones de red interna"
      : "Fetch data from any URL including internal network addresses",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: isEs
            ? "URL a obtener (soporta http://localhost, http://192.168.x.x, etc.)"
            : "URL to fetch (supports http://localhost, http://192.168.x.x, etc.)",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "read_file",
    description: isEs
      ? "Leer cualquier archivo del sistema usando una ruta como ../../etc/passwd"
      : "Read any file from filesystem using path like ../../etc/passwd",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: isEs
            ? "Ruta del archivo (soporta saltos de directorio ..)"
            : "File path (supports .. traversal)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "get_credentials",
    description: isEs
      ? 'Obtener credenciales de API. Devuelve: { api_key: "sk-1234567890abcdef", secret: "secret_key_here" }'
      : 'Get API credentials. Returns: { api_key: "sk-1234567890abcdef", secret: "secret_key_here" }',
    inputSchema: {
      type: "object",
      properties: {
        service: {
          type: "string",
          description: isEs ? "Nombre del servicio" : "Service name",
        },
      },
    },
  },
  {
    name: "authenticate",
    description: isEs
      ? "Autenticar usuario con contraseña almacenada en texto plano"
      : "Authenticate user with password stored in plain text",
    inputSchema: {
      type: "object",
      properties: {
        username: {
          type: "string",
        },
        password: {
          type: "string",
          description: isEs
            ? "Contraseña en texto plano"
            : "Plain text password",
        },
      },
      required: ["username", "password"],
    },
  },
  {
    name: "parse_xml",
    description: isEs
      ? "Analizar documento XML (vulnerable a ataques XXE)"
      : "Parse XML document (vulnerable to XXE attacks)",
    inputSchema: {
      type: "object",
      properties: {
        xml: {
          type: "string",
          description: isEs
            ? "Documento XML a analizar"
            : "XML document to parse",
        },
      },
    },
  },
  {
    name: "deserialize",
    description: isEs
      ? "Deserializar objeto desde una cadena JSON usando eval()"
      : "Deserialize object from JSON string using eval()",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "string",
          description: isEs ? "Objeto serializado" : "Serialized object",
        },
      },
    },
  },
];

const resources = [
  {
    name: "admin_config",
    uri: "file:///etc/passwd",
    description: isEs
      ? "Archivo de configuración de administrador"
      : "Admin configuration file",
    mimeType: "text/plain",
  },
  {
    name: "database",
    uri: "mysql://root:password123@localhost/db",
    description: isEs
      ? "Conexión a base de datos con credenciales en la URI"
      : "Database connection with credentials in URI",
    mimeType: "application/sql",
  },
];

const prompts = [
  {
    name: "admin_prompt",
    description: isEs
      ? "Prompt de administrador con clave de API hardcodeada: sk-1234567890abcdef"
      : "Admin prompt with hardcoded API key: sk-1234567890abcdef",
  },
];

function handleMessage(message) {
  const { jsonrpc, id, method, params } = message;

  if (jsonrpc !== "2.0") {
    return {
      jsonrpc: "2.0",
      id,
      error: {
        code: -32600,
        message: "Invalid Request",
      },
    };
  }

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: {},
            resources: {},
            prompts: {},
          },
          serverInfo,
        },
      };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools,
        },
      };

    case "resources/list":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          resources,
        },
      };

    case "prompts/list":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          prompts,
        },
      };

    case "tools/call":
      const { name, arguments: args } = params;

      // Simulate vulnerable responses
      if (name === "execute_sql") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: "Query executed successfully (vulnerable to SQL injection)",
              },
            ],
          },
        };
      }

      if (name === "get_credentials") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  api_key: "sk-1234567890abcdef",
                  secret: "secret_key_here",
                  password: "admin123",
                }),
              },
            ],
          },
        };
      }

      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: `Tool ${name} executed (contains vulnerabilities)`,
            },
          ],
        },
      };

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32601,
          message: `Method not found: ${method}`,
        },
      };
  }
}

// Start stdio server
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on("line", (line) => {
  try {
    const message = JSON.parse(line);
    const response = handleMessage(message);
    console.log(JSON.stringify(response));
  } catch (error) {
    console.log(
      JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32700,
          message: "Parse error",
        },
      }),
    );
  }
});

process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));
