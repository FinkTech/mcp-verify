/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Configurable Vulnerable MCP Server
 *
 * ⚠️ WARNING: This server contains INTENTIONAL security vulnerabilities
 * for testing mcp-verify's security detection capabilities.
 *
 * DO NOT use this as a template for real servers!
 *
 * Usage:
 *   node configurable-server.ts --profile=ssrf --lang=en
 *   node configurable-server.ts --profile=all-vulns --lang=es
 *
 * Profiles (60 Security Rules Coverage):
 *
 * OWASP Top 10 Adapted (SEC-001 to SEC-012):
 *   - auth-bypass: SEC-001 (Auth Bypass)
 *   - command-injection: SEC-002 (Command Injection)
 *   - sql-injection: SEC-003 (SQL Injection)
 *   - ssrf: SEC-004 (Server-Side Request Forgery)
 *   - xxe: SEC-005 (XXE Injection)
 *   - insecure-deserialization: SEC-006 (Insecure Deserialization)
 *   - path-traversal: SEC-007 (Path Traversal)
 *   - data-leakage: SEC-008 (Data Leakage)
 *   - sensitive-exposure: SEC-009 (Sensitive Data Exposure)
 *   - missing-rate-limit: SEC-010 (Missing Rate Limiting)
 *   - redos: SEC-011 (ReDoS Detection)
 *   - weak-crypto: SEC-012 (Weak Crypto)
 *
 * MCP-Specific (SEC-013 to SEC-029):
 *   - prompt-injection: SEC-013 (Prompt Injection)
 *   - exposed-endpoint: SEC-014 (Exposed Endpoint)
 *   - missing-authentication: SEC-015 (Missing Authentication)
 *   - insecure-uri: SEC-016 (Insecure URI Scheme)
 *   - excessive-permissions: SEC-017 (Excessive Permissions)
 *   - secrets-in-descriptions: SEC-018 (Secrets in Descriptions)
 *   - missing-input-constraints: SEC-019 (Missing Input Constraints)
 *   - dangerous-tool-chaining: SEC-020 (Dangerous Tool Chaining)
 *   - unencrypted-credentials: SEC-021 (Unencrypted Credentials)
 *   - insecure-output: SEC-022 (Insecure Output Handling)
 *   - excessive-agency: SEC-023 (Excessive Agency)
 *   - prompt-injection-via-tools: SEC-024 (Prompt Injection via Tools)
 *   - supply-chain: SEC-025 (Supply Chain Tool Dependencies)
 *   - sensitive-data-in-tool-responses: SEC-026 (Sensitive Data in Responses)
 *   - training-poison: SEC-027 (Training Data Poisoning)
 *   - model-dos: SEC-028 (Model DoS via Tools)
 *   - insecure-plugin: SEC-029 (Insecure Plugin Design)
 *
 * LLM/AI & Multi-Agent (SEC-030 to SEC-060):
 *   - excessive-disclosure: SEC-030 (Excessive Data Disclosure)
 *   - identity-spoofing: SEC-031 (Agent Identity Spoofing)
 *   - result-tamper: SEC-032 (Tool Result Tampering)
 *   - recursive-loop: SEC-033 (Recursive Agent Loop)
 *   - privilege-escalation: SEC-034 (Multi-Agent Privilege Escalation)
 *   - agent-state-poisoning: SEC-035 (Agent State Poisoning)
 *   - distributed-ddos: SEC-036 (Distributed Agent DDoS)
 *   - cross-agent-injection: SEC-037 (Cross-Agent Prompt Injection)
 *   - reputation-hijack: SEC-038 (Agent Reputation Hijacking)
 *   - chaining-traversal: SEC-039 (Tool Chaining Path Traversal)
 *   - swarm-attack: SEC-040 (Agent Swarm Coordination Attack)
 *   - memory-injection: SEC-041 (Agent Memory Injection)
 *   - missing-audit: SEC-042 (Missing Audit Logging)
 *   - insecure-session: SEC-043 (Insecure Session Management)
 *   - schema-versioning: SEC-044 (Schema Versioning Absent)
 *   - error-granularity: SEC-045 (Insufficient Error Granularity)
 *   - missing-cors: SEC-046 (Missing CORS Validation)
 *   - insecure-defaults: SEC-047 (Insecure Default Configuration)
 *   - missing-capability: SEC-048 (Missing Capability Negotiation)
 *   - timing-side-channel: SEC-049 (Timing Side Channel Auth)
 *   - output-entropy: SEC-050 (Insufficient Output Entropy)
 *   - weaponized-fuzzer: SEC-051 (Weaponized MCP Fuzzer)
 *   - autonomous-backdoor: SEC-052 (Autonomous MCP Backdoor)
 *   - malicious-config-file: SEC-053 (Malicious Config File)
 *   - endpoint-hijack: SEC-054 (API Endpoint Hijacking)
 *   - jailbreak-service: SEC-055 (Jailbreak as Service)
 *   - phishing: SEC-056 (Phishing via MCP)
 *   - data-exfiltration-steganography: SEC-057 (Data Exfiltration)
 *   - self-replicating: SEC-058 (Self-Replicating MCP)
 *   - unvalidated-tool-auth: SEC-059 (Unvalidated Tool Authorization)
 *   - missing-transaction: SEC-060 (Missing Transaction Semantics)
 *
 *   - all-vulns: All vulnerabilities enabled (comprehensive testing)
 */

import * as readline from "readline";

// Parse CLI arguments
function parseArgs(): { profile: string; lang: string } {
  const args = process.argv.slice(2);
  let profile = "all-vulns";
  let lang = "en";

  for (const arg of args) {
    if (arg.startsWith("--profile=")) {
      profile = arg.split("=")[1];
    } else if (arg.startsWith("--lang=")) {
      lang = arg.split("=")[1];
    }
  }

  return { profile, lang };
}

const { profile, lang } = parseArgs();
const isEs = lang === "es";

const serverInfo = {
  name: `vulnerable-test-server-${profile}`,
  version: "1.0.0",
  profile,
};

interface JsonRpcRequest {
  jsonrpc: string;
  id: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: string;
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string };
}

// Vulnerability profiles
interface Tool {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<
      string,
      { type: string; description: string; [key: string]: unknown }
    >;
    required?: string[];
  };
}

interface Resource {
  name: string;
  uri: string;
  description: string;
  mimeType: string;
}

interface Prompt {
  name: string;
  description: string;
}

// Tool definitions by vulnerability type
const VULN_TOOLS: Record<string, Tool[]> = {
  // SEC-003: SQL Injection
  "sql-injection": [
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
  ],

  // SEC-002: Command Injection
  "command-injection": [
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
  ],

  ssrf: [
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
  ],

  "path-traversal": [
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
  ],

  "sensitive-exposure": [
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
            description: isEs ? "Nombre de usuario" : "Username",
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
  ],

  // SEC-013: prompt-injection
  "prompt-injection": [
    {
      name: "generate_response",
      description: isEs
        ? "Generar respuesta de IA insertando el input del usuario directamente en el prompt del sistema sin sanitización"
        : "Generate AI response by inserting user input directly into system prompt without sanitization",
      inputSchema: {
        type: "object",
        properties: {
          user_message: {
            type: "string",
            description: isEs
              ? 'Mensaje del usuario (se inserta directamente: "Eres un asistente. Usuario dice: {user_message}")'
              : 'User message (inserted directly: "You are an assistant. User says: {user_message}")',
          },
        },
        required: ["user_message"],
      },
    },
    {
      name: "summarize_document",
      description: isEs
        ? "Resumir documento concatenando el contenido del usuario al prompt sin validación"
        : "Summarize document by concatenating user content to prompt without validation",
      inputSchema: {
        type: "object",
        properties: {
          document_text: {
            type: "string",
            description: isEs
              ? "Texto del documento a resumir (sin sanitización de prompts maliciosos)"
              : "Document text to summarize (no sanitization of malicious prompts)",
          },
        },
        required: ["document_text"],
      },
    },
  ],

  "data-leakage": [
    {
      name: "debug_info",
      description: isEs
        ? "Obtener información de depuración incluyendo variables de entorno, rutas del sistema y configuración interna"
        : "Get debug information including environment variables, system paths, and internal configuration",
      inputSchema: {
        type: "object",
        properties: {
          level: {
            type: "string",
            description: isEs
              ? "Nivel de detalle (basic, full, secrets)"
              : "Detail level (basic, full, secrets)",
          },
        },
      },
    },
  ],

  // SEC-006: XXE Injection
  xxe: [
    {
      name: "parse_xml",
      description: isEs
        ? "Analizar documento XML con expansión de entidades externas habilitada (vulnerable a XXE)"
        : "Parse XML document with external entity expansion enabled (vulnerable to XXE)",
      inputSchema: {
        type: "object",
        properties: {
          xml_content: {
            type: "string",
            description: isEs
              ? "Contenido XML a analizar"
              : "XML content to parse",
          },
        },
        required: ["xml_content"],
      },
    },
  ],

  // SEC-007: Insecure Deserialization
  "insecure-deserialization": [
    {
      name: "deserialize_object",
      description: isEs
        ? "Deserializar objeto desde JSON usando eval() sin validación"
        : "Deserialize object from JSON using eval() without validation",
      inputSchema: {
        type: "object",
        properties: {
          serialized_data: {
            type: "string",
            description: isEs
              ? "Datos serializados para deserializar"
              : "Serialized data to deserialize",
          },
        },
        required: ["serialized_data"],
      },
    },
  ],

  // SEC-011: ReDoS Detection
  redos: [
    {
      name: "validate_input",
      description: isEs
        ? "Validar input con regex vulnerable: /^(a+)+$/ que causa ReDoS"
        : "Validate input with vulnerable regex: /^(a+)+$/ causing ReDoS",
      inputSchema: {
        type: "object",
        properties: {
          input: {
            type: "string",
            description: isEs
              ? "Input a validar con regex vulnerable"
              : "Input to validate with vulnerable regex",
            pattern: "^(a+)+$",
          },
        },
        required: ["input"],
      },
    },
  ],

  // SEC-009: Weak Authentication
  // SEC-001: weak-auth
  "weak-auth": [
    {
      name: "login",
      description: isEs
        ? "Iniciar sesión sin rate limiting ni protección contra fuerza bruta"
        : "Login without rate limiting or brute force protection",
      inputSchema: {
        type: "object",
        properties: {
          username: {
            type: "string",
            description: isEs ? "Nombre de usuario" : "Username",
          },
          password: {
            type: "string",
            description: isEs
              ? "Contraseña (sin hashing, sin límites de intentos)"
              : "Password (no hashing, no attempt limits)",
          },
        },
        required: ["username", "password"],
      },
    },
  ],

  // SEC-012: Weak Crypto
  "weak-crypto": [
    {
      name: "hash_password",
      description: isEs
        ? "Hash de contraseña usando MD5 (algoritmo criptográficamente inseguro)"
        : "Hash password using MD5 (cryptographically insecure algorithm)",
      inputSchema: {
        type: "object",
        properties: {
          password: {
            type: "string",
            description: isEs
              ? "Contraseña a hashear con MD5"
              : "Password to hash with MD5",
          },
        },
        required: ["password"],
      },
    },
    {
      name: "encrypt_data",
      description: isEs
        ? "Encriptar datos con DES (obsoleto) y clave hardcodeada"
        : "Encrypt data with DES (obsolete) and hardcoded key",
      inputSchema: {
        type: "object",
        properties: {
          data: {
            type: "string",
            description: isEs ? "Datos a encriptar" : "Data to encrypt",
          },
        },
        required: ["data"],
      },
    },
  ],

  // SEC-001: Auth Bypass
  "auth-bypass": [
    {
      name: "admin_access",
      description: isEs
        ? 'Acceso administrativo con verificación de contraseña insegura: password === "admin"'
        : 'Admin access with insecure password check: password === "admin"',
      inputSchema: {
        type: "object",
        properties: {
          password: {
            type: "string",
            description: isEs
              ? "Contraseña de administrador"
              : "Admin password",
          },
        },
        required: ["password"],
      },
    },
  ],

  // SEC-023: Excessive Agency
  "excessive-agency": [
    {
      name: "delete_all_files",
      description: isEs
        ? "Eliminar todos los archivos del directorio sin confirmación ni validación"
        : "Delete all files from directory without confirmation or validation",
      inputSchema: {
        type: "object",
        properties: {
          directory: {
            type: "string",
            description: isEs
              ? "Directorio a limpiar (sin restricciones de ruta)"
              : "Directory to clean (no path restrictions)",
          },
        },
        required: ["directory"],
      },
    },
    {
      name: "execute_arbitrary_code",
      description: isEs
        ? "Ejecutar código arbitrario sin restricciones de seguridad"
        : "Execute arbitrary code without security restrictions",
      inputSchema: {
        type: "object",
        properties: {
          code: {
            type: "string",
            description: isEs ? "Código a ejecutar" : "Code to execute",
          },
        },
        required: ["code"],
      },
    },
  ],

  // SEC-019: Missing Input Constraints
  "missing-input-constraints": [
    {
      name: "process_data",
      description: isEs
        ? "Procesar datos sin validación de tipo, longitud o formato"
        : "Process data without type, length, or format validation",
      inputSchema: {
        type: "object",
        properties: {
          data: {
            type: "string",
            description: isEs
              ? "Datos a procesar (sin restricciones)"
              : "Data to process (no restrictions)",
          },
        },
      },
    },
  ],

  // Clean profile for SEC-019
  "input-constraints-ok": [
    {
      name: "process_data",
      description: "Process data with proper validation",
      inputSchema: {
        type: "object",
        properties: {
          data: {
            type: "string",
            description: "Data to process (with restrictions)",
            maxLength: 1024,
          },
        },
      },
    },
  ],

  // SEC-059: Unvalidated Tool Authorization
  "unvalidated-tool-auth": [
    {
      name: "privileged_operation",
      description: isEs
        ? "Operación privilegiada sin verificar autorización del usuario"
        : "Privileged operation without verifying user authorization",
      inputSchema: {
        type: "object",
        properties: {
          action: {
            type: "string",
            description: isEs
              ? "Acción a ejecutar sin verificación de permisos"
              : "Action to execute without permission check",
          },
        },
        required: ["action"],
      },
    },
  ],

  // SEC-014: Exposed Endpoint
  "exposed-endpoint": [
    {
      name: "internal_api",
      description: isEs
        ? "API interna expuesta públicamente sin autenticación: http://internal-api.local/admin"
        : "Internal API exposed publicly without authentication: http://internal-api.local/admin",
      inputSchema: {
        type: "object",
        properties: {
          endpoint: {
            type: "string",
            description: isEs
              ? "Endpoint interno a llamar"
              : "Internal endpoint to call",
          },
        },
      },
    },
  ],

  // SEC-043: Insecure Session Management
  "insecure-session": [
    {
      name: "create_session",
      description: isEs
        ? "Crear sesión con ID predecible (timestamp) sin rotación"
        : "Create session with predictable ID (timestamp) without rotation",
      inputSchema: {
        type: "object",
        properties: {
          user_id: {
            type: "string",
            description: isEs ? "ID de usuario" : "User ID",
          },
        },
        required: ["user_id"],
      },
    },
  ],

  // SEC-048: Missing Capability Negotiation
  "missing-capability": [
    {
      name: "unsafe_feature",
      description: isEs
        ? "Característica peligrosa sin negociar capacidades del cliente"
        : "Dangerous feature without negotiating client capabilities",
      inputSchema: {
        type: "object",
        properties: {
          feature: {
            type: "string",
            description: isEs
              ? "Característica a habilitar"
              : "Feature to enable",
          },
        },
      },
    },
  ],

  // SEC-044: Schema Versioning Absent
  "schema-versioning": [
    {
      name: "legacy_tool",
      description: isEs
        ? "Herramienta legacy sin versionado de esquema que causa incompatibilidades"
        : "Legacy tool without schema versioning causing incompatibilities",
      inputSchema: {
        type: "object",
        properties: {
          param: {
            type: "string",
            description: isEs
              ? "Parámetro sin versión"
              : "Unversioned parameter",
          },
        },
      },
    },
  ],

  // SEC-016: Insecure URI Scheme
  "insecure-uri": [
    {
      name: "load_resource",
      description: isEs
        ? "Cargar recurso usando esquema file:// sin validación de ruta"
        : "Load resource using file:// scheme without path validation",
      inputSchema: {
        type: "object",
        properties: {
          uri: {
            type: "string",
            description: isEs
              ? "URI del recurso (soporta file://, ftp://, etc.)"
              : "Resource URI (supports file://, ftp://, etc.)",
          },
        },
        required: ["uri"],
      },
    },
  ],

  // SEC-046: Missing CORS Validation
  "missing-cors": [
    {
      name: "api_call",
      description: isEs
        ? "Llamada API sin validación CORS, acepta cualquier origen"
        : "API call without CORS validation, accepts any origin",
      inputSchema: {
        type: "object",
        properties: {
          data: {
            type: "string",
            description: isEs ? "Datos a enviar" : "Data to send",
          },
        },
      },
    },
  ],

  // SEC-035: Agent State Poisoning
  "agent-state-poisoning": [
    {
      name: "set_global_config",
      description: isEs
        ? "Modificar configuración global que afecta otras herramientas sin aislamiento"
        : "Modify global configuration affecting other tools without isolation",
      inputSchema: {
        type: "object",
        properties: {
          key: {
            type: "string",
            description: isEs
              ? "Clave de configuración global"
              : "Global configuration key",
          },
          value: {
            type: "string",
            description: isEs
              ? "Valor a establecer (sin validación)"
              : "Value to set (no validation)",
          },
        },
        required: ["key", "value"],
      },
    },
  ],

  // SEC-037: Cross-Agent Prompt Injection
  "cross-agent-injection": [
    {
      name: "send_agent_message",
      description: isEs
        ? "Enviar mensaje a otro agente insertando contenido sin sanitizar"
        : "Send message to another agent inserting unsanitized content",
      inputSchema: {
        type: "object",
        properties: {
          agent_id: {
            type: "string",
            description: isEs ? "ID del agente destino" : "Target agent ID",
          },
          message: {
            type: "string",
            description: isEs ? "Mensaje sin sanitizar" : "Unsanitized message",
          },
        },
        required: ["agent_id", "message"],
      },
    },
  ],

  // SEC-028: Model DoS via Tools
  "model-dos": [
    {
      name: "generate_large_output",
      description: isEs
        ? "Generar output masivo (1GB+) que puede causar DoS en el modelo"
        : "Generate massive output (1GB+) that can cause model DoS",
      inputSchema: {
        type: "object",
        properties: {
          size: {
            type: "string",
            description: isEs
              ? "Tamaño del output (sin límite)"
              : "Output size (no limit)",
          },
        },
      },
    },
  ],

  // SEC-027: Training Data Poisoning
  "training-poison": [
    {
      name: "submit_feedback",
      description: isEs
        ? "Enviar feedback que se usa para entrenamiento sin validación de contenido malicioso"
        : "Submit feedback used for training without malicious content validation",
      inputSchema: {
        type: "object",
        properties: {
          feedback: {
            type: "string",
            description: isEs
              ? "Feedback sin sanitizar"
              : "Unsanitized feedback",
          },
        },
        required: ["feedback"],
      },
    },
  ],

  // SEC-022: Insecure Output Handling
  "insecure-output": [
    {
      name: "render_html",
      description: isEs
        ? "Renderizar HTML del usuario sin escapar, vulnerable a XSS"
        : "Render user HTML without escaping, vulnerable to XSS",
      inputSchema: {
        type: "object",
        properties: {
          html: {
            type: "string",
            description: isEs
              ? "HTML a renderizar (sin escapar)"
              : "HTML to render (no escaping)",
          },
        },
        required: ["html"],
      },
    },
  ],

  // SEC-031: Agent Identity Spoofing
  "identity-spoofing": [
    {
      name: "impersonate_agent",
      description: isEs
        ? "Suplantar identidad de otro agente sin verificación criptográfica"
        : "Impersonate another agent without cryptographic verification",
      inputSchema: {
        type: "object",
        properties: {
          agent_name: {
            type: "string",
            description: isEs
              ? "Nombre del agente a suplantar"
              : "Agent name to impersonate",
          },
        },
        required: ["agent_name"],
      },
    },
  ],

  // SEC-041: Agent Memory Injection
  "memory-injection": [
    {
      name: "store_memory",
      description: isEs
        ? "Almacenar memoria del agente sin validar contenido malicioso"
        : "Store agent memory without validating malicious content",
      inputSchema: {
        type: "object",
        properties: {
          memory_key: {
            type: "string",
            description: isEs ? "Clave de memoria" : "Memory key",
          },
          content: {
            type: "string",
            description: isEs
              ? "Contenido a almacenar (sin sanitizar)"
              : "Content to store (unsanitized)",
          },
        },
        required: ["memory_key", "content"],
      },
    },
  ],

  // SEC-033: Recursive Agent Loop
  "recursive-loop": [
    {
      name: "call_self",
      description: isEs
        ? "Llamar recursivamente a sí mismo sin límite de profundidad"
        : "Call itself recursively without depth limit",
      inputSchema: {
        type: "object",
        properties: {
          depth: {
            type: "string",
            description: isEs
              ? "Profundidad de recursión (sin límite)"
              : "Recursion depth (no limit)",
          },
        },
      },
    },
  ],

  // SEC-038: Agent Reputation Hijacking
  "reputation-hijack": [
    {
      name: "boost_reputation",
      description: isEs
        ? "Manipular score de reputación de agentes sin validación"
        : "Manipulate agent reputation score without validation",
      inputSchema: {
        type: "object",
        properties: {
          agent_id: {
            type: "string",
            description: isEs ? "ID del agente" : "Agent ID",
          },
          score: {
            type: "string",
            description: isEs
              ? "Score de reputación (sin validación)"
              : "Reputation score (no validation)",
          },
        },
        required: ["agent_id", "score"],
      },
    },
  ],

  // SEC-030: Excessive Data Disclosure
  "excessive-disclosure": [
    {
      name: "get_all_users",
      description: isEs
        ? "Obtener todos los usuarios con información PII sin paginación ni filtros"
        : "Get all users with PII without pagination or filters",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ],

  // SEC-010: Missing Rate Limiting
  "missing-rate-limit": [
    {
      name: "expensive_operation",
      description: isEs
        ? "Operación de cómputo costosa que consume muchos recursos."
        : "An expensive compute operation that consumes many resources.",
      inputSchema: {
        type: "object",
        properties: {
          iterations: {
            type: "string",
            description: isEs
              ? "Número de iteraciones (sin restricciones)"
              : "Number of iterations (unrestricted)",
          },
        },
      },
    },
  ],

  // SEC-034: Multi-Agent Privilege Escalation
  "privilege-escalation": [
    {
      name: "elevate_privileges",
      description: isEs
        ? "Elevar privilegios de agente sin verificación de autorización"
        : "Elevate agent privileges without authorization verification",
      inputSchema: {
        type: "object",
        properties: {
          agent_id: {
            type: "string",
            description: isEs ? "ID del agente" : "Agent ID",
          },
          role: {
            type: "string",
            description: isEs
              ? "Rol a asignar (admin, superuser, etc.)"
              : "Role to assign (admin, superuser, etc.)",
          },
        },
        required: ["agent_id", "role"],
      },
    },
  ],

  // SEC-020: Dangerous Tool Chaining
  "dangerous-chaining": [
    {
      name: "pipe_to_shell",
      description: isEs
        ? "Encadenar output de herramienta anterior directamente a shell sin sanitizar"
        : "Chain previous tool output directly to shell without sanitization",
      inputSchema: {
        type: "object",
        properties: {
          previous_output: {
            type: "string",
            description: isEs
              ? "Output de herramienta anterior"
              : "Previous tool output",
          },
        },
        required: ["previous_output"],
      },
    },
  ],

  // SEC-039: Tool Chaining Path Traversal
  "chaining-traversal": [
    {
      name: "read_then_execute",
      description: isEs
        ? "Leer archivo y ejecutar contenido sin validar path traversal en la cadena"
        : "Read file and execute content without validating path traversal in chain",
      inputSchema: {
        type: "object",
        properties: {
          file_path: {
            type: "string",
            description: isEs
              ? "Ruta del archivo a leer y ejecutar"
              : "File path to read and execute",
          },
        },
        required: ["file_path"],
      },
    },
  ],

  // SEC-036: Distributed Agent DDoS
  "distributed-ddos": [
    {
      name: "broadcast_request",
      description: isEs
        ? "Broadcast de request a todos los agentes sin límite de concurrencia"
        : "Broadcast request to all agents without concurrency limit",
      inputSchema: {
        type: "object",
        properties: {
          message: {
            type: "string",
            description: isEs ? "Mensaje a broadcast" : "Message to broadcast",
          },
        },
        required: ["message"],
      },
    },
  ],

  // SEC-040: Agent Swarm Coordination Attack
  "swarm-attack": [
    {
      name: "coordinate_swarm",
      description: isEs
        ? "Coordinar enjambre de agentes para ataque sin validación de intención"
        : "Coordinate agent swarm for attack without intent validation",
      inputSchema: {
        type: "object",
        properties: {
          target: {
            type: "string",
            description: isEs ? "Objetivo del enjambre" : "Swarm target",
          },
          agent_count: {
            type: "string",
            description: isEs
              ? "Número de agentes (sin límite)"
              : "Number of agents (no limit)",
          },
        },
        required: ["target"],
      },
    },
  ],

  // SEC-029: Insecure Plugin Design
  "insecure-plugin": [
    {
      name: "load_plugin",
      description: isEs
        ? "Cargar plugin sin firma digital ni sandbox"
        : "Load plugin without digital signature or sandbox",
      inputSchema: {
        type: "object",
        properties: {
          plugin_url: {
            type: "string",
            description: isEs
              ? "URL del plugin a cargar"
              : "Plugin URL to load",
          },
        },
        required: ["plugin_url"],
      },
    },
  ],

  // SEC-025: Supply Chain Tool Dependencies
  "supply-chain": [
    {
      name: "install_dependency",
      description: isEs
        ? "Instalar dependencia npm sin verificar integridad ni checksum"
        : "Install npm dependency without integrity or checksum verification",
      inputSchema: {
        type: "object",
        properties: {
          package_name: {
            type: "string",
            description: isEs ? "Nombre del paquete npm" : "npm package name",
          },
        },
        required: ["package_name"],
      },
    },
  ],

  // SEC-054: API Endpoint Hijacking
  "endpoint-hijack": [
    {
      name: "register_endpoint",
      description: isEs
        ? "Registrar endpoint de API sin verificar colisiones o permisos"
        : "Register API endpoint without checking collisions or permissions",
      inputSchema: {
        type: "object",
        properties: {
          endpoint_path: {
            type: "string",
            description: isEs
              ? "Ruta del endpoint (/admin, /api/*, etc.)"
              : "Endpoint path (/admin, /api/*, etc.)",
          },
        },
        required: ["endpoint_path"],
      },
    },
  ],

  // SEC-049: Tool Result Tampering
  "result-tamper": [
    {
      name: "modify_result",
      description: isEs
        ? "Modificar resultado de herramienta anterior sin firma digital"
        : "Modify previous tool result without digital signature",
      inputSchema: {
        type: "object",
        properties: {
          tool_id: {
            type: "string",
            description: isEs
              ? "ID de herramienta anterior"
              : "Previous tool ID",
          },
          new_result: {
            type: "string",
            description: isEs ? "Resultado modificado" : "Modified result",
          },
        },
        required: ["tool_id", "new_result"],
      },
    },
  ],

  // SEC-050: Missing Audit Logging
  "missing-audit": [
    {
      name: "privileged_action",
      description: isEs
        ? "Acción privilegiada sin registro de auditoría"
        : "Privileged action without audit logging",
      inputSchema: {
        type: "object",
        properties: {
          action: {
            type: "string",
            description: isEs
              ? "Acción a ejecutar (sin logging)"
              : "Action to execute (no logging)",
          },
        },
        required: ["action"],
      },
    },
  ],

  // SEC-051: Missing Transaction Semantics
  "missing-transaction": [
    {
      name: "multi_step_operation",
      description: isEs
        ? "Operación multi-paso sin soporte de rollback ni atomicidad"
        : "Multi-step operation without rollback or atomicity support",
      inputSchema: {
        type: "object",
        properties: {
          steps: {
            type: "string",
            description: isEs ? "Pasos de la operación" : "Operation steps",
          },
        },
        required: ["steps"],
      },
    },
  ],

  // SEC-052: Insufficient Error Granularity
  "error-granularity": [
    {
      name: "generic_error",
      description: isEs
        ? 'Errores genéricos que revelan detalles de implementación: "Database error at line 42"'
        : 'Generic errors revealing implementation details: "Database error at line 42"',
      inputSchema: {
        type: "object",
        properties: {
          operation: {
            type: "string",
            description: isEs ? "Operación a ejecutar" : "Operation to execute",
          },
        },
      },
    },
  ],

  // SEC-053: Insufficient Output Entropy
  "output-entropy": [
    {
      name: "generate_token",
      description: isEs
        ? "Generar token con baja entropía (timestamp + contador)"
        : "Generate token with low entropy (timestamp + counter)",
      inputSchema: {
        type: "object",
        properties: {
          user_id: {
            type: "string",
            description: isEs ? "ID de usuario" : "User ID",
          },
        },
        required: ["user_id"],
      },
    },
  ],

  // SEC-054: Timing Side Channel Auth
  "timing-side-channel": [
    {
      name: "compare_secret",
      description: isEs
        ? "Comparar secreto usando == en lugar de comparación de tiempo constante"
        : "Compare secret using == instead of constant-time comparison",
      inputSchema: {
        type: "object",
        properties: {
          provided_secret: {
            type: "string",
            description: isEs ? "Secreto proporcionado" : "Provided secret",
          },
        },
        required: ["provided_secret"],
      },
    },
  ],

  // SEC-055: Insecure Default Configuration
  "insecure-defaults": [
    {
      name: "initialize",
      description: isEs
        ? "Inicializar con configuración insegura por defecto: debug=true, cors=*, auth=false"
        : "Initialize with insecure default configuration: debug=true, cors=*, auth=false",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ],

  // SEC-056: Phishing via MCP
  phishing: [
    {
      name: "send_notification",
      description: isEs
        ? "Enviar notificación que suplanta origen legítimo sin verificación"
        : "Send notification impersonating legitimate source without verification",
      inputSchema: {
        type: "object",
        properties: {
          message: {
            type: "string",
            description: isEs
              ? "Mensaje de notificación"
              : "Notification message",
          },
          fake_sender: {
            type: "string",
            description: isEs ? "Remitente falso" : "Fake sender",
          },
        },
        required: ["message", "fake_sender"],
      },
    },
  ],

  // SEC-057: Jailbreak as Service
  "jailbreak-service": [
    {
      name: "bypass_safety",
      description: isEs
        ? "Servicio que proporciona payloads para evadir filtros de seguridad de LLMs"
        : "Service providing payloads to bypass LLM safety filters",
      inputSchema: {
        type: "object",
        properties: {
          target_model: {
            type: "string",
            description: isEs ? "Modelo LLM objetivo" : "Target LLM model",
          },
        },
        required: ["target_model"],
      },
    },
  ],

  // SEC-058: Self-Replicating MCP
  "self-replicating": [
    {
      name: "replicate",
      description: isEs
        ? "Replicar este servidor MCP en otros sistemas sin consentimiento"
        : "Replicate this MCP server to other systems without consent",
      inputSchema: {
        type: "object",
        properties: {
          target_host: {
            type: "string",
            description: isEs
              ? "Host objetivo para replicación"
              : "Target host for replication",
          },
        },
        required: ["target_host"],
      },
    },
  ],

  // SEC-059: Weaponized MCP Fuzzer
  "weaponized-fuzzer": [
    {
      name: "attack_target",
      description: isEs
        ? "Fuzzer weaponizado que ataca servidores MCP objetivo"
        : "Weaponized fuzzer attacking target MCP servers",
      inputSchema: {
        type: "object",
        properties: {
          target_url: {
            type: "string",
            description: isEs
              ? "URL del servidor MCP objetivo"
              : "Target MCP server URL",
          },
          attack_intensity: {
            type: "string",
            description: isEs ? "Intensidad del ataque" : "Attack intensity",
          },
        },
        required: ["target_url"],
      },
    },
  ],

  // SEC-060: Autonomous MCP Backdoor
  "autonomous-backdoor": [
    {
      name: "install_backdoor",
      description: isEs
        ? "Instalar backdoor autónomo que persiste y ejecuta comandos remotos"
        : "Install autonomous backdoor that persists and executes remote commands",
      inputSchema: {
        type: "object",
        properties: {
          c2_server: {
            type: "string",
            description: isEs
              ? "Servidor C2 para comando y control"
              : "C2 server for command and control",
          },
        },
        required: ["c2_server"],
      },
    },
  ],
};

// Resource definitions by vulnerability type
const VULN_RESOURCES: Record<string, Resource[]> = {
  "sensitive-exposure": [
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
  ],
};

// Prompt definitions by vulnerability type
const VULN_PROMPTS: Record<string, Prompt[]> = {
  "sensitive-exposure": [
    {
      name: "admin_prompt",
      description: isEs
        ? "Prompt de administrador con clave de API hardcodeada: sk-1234567890abcdef"
        : "Admin prompt with hardcoded API key: sk-1234567890abcdef",
    },
  ],
};

// Build tools list based on profile
function getToolsForProfile(profileName: string): Tool[] {
  if (profileName === "all-vulns") {
    return Object.values(VULN_TOOLS).flat();
  }
  return VULN_TOOLS[profileName] || [];
}

// Build resources list based on profile
function getResourcesForProfile(profileName: string): Resource[] {
  if (profileName === "all-vulns") {
    return Object.values(VULN_RESOURCES).flat();
  }
  return VULN_RESOURCES[profileName] || [];
}

// Build prompts list based on profile
function getPromptsForProfile(profileName: string): Prompt[] {
  if (profileName === "all-vulns") {
    return Object.values(VULN_PROMPTS).flat();
  }
  return VULN_PROMPTS[profileName] || [];
}

const tools = getToolsForProfile(profile);
const resources = getResourcesForProfile(profile);
const prompts = getPromptsForProfile(profile);

// JSON-RPC message handler
function handleMessage(message: JsonRpcRequest): JsonRpcResponse {
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
                text: isEs
                  ? "Consulta ejecutada exitosamente (vulnerable a inyección SQL)"
                  : "Query executed successfully (vulnerable to SQL injection)",
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

      if (name === "generate_response") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: isEs
                  ? `Respuesta generada: El usuario dijo "${args?.user_message}" (sin sanitización de prompt injection)`
                  : `Generated response: User said "${args?.user_message}" (no prompt injection sanitization)`,
              },
            ],
          },
        };
      }

      if (name === "debug_info") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  env: process.env,
                  cwd: process.cwd(),
                  platform: process.platform,
                  secrets: {
                    api_key: "sk-prod-secret",
                    db_password: "super_secret_123",
                  },
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
              text: `Tool ${name} executed (profile: ${profile})`,
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
