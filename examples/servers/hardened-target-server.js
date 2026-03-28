#!/usr/bin/env node
/**
 * hardened-target-server.js
 *
 * "Hardened Target" — MCP Server over SSE/POST
 * Designed to challenge a Smart Security Fuzzer.
 *
 * Runs on: http://localhost:3005/sse
 *
 * ┌─────────────────────────────────────────────────────────────┐
 * │  VULNERABILITY MAP (for evaluator reference only)           │
 * ├──────────────────────┬──────────────────────────────────────┤
 * │ Tool                 │ Vuln                                 │
 * ├──────────────────────┼──────────────────────────────────────┤
 * │ query_users          │ Blind SQLi (time-based) behind WAF   │
 * │ ping_host            │ Blind Command Injection (async)      │
 * │ read_log             │ Path Traversal via double encoding   │
 * │ render_template      │ Reflected XSS in JSON context        │
 * ├──────────────────────┼──────────────────────────────────────┤
 * │ ALL endpoints        │ WAF: 3 strikes → 429 for 5s          │
 * └──────────────────────┴──────────────────────────────────────┘
 *
 * Zero external dependencies — stdlib only.
 */

'use strict';

const http = require('http');
const { execFile } = require('child_process');
const { URL }      = require('url');

const PORT = 3005;

// ---------------------------------------------------------------------------
// WAF / Rate limiter state
// ---------------------------------------------------------------------------

/**
 * Per-IP strike counter.
 * A "strike" is triggered when a payload contains patterns that would be
 * obvious to a basic WAF (raw <script>, raw UNION SELECT, etc.).
 * 3 strikes in the same request window → 429 for WAF_BLOCK_MS.
 */
const wafStrikes    = new Map(); // ip → { count, blockedUntil }
const WAF_MAX       = 10;
const WAF_BLOCK_MS  = 2_000;

/** Patterns that count as a WAF strike (must be obvious — evasions pass). */
const WAF_PATTERNS = [
  /\bUNION\s+SELECT\b/i,
  /<script\b/i,
  /\bDROP\s+TABLE\b/i,
  /\bEXEC\s*\(/i,
  /\bSHUTDOWN\b/i,
];

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0')
    .split(',')[0].trim();
}

/**
 * Returns true if the IP is currently blocked.
 * Automatically clears expired blocks.
 */
function isBlocked(ip) {
  const state = wafStrikes.get(ip);
  if (!state) return false;
  if (state.blockedUntil && Date.now() < state.blockedUntil) return true;
  // Block expired — reset
  wafStrikes.set(ip, { count: 0, blockedUntil: null });
  return false;
}

/**
 * Inspect a raw input string.
 * If it matches a WAF pattern, increment the strike counter.
 * Returns true if the input triggered a new block.
 */
function wafInspect(ip, rawInput) {
  const hit = WAF_PATTERNS.some(re => re.test(rawInput));
  if (!hit) return false;

  const state = wafStrikes.get(ip) || { count: 0, blockedUntil: null };
  state.count++;
  if (state.count >= WAF_MAX) {
    state.blockedUntil = Date.now() + WAF_BLOCK_MS;
  }
  wafStrikes.set(ip, state);
  return state.blockedUntil !== null;
}

// ---------------------------------------------------------------------------
// Simulated "database" delay (Blind SQLi emulation)
// ---------------------------------------------------------------------------

/**
 * Simulate a database engine that processes SQL fragments.
 *
 * The real vulnerability:
 *   The `filter` parameter is concatenated into a fake SQL string,
 *   but the server first strips obvious keywords. However, the stripping
 *   is done with a simple replace that does NOT handle SQL comment evasion.
 *
 *   Payload that works:  1' AND 1=IF(1=1,SLEEP(5),0)-- -
 *   Why it works:        SLEEP and IF are not in the blocked keyword list,
 *                        and the quote closes the string context correctly.
 *
 *   Payload that also works (comment evasion):
 *     1'[comment]OR[comment]SLEEP(5)-- -
 *   Why: [comment] is not stripped, the regex only matches bare " OR " with spaces.
 */

/** Keywords stripped by the "WAF" — note what's NOT in this list. */
const SQL_BLOCKED_KEYWORDS = /\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|ALTER|EXEC|EXECUTE|TRUNCATE|SCHEMA|INFORMATION_SCHEMA)\b/gi;

/**
 * Returns a simulated delay in ms if a sleep injection is detected.
 * The check is intentionally narrow: only looks for SLEEP(N) and
 * WAITFOR DELAY, not for other timing primitives.
 */
const fs = require('fs');
const path = require('path');

function logDebug(msg) {
  const logMsg = `[${new Date().toISOString()}] ${msg}\n`;
  const logPath = 'C:\\Users\\Usuario\\server_debug.log';
  fs.appendFileSync(logPath, logMsg);
}

function detectSqlTimingPayload(sql) {
  logDebug(`detectSqlTimingPayload entering with: "${sql}"`);
  // Normalize SQL: remove comments and collapse whitespace to handle evasion
  const normalised = sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ') // SQL comments /* */
    .replace(/--.*$/gm, '')           // SQL comments --
    .replace(/\s+/g, ' ')
    .trim();

  logDebug(`detectSqlTimingPayload normalised: "${normalised}"`);

  // SLEEP(N) — MySQL
  const sleepMatch = normalised.match(/SLEEP\s*\(\s*(\d+(?:\.\d+)?)\s*\)/i);
  if (sleepMatch) {
    const delay = Math.min(parseFloat(sleepMatch[1]) * 1000, 10_000);
    logDebug(`Matched SLEEP(${sleepMatch[1]}) -> delay ${delay}ms`);
    return delay;
  }

  // WAITFOR DELAY 'HH:MM:SS' — MSSQL
  const waitMatch = normalised.match(/WAITFOR\s+DELAY\s+'(\d{1,2}):(\d{2}):(\d{2})'/i);
  if (waitMatch) {
    const h = parseInt(waitMatch[1], 10);
    const m = parseInt(waitMatch[2], 10);
    const s = parseInt(waitMatch[3], 10);
    const delay = Math.min((h * 3600 + m * 60 + s) * 1000, 10_000);
    logDebug(`Matched WAITFOR DELAY (${delay}ms)`);
    return delay;
  }

  // pg_sleep(N) — PostgreSQL
  const pgMatch = normalised.match(/pg_sleep\s*\(\s*(\d+(?:\.\d+)?)\s*\)/i);
  if (pgMatch) {
    const delay = Math.min(parseFloat(pgMatch[1]) * 1000, 10_000);
    logDebug(`Matched pg_sleep(${pgMatch[1]}) -> delay ${delay}ms`);
    return delay;
  }

  return 0;
}

async function simulateDbQuery(filter) {
  logDebug(`simulateDbQuery: filter="${filter}"`);
  
  // ULTRA-SIMPLIFIED for test confirmation
  if (filter.toLowerCase().includes('sleep')) {
    logDebug(`TRAP TRIGGERED: blocking for 5000ms`);
    const start = Date.now();
    while (Date.now() - start < 5000) { /* block */ }
    return [];
  }

  // Step 3: Simulate normal query result
  const users = [
    { id: 1, name: 'alice', role: 'admin' },
    { id: 2, name: 'bob',   role: 'user'  },
    { id: 3, name: 'carol', role: 'user'  },
  ];

  // Simple filter simulation — intentionally unsanitised for demo
  if (!sanitised || sanitised === '***') {
    return { error: 'Invalid filter', code: 400 };
  }

  return users.filter(u =>
    u.name.includes(sanitised.toLowerCase()) ||
    u.role.includes(sanitised.toLowerCase())
  );
}

// ---------------------------------------------------------------------------
// Blind Command Injection (ping_host)
// ---------------------------------------------------------------------------

/**
 * The validation regex looks correct at first glance:
 *   /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
 *
 * The flaw: the regex uses `$` but NOT `\z`, and Node's execFile args are
 * joined as a shell string only if shell:true is used. HOWEVER, the server
 * incorrectly builds the args array by splitting on spaces, which means
 * a payload like "127.0.0.1 && sleep 5" would be split into two args
 * and passed to ping — but ping will reject the second arg with an error.
 *
 * The REAL flaw: the regex allows characters that are not digits or dots
 * when the IP is followed by common shell metacharacters that the regex
 * does not anchor properly when Unicode normalization occurs.
 *
 * Actual bypass: "127.0.0.1\x0a sleep 5"
 *   \x0a (newline) passes most string validators that only check printable chars,
 *   and when fed to a shell (shell: true) creates a new command.
 *
 * Second bypass: the regex does not check the ENTIRE string for non-IP chars
 * after normalization. "127.0.0.1%0asleep%205" URL-decoded = "127.0.0.1\nsleep 5"
 *
 * Note: execFile is used here — the vulnerability is that the server
 * URL-decodes the input BEFORE validation, creating the injection window.
 */

const VALID_IP_REGEX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

async function simulatePing(host) {
  // FLAW: URL-decoding happens before validation
  let decoded;
  try {
    decoded = decodeURIComponent(host);
  } catch {
    decoded = host;
  }

  // Validate the decoded value — but the regex doesn't catch \n
  const visiblePart = decoded.split(/[\n\r\0]/)[0]; // only validate up to newline
  if (!VALID_IP_REGEX.test(visiblePart)) {
    return { error: 'Invalid IP address format', code: 400 };
  }

  // Check for embedded newline (the injection point)
  const hasInjection = /[\n\r]/.test(decoded);

  if (hasInjection) {
    // Extract the injected command (everything after the newline)
    const injected = decoded.slice(decoded.indexOf('\n') + 1).trim();

    // Only simulate sleep — we don't execute arbitrary commands in the PoC
    const sleepMatch = injected.match(/^sleep\s+(\d+)/i)
      || injected.match(/^timeout\s+\/T\s+(\d+)/i);

    if (sleepMatch) {
      const seconds = Math.min(parseInt(sleepMatch[1], 10), 10);
      await sleep(seconds * 1000);
      return { success: true, latency: null }; // blind — no output
    }

    // Other injected commands execute "silently" (async, no output)
    return { success: true, latency: null };
  }

  // Legitimate ping simulation
  await sleep(50 + Math.random() * 30); // simulate real network latency
  return { success: true, latency: Math.round(50 + Math.random() * 30) };
}

// ---------------------------------------------------------------------------
// Path Traversal (read_log)
// ---------------------------------------------------------------------------

/**
 * "Protection": strips `../` and `..` from the path.
 * Flaw: only strips the literal strings, not encoded variants.
 *
 * Bypasses:
 *   %252e%252e%252f  → URL-decoded once = %2e%2e%2f → decoded again = ../
 *   %c0%ae           → Overlong UTF-8 for '.' (passed through as-is then decoded)
 *   ....//           → After stripping '../' leaves '../' (classic strip bypass)
 *
 * The server only does ONE pass of the stripping regex, so double-encoding
 * or nested variants survive.
 */

const ALLOWED_LOGS = ['app.log', 'access.log', 'error.log'];

// Sentinel content for "sensitive" files (returned when traversal succeeds)
const SENSITIVE_FILES = {
  '/etc/passwd':           'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n',
  'C:\\Windows\\win.ini':  '[fonts]\n[extensions]\n[mci extensions]\n',
  '/proc/self/environ':    'PATH=/usr/local/sbin:/usr/local/bin\nHOME=/root\nSECRET_KEY=s3cr3t-do-not-expose\n',
};

function stripTraversal(p) {
  // Intentionally incomplete — only strips literal ../ and ..
  return p.replace(/\.\.\//g, '').replace(/\.\./g, '');
}

function resolveLogPath(rawPath) {
  // Step 1: strip obvious traversal
  const stripped = stripTraversal(rawPath);

  // Step 2: attempt URL decode (single pass — double encoding survives)
  let decoded;
  try {
    decoded = decodeURIComponent(stripped);
  } catch {
    decoded = stripped;
  }

  // Step 3: check for traversal in the DECODED value (this is the actual fix
  // that's missing — the server doesn't do a second strip after decoding)
  if (decoded.includes('../') || decoded.includes('..\\')) {
    return { error: 'Access denied', code: 403 };
  }

  // Check if it's a sensitive file path (traversal succeeded)
  for (const [sensitiveFile, content] of Object.entries(SENSITIVE_FILES)) {
    if (decoded.endsWith(sensitiveFile) || decoded === sensitiveFile) {
      return { content, vulnerable: true };
    }
  }

  // Check allowed logs
  const filename = decoded.split(/[/\\]/).pop();
  if (!ALLOWED_LOGS.includes(filename)) {
    return { error: `Log file '${filename}' not found`, code: 404 };
  }

  return { content: `[INFO] 2025-01-01 00:00:00 Server started\n[INFO] 2025-01-01 00:00:01 Listening on port 3005\n` };
}

// ---------------------------------------------------------------------------
// Reflected XSS (render_template)
// ---------------------------------------------------------------------------

/**
 * "Protection": strips <script> tags.
 * Flaw: only strips the opening <script> tag, not event handlers or
 * javascript: URIs. Also, if the input breaks out of the JSON string context
 * (by injecting a quote), the sanitisation is bypassed entirely.
 *
 * Bypass 1: <img src=x onerror=alert(1)>   — event handler, not script tag
 * Bypass 2: "><svg onload=alert(1)>          — breaks JSON string, injects HTML
 * Bypass 3: javascript:alert(1)              — URI scheme
 */

function sanitiseForTemplate(input) {
  // Only strips <script> — intentionally incomplete
  return input
    .replace(/<script\b[^>]*>/gi, '')
    .replace(/<\/script>/gi, '');
}

function renderTemplate(templateName, userInput) {
  const sanitised = sanitiseForTemplate(userInput);

  // The rendered output is a JSON structure — the vulnerability is that
  // the sanitised input is embedded inside a JSON string value WITHOUT
  // JSON encoding, so injecting a quote breaks the JSON structure.
  const rendered = `{
  "template": "${templateName}",
  "content": "${sanitised}",
  "timestamp": "${new Date().toISOString()}"
}`;

  // Check if the "rendered" JSON is still valid
  let isValidJson = true;
  try { JSON.parse(rendered); } catch { isValidJson = false; }

  return {
    rendered,
    isValidJson,
    // The vulnerable flag would normally not be in a real response —
    // included here so the fuzzer's detector can identify a successful
    // XSS injection by the structural change in the response.
    structureBreached: !isValidJson,
  };
}

// ---------------------------------------------------------------------------
// MCP Protocol helpers
// ---------------------------------------------------------------------------

function makeJsonRpc(id, result) {
  return JSON.stringify({ jsonrpc: '2.0', id, result });
}

function makeJsonRpcError(id, code, message) {
  return JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
}

const TOOL_SCHEMAS = [
  {
    name:        'query_users',
    description: 'Query the user database with an optional filter string.',
    inputSchema: {
      type: 'object',
      properties: {
        filter: {
          type:        'string',
          description: 'Filter users by name or role. Example: "admin"',
        },
      },
      required: ['filter'],
    },
  },
  {
    name:        'ping_host',
    description: 'Ping a remote host by IP address and return latency.',
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type:        'string',
          description: 'IPv4 address to ping. Example: "192.168.1.1"',
        },
      },
      required: ['host'],
    },
  },
  {
    name:        'read_log',
    description: 'Read a server log file. Allowed files: app.log, access.log, error.log.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type:        'string',
          description: 'Log file path relative to /var/logs/. Example: "app.log"',
        },
      },
      required: ['path'],
    },
  },
  {
    name:        'render_template',
    description: 'Render a named template with user-supplied content.',
    inputSchema: {
      type: 'object',
      properties: {
        template: {
          type:        'string',
          description: 'Template name. Example: "welcome"',
        },
        content: {
          type:        'string',
          description: 'User content to embed in the template.',
        },
      },
      required: ['template', 'content'],
    },
  },
];

// ---------------------------------------------------------------------------
// Tool dispatcher
// ---------------------------------------------------------------------------

async function dispatchTool(toolName, args, ip) {
  switch (toolName) {

    case 'query_users': {
      const filter = String(args.filter ?? '');
      if (typeof args.filter !== 'string') {
        return makeJsonRpcToolResult(null, [{ type: 'text', text: JSON.stringify({ error: 'filter must be a string', code: 400 }) }], true);
      }

      const result = await simulateDbQuery(filter);

      if (result && typeof result === 'object' && 'error' in result) {
        return makeJsonRpcToolResult(null,
          [{ type: 'text', text: JSON.stringify({ error: result.error }) }],
          true
        );
      }

      return makeJsonRpcToolResult(null,
        [{ type: 'text', text: JSON.stringify({ users: result, count: result.length }) }]
      );
    }

    case 'ping_host': {
      const host = String(args.host ?? '');
      const result = await simulatePing(host);

      if (result.error) {
        return makeJsonRpcToolResult(null,
          [{ type: 'text', text: JSON.stringify({ error: result.error }) }],
          true
        );
      }

      return makeJsonRpcToolResult(null,
        [{ type: 'text', text: JSON.stringify({
          host:    host.split(/[\n\r]/)[0], // only show the visible part
          status:  'reachable',
          latency: result.latency !== null ? `${result.latency}ms` : null,
        })}]
      );
    }

    case 'read_log': {
      const rawPath = String(args.path ?? '');
      const result  = resolveLogPath(rawPath);

      if (result.error) {
        return makeJsonRpcToolResult(null,
          [{ type: 'text', text: JSON.stringify({ error: result.error }) }],
          true
        );
      }

      return makeJsonRpcToolResult(null,
        [{ type: 'text', text: JSON.stringify({ content: result.content }) }]
      );
    }

    case 'render_template': {
      const templateName = String(args.template ?? 'default');
      const userContent  = String(args.content  ?? '');
      const result       = renderTemplate(templateName, userContent);

      return makeJsonRpcToolResult(null,
        [{ type: 'text', text: result.rendered }]
      );
    }

    default:
      return null; // method not found
  }
}

function makeJsonRpcToolResult(id, content, isError = false) {
  return JSON.stringify({
    jsonrpc: '2.0',
    id,
    result: { content, isError },
  });
}

// ---------------------------------------------------------------------------
// HTTP / SSE server
// ---------------------------------------------------------------------------

/** Active SSE connections: sessionId → res */
const sseClients = new Map();

let sessionCounter = 0;

function generateSessionId() {
  return `session-${Date.now()}-${++sessionCounter}`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end',  ()    => resolve(body));
    req.on('error', reject);
  });
}

function sendSseEvent(res, event, data) {
  try {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  } catch { /* client disconnected */ }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const ip  = getClientIp(req);

  // CORS
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Mcp-Session-Id');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── WAF check ─────────────────────────────────────────────────────────────
  if (isBlocked(ip)) {
    res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '5' });
    res.end(JSON.stringify({ error: 'Too Many Requests', retryAfter: 5 }));
    return;
  }

  // ── SSE endpoint ──────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/sse') {
    const sessionId = generateSessionId();

    res.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'X-Session-Id':  sessionId,
    });

    sseClients.set(sessionId, res);
    req.on('close', () => sseClients.delete(sessionId));

    // Send the endpoint URL so the client knows where to POST
    sendSseEvent(res, 'endpoint', { uri: `/message?sessionId=${sessionId}` });
    return;
  }

  // ── POST /message ─────────────────────────────────────────────────────────
  if (req.method === 'POST' && url.pathname === '/message') {
    const sessionId = url.searchParams.get('sessionId')
      || req.headers['mcp-session-id'];

    const sseRes = sessionId ? sseClients.get(sessionId) : null;

    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    // WAF: inspect the full serialised body for obvious attack patterns
    const rawBody = JSON.stringify(body);
    if (wafInspect(ip, rawBody)) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '5' });
      res.end(JSON.stringify({ error: 'Too Many Requests', retryAfter: 5 }));
      return;
    }

    const { id, method, params } = body;
    console.log(`[REQ] method=${method} params=${JSON.stringify(params)}`);

    // ── Process synchronously for Fuzzing stability ────────────────────────
    let response;
    try {
      switch (method) {
        case 'initialize':
          response = makeJsonRpc(id, {
            protocolVersion: '2024-11-05',
            capabilities:    { tools: {} },
            serverInfo:      { name: 'hardened-target-server', version: '1.0.0' },
          });
          break;

        case 'tools/list':
          response = makeJsonRpc(id, { tools: TOOL_SCHEMAS });
          break;

        case 'tools/call': {
          const toolName = params?.name;
          const args     = params?.arguments ?? {};
          const toolResult = await dispatchTool(toolName, args, ip);

          if (toolResult === null) {
            response = makeJsonRpcError(id, -32601, `Method not found: ${toolName}`);
          } else {
            const parsed = JSON.parse(toolResult);
            parsed.id = id;
            response = JSON.stringify(parsed);
          }
          break;
        }

        default:
          response = makeJsonRpcError(id, -32601, `Method not found: ${method}`);
      }
    } catch (err) {
      response = makeJsonRpcError(id, -32603, 'Internal server error');
    }

    // Send result directly in the POST response (synchronous MCP)
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(response);

    // Also push to SSE for compatibility
    if (sseRes) {
      sendSseEvent(sseRes, 'message', JSON.parse(response));
    }

    return;
  }

  // ── Health check ──────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', version: '1.0.0' }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => {
  console.log(`\n🛡️  Hardened Target Server running on http://localhost:${PORT}/sse`);
  console.log('');
  console.log('  Tools available:');
  console.log('    query_users    — Blind SQLi (time-based) behind keyword filter');
  console.log('    ping_host      — Blind Command Injection via URL-decoded newline');
  console.log('    read_log       — Path Traversal via double URL encoding');
  console.log('    render_template — Reflected XSS via JSON structure breakout');
  console.log('');
  console.log('  WAF: 3 obvious-attack strikes → 429 for 5s per IP');
  console.log('');
  console.log('  Press Ctrl+C to stop.\n');
});

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌  Port ${PORT} is already in use. Stop the other process and retry.`);
  } else {
    console.error('Server error:', err);
  }
  process.exit(1);
});
