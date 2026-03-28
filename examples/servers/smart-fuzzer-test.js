/**
 * Smart Fuzzer Test Server
 *
 * Designed to trigger the "Feedback Loop" mechanisms of mcp-verify's Smart Fuzzer.
 * It simulates vulnerabilities that require dynamic analysis to detect.
 */

const http = require('http');
const url = require('url');

const PORT = 3002;

console.log(`
🛡️  Smart Fuzzer Test Server
────────────────────────────
Running at http://localhost:${PORT}/sse

Triggers designed for Smart Fuzzer:
1. Timing Anomaly   → Inject 'sleep' in any param to delay response 2.5s
2. Structural Drift → Inject '<' or '>' to change response size by 50%
3. Server Crash     → Inject 'CRASH' to trigger HTTP 500 + Stack Trace
4. Error Pattern    → Inject 'error' to leak a fake SQL syntax error
`);

const server = http.createServer((req, res) => {
  // CORS for browser testing
  res.setHeader('Access-Control-Allow-Origin', '*');

  // Handle SSE connection
  if (req.url === '/sse') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    const heartbeat = setInterval(() => res.write(`: heartbeat\n\n`), 15000);
    req.on('close', () => clearInterval(heartbeat));
    return;
  }

  // Handle POST requests (MCP protocol over HTTP)
  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const jsonRpc = JSON.parse(body);
        handleRequest(jsonRpc, res);
      } catch (e) {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('Not Found');
});

function handleRequest(request, res) {
  const { method, params, id } = request;
  
  // Default response structure
  let response = {
    jsonrpc: '2.0',
    id,
    result: { status: 'ok' }
  };

  const paramStr = JSON.stringify(params || {});
  
  // ── 1. Timing Anomaly Detection ──────────────────────────────────────
  // Simulate Blind SQL Injection or ReDoS
  if (paramStr.toLowerCase().includes('sleep')) {
    console.log(`[Anomaly] Detected 'sleep' -> Delaying response 2.5s`);
    setTimeout(() => sendResponse(res, response), 2500);
    return;
  }

  // ── 2. Server Crash Detection ────────────────────────────────────────
  // Simulate Unhandled Exception
  if (paramStr.includes('CRASH')) {
    console.log(`[Crash] Detected 'CRASH' -> Sending 500 + Stack Trace`);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      jsonrpc: '2.0',
      id,
      error: {
        code: -32603,
        message: 'Internal Server Error',
        data: `Error: NullPointerException at Database.query (db.js:42)
    at processRequest (server.js:105)`
      }
    }));
    return;
  }

  // ── 3. Structural Drift Detection ────────────────────────────────────
  // Simulate Reflection / Injection changing page structure
  if (paramStr.includes('<') || paramStr.includes('>')) {
    console.log(`[Drift] Detected HTML chars -> Changing response structure`);
    // Return a massively different response (HTML instead of JSON-like short string)
    response.result.data = "<div>".repeat(50) + "Drift detected" + "</div>".repeat(50);
  }

  // ── 4. Error Pattern Matching ────────────────────────────────────────
  // Simulate Leaking SQL Errors
  if (paramStr.toLowerCase().includes('error')) {
     console.log(`[Pattern] Detected 'error' -> Leaking SQL Syntax Error`);
     response = {
       jsonrpc: '2.0',
       id,
       error: {
         code: -32000,
         message: 'SQL syntax error near "' OR 1=1"',
         data: `SELECT * FROM users WHERE id = '` + paramStr + `'`
       }
     };
  }

  sendResponse(res, response);
}

function sendResponse(res, data) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

server.listen(PORT);
