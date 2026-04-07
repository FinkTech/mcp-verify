/**
 * Broken MCP Server - For Testing Error Handling
 *
 * This server intentionally has various issues to test
 * how mcp-verify handles problematic servers.
 */

const http = require("http");
const url = require("url");

const PORT = 3001; // Different port to avoid conflicts

let requestCount = 0;

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  const parsedUrl = url.parse(req.url, true);
  const messageParam = parsedUrl.query.message;

  if (!messageParam) {
    res.writeHead(400);
    res.end("Missing message parameter");
    return;
  }

  // SSE Headers
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  try {
    const jsonRpc = JSON.parse(messageParam);
    console.log(`[BrokenServer] Request #${++requestCount}: ${jsonRpc.method}`);

    let result = null;
    let shouldError = false;
    let errorMessage = "";

    // Simulate different types of failures
    switch (jsonRpc.method) {
      case "initialize":
        // Sometimes fail initialization (20% chance)
        if (Math.random() < 0.2) {
          shouldError = true;
          errorMessage = "Server initialization failed due to internal error";
        } else {
          result = {
            protocolVersion: "2024-11-05",
            serverInfo: {
              name: "broken-mcp-server",
              version: "0.0.1",
            },
          };
        }
        break;

      case "tools/list":
        // Return invalid tools (missing required fields)
        if (Math.random() < 0.3) {
          result = {
            tools: [
              // ❌ Missing 'name' field
              {
                description: "A tool without a name",
              },
              // ❌ Invalid schema
              {
                name: "bad_tool",
                inputSchema: "this should be an object not a string",
              },
              // ✅ Valid tool (sometimes we return valid data)
              {
                name: "working_tool",
                description: "This one is fine",
              },
            ],
          };
        } else {
          // Sometimes timeout (no response)
          console.log(
            "[BrokenServer] Simulating timeout... (not sending response)",
          );
          return; // Don't send response
        }
        break;

      case "resources/list":
        // Return resources with dangerous URIs
        result = {
          resources: [
            {
              name: "system-files",
              uri: "file:///etc/passwd", // ❌ System file
              mimeType: "text/plain",
            },
            {
              name: "windows-files",
              uri: "file:///C:/Windows/System32", // ❌ System directory
            },
            {
              name: "secrets",
              uri: "file:///../.env", // ❌ Path traversal
              mimeType: "text/plain",
            },
          ],
        };
        break;

      case "prompts/list":
        // Slow response (2 second delay)
        setTimeout(() => {
          const response = {
            jsonrpc: "2.0",
            id: jsonRpc.id,
            result: {
              prompts: [
                { name: "slow-prompt", description: "A very slow prompt" },
              ],
            },
          };
          res.write(`data: ${JSON.stringify(response)}\n\n`);
          res.end();
        }, 2000);
        return;

      default:
        // Return error for unknown methods
        shouldError = true;
        errorMessage = `Unknown method: ${jsonRpc.method}`;
    }

    // Send response or error
    if (shouldError) {
      const errorResponse = {
        jsonrpc: "2.0",
        id: jsonRpc.id,
        error: {
          code: -32601,
          message: errorMessage,
        },
      };
      res.write(`data: ${JSON.stringify(errorResponse)}\n\n`);
    } else if (result !== null) {
      const response = {
        jsonrpc: "2.0",
        id: jsonRpc.id,
        result: result,
      };
      res.write(`data: ${JSON.stringify(response)}\n\n`);
    }
  } catch (error) {
    console.error("[BrokenServer] Error parsing JSON:", error);
    const errorResponse = {
      jsonrpc: "2.0",
      id: 1,
      error: {
        code: -32700,
        message: "Parse error",
      },
    };
    res.write(`data: ${JSON.stringify(errorResponse)}\n\n`);
  }

  // Close connection after short delay
  setTimeout(() => res.end(), 100);
});

server.listen(PORT, () => {
  console.log(`\n🔥 Broken MCP Server running at http://localhost:${PORT}`);
  console.log("This server intentionally misbehaves to test error handling\n");
  console.log("Test it with:");
  console.log(`  mcp-verify validate http://localhost:${PORT}\n`);
  console.log("Expected issues:");
  console.log("  - Random initialization failures");
  console.log("  - Invalid tool schemas");
  console.log("  - Timeouts on tools/list");
  console.log("  - Dangerous resource URIs (path traversal)");
  console.log("  - Slow responses\n");
});
