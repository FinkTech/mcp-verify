/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import * as http from "http";
import * as url from "url";
import { t } from "@mcp-verify/shared";
import { createScopedLogger } from "../../infrastructure/logging/logger";

export class MockServer {
  private port: number;
  private server: http.Server | null = null;
  private logger = createScopedLogger("MockServer");

  constructor(port: number = 3000) {
    this.port = port;
  }

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) =>
        this.handleRequest(req, res),
      );
      this.server.listen(this.port, () => {
        this.logger.info(
          `${t("mock_server_running")} http://localhost:${this.port}`,
        );
        resolve();
      });
    });
  }

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, User-Agent");

    if (req.method === "OPTIONS") {
      res.writeHead(200);
      res.end();
      return;
    }

    // Support both HTTP POST (for HttpTransport) and SSE GET (for SSE transport)
    if (req.method === "POST") {
      // HTTP POST with JSON body (HttpTransport)
      this.handleHttpPost(req, res);
    } else if (req.method === "GET") {
      // SSE with query parameter (SSE transport)
      this.handleSseGet(req, res);
    } else {
      res.writeHead(405);
      res.end("Method Not Allowed");
    }
  }

  private handleHttpPost(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk.toString();
    });

    req.on("end", () => {
      try {
        const jsonRpc = JSON.parse(body);
        this.logger.debug(t("mock_received", { method: jsonRpc.method }));

        const result = this.processRpc(jsonRpc);

        const response = {
          jsonrpc: "2.0",
          id: jsonRpc.id,
          result: result,
        };

        // Standard JSON response for HTTP POST
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(response));
      } catch (error) {
        this.logger.error(
          t("error_handling_request"),
          error instanceof Error ? error : undefined,
        );
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
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

    req.on("error", (error) => {
      this.logger.error("Request error", error);
      res.writeHead(500);
      res.end("Internal Server Error");
    });
  }

  private handleSseGet(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || "", true);
    const messageParam = parsedUrl.query.message as string;

    if (!messageParam) {
      res.writeHead(400);
      res.end(
        "Missing message parameter (SSE transport expects ?message=JSON)",
      );
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
      this.logger.debug(t("mock_received", { method: jsonRpc.method }));

      const result = this.processRpc(jsonRpc);

      const response = {
        jsonrpc: "2.0",
        id: jsonRpc.id,
        result: result,
      };

      res.write(`data: ${JSON.stringify(response)}\n\n`);
    } catch (error) {
      this.logger.error(
        t("error_handling_request"),
        error instanceof Error ? error : undefined,
      );
    }

    // Close connection immediately as per current simple mock behavior
    setTimeout(() => res.end(), 100);
  }

  private processRpc(
    jsonRpc: Record<string, unknown>,
  ): Record<string, unknown> {
    switch (jsonRpc.method) {
      case "initialize":
        return {
          protocolVersion: "2024-11-05",
          serverInfo: { name: "mock-mcp-server", version: "1.0.0" },
          capabilities: {
            tools: {},
            resources: {},
            prompts: {},
          },
        };
      case "tools/list":
        return {
          tools: [
            {
              name: "calculate_sum",
              description: "Adds two numbers together",
              inputSchema: {
                type: "object",
                properties: { a: { type: "number" }, b: { type: "number" } },
                required: ["a", "b"],
              },
            },
            {
              name: "fetch_weather",
              description: "Gets weather for a location",
              inputSchema: {
                type: "object",
                properties: { city: { type: "string" } },
              },
            },
          ],
        };
      case "tools/call":
        const params = jsonRpc.params as {
          name: string;
          arguments: Record<string, any>;
        };
        if (params.name === "calculate_sum") {
          const { a, b } = params.arguments;
          return {
            content: [{ type: "text", text: String(Number(a) + Number(b)) }],
          };
        }
        return { content: [{ type: "text", text: "Mock tool executed" }] };
      case "resources/list":
        return {
          resources: [
            {
              name: "app-logs",
              uri: "file:///var/log/app.log",
              mimeType: "text/plain",
            },
          ],
        };
      case "prompts/list":
        return {
          prompts: [
            {
              name: "debug-error",
              description: "Analyze an error log",
              arguments: [],
            },
            {
              name: "write-code",
              description: "Generate code snippet",
              arguments: [{ name: "language", required: true }],
            },
          ],
        };
      case "prompts/get":
        const promptParams = jsonRpc.params as { name: string };
        return {
          description: "Mock prompt result",
          messages: [
            {
              role: "user",
              content: {
                type: "text",
                text: "This is a mock prompt for " + promptParams.name,
              },
            },
          ],
        };
      default:
        return {};
    }
  }

  stop() {
    if (this.server) this.server.close();
  }
}
