/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import http from "http";
import chalk from "chalk";
import { translations, Language, ITransport } from "@mcp-verify/core";
import { ToolExecutor } from "@mcp-verify/core/use-cases/playground/tool-executor";
import {
  JsonObject,
  McpTool,
} from "@mcp-verify/core/domain/shared/common.types";
import { t, getCurrentLanguage } from "@mcp-verify/shared";
import { registerCleanup } from "../utils/cleanup-handlers";
import {
  createTransport,
  detectTransportType,
} from "../utils/transport-factory";

function generateDashboardHTML(lang: Language): string {
  const t = translations[lang];

  return `
<!DOCTYPE html>
<html lang="${lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${t.dashboard_title}</title>
    <!-- PrismJS for Syntax Highlighting -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: rgba(30, 41, 59, 0.7);
            --border: rgba(148, 163, 184, 0.1);
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.2);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #22c55e;
            --error: #ef4444;
            --method-tool: #a78bfa;
            --method-resource: #34d399;
        }

        * { box-sizing: border-box; }

        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-dark);
            background-image: radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.1) 0px, transparent 50%),
                              radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.1) 0px, transparent 50%);
            color: var(--text-main);
            margin: 0;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* --- Header --- */
        header {
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border);
            padding: 0 1.5rem;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            z-index: 10;
        }

        .brand {
            font-weight: 700;
            font-size: 1.1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: white;
        }
        .brand span { color: var(--accent); }

        .connection-pill {
            font-size: 0.75rem;
            padding: 0.25rem 0.75rem;
            border-radius: 99px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: #64748b; transition: all 0.3s; }
        .dot.active { background: var(--success); box-shadow: 0 0 10px var(--success); }

        /* --- Layout --- */
        .container {
            display: flex;
            flex: 1;
            overflow: hidden;
        }

        /* --- Sidebar --- */
        aside {
            width: 260px;
            background: rgba(15, 23, 42, 0.5);
            border-right: 1px solid var(--border);
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .nav-item {
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            color: var(--text-muted);
            transition: all 0.2s;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .nav-item:hover { background: rgba(255,255,255,0.03); color: white; }
        .nav-item.active {
            background: var(--accent-glow);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.2);
        }

        /* --- Main Content --- */
        main {
            flex: 1;
            padding: 1.5rem;
            overflow-y: auto;
            position: relative;
        }

        /* --- Cards & UI Elements --- */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .card-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            background: rgba(255,255,255,0.02);
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* --- Traffic Log Styles --- */
        #traffic-list {
            display: flex;
            flex-direction: column;
        }
        
        .log-item {
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
            transition: background 0.2s;
        }
        .log-item:hover { background: rgba(255,255,255,0.02); }
        
        .log-summary {
            padding: 0.75rem 1.5rem;
            display: grid;
            grid-template-columns: 80px 40px 1fr auto;
            align-items: center;
            gap: 1rem;
            cursor: pointer;
        }

        .log-time { color: var(--text-muted); font-size: 0.8rem; font-family: monospace; }
        .direction { font-weight: bold; }
        .direction.in { color: var(--accent); }
        .direction.out { color: var(--success); }
        
        .method-badge {
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.75rem;
            background: rgba(255,255,255,0.1);
        }
        .method-badge.tool { color: var(--method-tool); background: rgba(167, 139, 250, 0.15); }
        .method-badge.resource { color: var(--method-resource); background: rgba(52, 211, 153, 0.15); }

        .log-details {
            padding: 0 1.5rem 1rem 1.5rem;
            display: none;
            background: rgba(0,0,0,0.2);
        }
        .log-details.open { display: block; }

        /* --- Playground Styles --- */
        .playground-grid {
            display: grid;
            grid-template-columns: 350px 1fr;
            gap: 1.5rem;
            height: calc(100vh - 100px);
        }

        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: var(--text-muted); font-size: 0.85rem; }
        
        input, select {
            width: 100%;
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border);
            color: white;
            padding: 0.6rem;
            border-radius: 0.375rem;
            font-family: inherit;
            transition: border-color 0.2s;
        }
        input:focus, select:focus { outline: none; border-color: var(--accent); }

        .btn {
            background: var(--accent);
            color: #0f172a;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.375rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }

        /* Syntax Highlighter Overrides */
        pre[class*="language-"] {
            margin: 0 !important;
            border-radius: 0.5rem;
            font-size: 0.85rem;
            background: #0b101b !important;
            border: 1px solid var(--border);
        }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            ${t.dashboard_brand}
        </div>
        <div class="connection-pill">
            <div id="connection-dot" class="dot"></div>
            <span id="target-display">${t.dashboard_connecting}</span>
        </div>
    </header>

    <div class="container">
        <aside>
            <div class="nav-item active" onclick="switchTab('traffic')">
                <span>📊</span> ${t.dashboard_traffic_inspector}
            </div>
            <div class="nav-item" onclick="switchTab('playground')">
                <span>🎮</span> ${t.dashboard_interactive_playground}
            </div>
            <div style="flex:1"></div>
            <div style="font-size:0.75rem; color:#475569; padding:1rem;">
                ${t.version_author}
            </div>
        </aside>

        <main>
            <!-- TRAFFIC TAB -->
            <div id="tab-traffic">
                <div class="card">
                    <div class="card-header">
                        <span>${t.dashboard_live_traffic}</span>
                        <div style="display:flex; gap:0.5rem">
                            <button onclick="clearLogs()" style="background:none; border:1px solid var(--border); color:var(--text-muted); padding:0.25rem 0.5rem; border-radius:4px; cursor:pointer">${t.dashboard_clear}</button>
                        </div>
                    </div>
                    <div id="traffic-list">
                        <div style="padding:3rem; text-align:center; color:var(--text-muted)">
                            ${t.dashboard_waiting_requests}<br>
                            <span style="font-size:0.8rem; opacity:0.7">${t.dashboard_connect_client}</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- PLAYGROUND TAB -->
            <div id="tab-playground" style="display:none; height:100%">
                <div class="playground-grid">
                    <!-- Left: Controls -->
                    <div class="card" style="display:flex; flex-direction:column;">
                        <div class="card-header">${t.dashboard_configure_request}</div>
                        <div style="padding:1.5rem; flex:1; overflow-y:auto">
                            <div class="form-group">
                                <label>${t.dashboard_tool_capability}</label>
                                <select id="tool-selector" onchange="renderToolForm()">
                                    <option value="">${t.dashboard_select_tool}</option>
                                </select>
                            </div>
                            <div id="dynamic-form">
                                <!-- Inputs generated here -->
                            </div>
                        </div>
                        <div style="padding:1.5rem; border-top:1px solid var(--border)">
                            <button class="btn" onclick="executeTool()" id="exec-btn">${t.dashboard_run_tool}</button>
                        </div>
                    </div>

                    <!-- Right: Results -->
                    <div class="card" style="display:flex; flex-direction:column;">
                        <div class="card-header">
                            <span>${t.dashboard_response}</span>
                            <span id="latency-display" style="font-size:0.8rem; color:var(--text-muted)"></span>
                        </div>
                        <div style="flex:1; background:#0b101b; overflow:hidden; position:relative">
                            <pre><code id="result-code" class="language-json">${t.dashboard_results_placeholder}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- PrismJS Script -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>

    <script>
        // --- State Management ---
        let tools = [];
        let isConnected = false;

        // --- UI Navigation ---
        function switchTab(id) {
            document.getElementById('tab-traffic').style.display = 'none';
            document.getElementById('tab-playground').style.display = 'none';
            document.getElementById('tab-' + id).style.display = 'block';
            
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            event.currentTarget.classList.add('active');
        }

        // --- Traffic Logic ---
        function clearLogs() {
            document.getElementById('traffic-list').innerHTML = '';
        }

        function addLogEntry(data) {
            const container = document.getElementById('traffic-list');
            // Remove empty state if present
            if (container.children.length === 1 && container.children[0].style.padding === '3rem') container.innerHTML = '';

            const id = 'log-' + Date.now();
            const time = new Date().toLocaleTimeString();
            const method = data.method || (data.result ? 'response' : 'unknown');
            const type = method.startsWith('tools/') ? 'tool' : 'resource';
            const icon = data.direction === 'in' ? '➡' : '⬅';
            const dirClass = data.direction === 'in' ? 'in' : 'out';

            const html = \`
                <div class="log-item">
                    <div class="log-summary" onclick="toggleLog('\${id}')">
                        <span class="log-time">\${time}</span>
                        <span class="direction \${dirClass}">\${icon}</span>
                        <span>\${method}</span>
                        <span class="method-badge \${type}">\${type}</span>
                    </div>
                    <div id="\${id}" class="log-details">
                        <pre><code class="language-json">\${JSON.stringify(data.params || data.result || data, null, 2)}</code></pre>
                    </div>
                </div>
            \`;

            // Insert after header
            container.insertAdjacentHTML('afterbegin', html);
            Prism.highlightAll();
        }

        function toggleLog(id) {
            document.getElementById(id).classList.toggle('open');
        }

        // --- Playground Logic ---
        function renderToolForm() {
            const toolName = document.getElementById('tool-selector').value;
            const container = document.getElementById('dynamic-form');
            container.innerHTML = '';

            const tool = tools.find(t => t.name === toolName);
            if (!tool) return;

            if (tool.inputSchema?.properties) {
                Object.entries(tool.inputSchema.properties).forEach(([key, schema]) => {
                    const group = document.createElement('div');
                    group.className = 'form-group';
                    
                    const label = document.createElement('label');
                    label.innerText = key;
                    if(schema.description) label.innerHTML += \` <span style="opacity:0.6">(\${schema.description})</span>\`;
                    
                    const input = document.createElement('input');
                    input.id = 'arg-' + key;
                    input.placeholder = schema.type || 'string';
                    
                    group.appendChild(label);
                    group.appendChild(input);
                    container.appendChild(group);
                });
            } else {
                container.innerHTML = '<div style="color:var(--text-muted); font-style:italic">${t.dashboard_no_arguments}</div>';
            }
        }

        async function executeTool() {
            const toolName = document.getElementById('tool-selector').value;
            if (!toolName) return;

            const btn = document.getElementById('exec-btn');
            btn.disabled = true;
            btn.innerText = '${t.dashboard_running}';
            const startTime = Date.now();

            // Collect Args
            const args = {};
            document.querySelectorAll('[id^="arg-"]').forEach(input => {
                const key = input.id.replace('arg-', '');
                if (input.value) args[key] = input.value; 
            });

            try {
                const res = await fetch('/api/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: toolName, arguments: args })
                });
                
                const data = await res.json();
                const duration = Date.now() - startTime;
                
                document.getElementById('latency-display').innerText = \`\${duration}ms\`;
                document.getElementById('result-code').textContent = JSON.stringify(data, null, 2);
                Prism.highlightAll();
            } catch (e) {
                document.getElementById('result-code').textContent = JSON.stringify({ error: e.message }, null, 2);
            } finally {
                btn.disabled = false;
                btn.innerText = '${t.dashboard_run_tool}';
            }
        }

        // --- Connection (SSE) ---
        function connect() {
            const sse = new EventSource('/sse');

            sse.onopen = () => {
                isConnected = true;
                document.getElementById('connection-dot').classList.add('active');
                document.getElementById('target-display').innerText = '${t.dashboard_connected}';
            };

            sse.onerror = () => {
                isConnected = false;
                document.getElementById('connection-dot').classList.remove('active');
                document.getElementById('target-display').innerText = '${t.dashboard_reconnecting}';
            };

            sse.addEventListener('tools', (e) => {
                try {
                    tools = JSON.parse(e.data);
                    const select = document.getElementById('tool-selector');
                    const current = select.value;
                    select.innerHTML = '<option value="">${t.dashboard_select_tool}</option>';
                    tools.forEach(t => {
                        const opt = document.createElement('option');
                        opt.value = t.name;
                        opt.innerText = t.name;
                        select.appendChild(opt);
                    });
                    if (current) select.value = current;
                } catch (error) {
                    console.error('Failed to parse tools event:', error);
                }
            });

            sse.addEventListener('log', (e) => {
                try {
                    const log = JSON.parse(e.data);
                    addLogEntry(log);
                } catch (error) {
                    console.error('Failed to parse log event:', error);
                }
            });
        }

        // Initialize
        connect();
    </script>
</body>
</html>
`;
}

export async function runDashboardAction(
  target: string,
  options: Record<string, unknown>,
) {
  const port = parseInt(String(options.port || "8080"));
  const lang = getCurrentLanguage();
  const trans = translations[lang];

  console.log(chalk.cyan(`🚀 ${trans.dashboard_starting}`));
  console.log(
    chalk.gray(`${trans.dashboard_target_server} ` + chalk.white(target)),
  );
  console.log(
    chalk.green(`👉 ${trans.dashboard_active_at} http://localhost:${port}`),
  );

  const DASHBOARD_HTML = generateDashboardHTML(lang);

  // Initialize MCP connection for real tool execution
  let toolExecutor: ToolExecutor | null = null;
  let transport: ITransport | null = null;
  let realTools: McpTool[] = [];

  try {
    // Create transport and executor
    const transportType = detectTransportType(target);
    transport = createTransport(target, { transportType });
    toolExecutor = new ToolExecutor(transport);

    // Connect to server
    console.log(chalk.gray(trans.dashboard_connecting_server));
    await toolExecutor.connect();

    // Fetch real tools
    realTools = await toolExecutor.listTools();
    console.log(
      chalk.green(
        trans.dashboard_connected_count.replace(
          "{count}",
          String(realTools.length),
        ),
      ),
    );
  } catch (error) {
    console.log(chalk.yellow(trans.dashboard_error_connect));
    console.log(
      chalk.gray(
        `   Error: ${error instanceof Error ? error.message : String(error)}`,
      ),
    );
    console.log(chalk.gray(trans.dashboard_mock_mode));
  }

  const server = http.createServer(async (req, res) => {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");

    // 1. Serve Dashboard HTML
    if (req.url === "/" || req.url === "/index.html") {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(DASHBOARD_HTML);
      return;
    }

    // 2. SSE Endpoint
    if (req.url === "/sse") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });

      // Send real tools if available, otherwise fallback to mock tools
      const toolsToSend =
        realTools.length > 0
          ? realTools
          : [
              {
                name: "calculator",
                description: trans.calculator_desc,
                inputSchema: {
                  properties: {
                    operation: { type: "string" },
                    a: { type: "number" },
                    b: { type: "number" },
                  },
                },
              },
              {
                name: "get_weather",
                description: trans.get_weather_desc,
                inputSchema: { properties: { city: { type: "string" } } },
              },
            ];
      res.write(`event: tools\ndata: ${JSON.stringify(toolsToSend)}\n\n`);

      const interval = setInterval(() => res.write(": keep-alive\n\n"), 15000);
      req.on("close", () => clearInterval(interval));
      return;
    }

    // 3. API Execution Endpoint
    if (req.url === "/api/execute" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", async () => {
        try {
          const reqData = JSON.parse(body);

          // Execute real tool if executor is available
          if (toolExecutor) {
            try {
              const result = await toolExecutor.executeTool(
                reqData.name,
                reqData.arguments || {},
              );

              if (result.success) {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(
                  JSON.stringify({
                    jsonrpc: "2.0",
                    id: 1,
                    result: result.result,
                  }),
                );
              } else {
                res.writeHead(500, { "Content-Type": "application/json" });
                res.end(
                  JSON.stringify({
                    jsonrpc: "2.0",
                    id: 1,
                    error: {
                      code: -32000,
                      message: result.error || trans.dashboard_exec_failed,
                    },
                  }),
                );
              }
            } catch (execError) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  error: {
                    code: -32000,
                    message:
                      execError instanceof Error
                        ? execError.message
                        : trans.dashboard_unknown_exec_error,
                  },
                }),
              );
            }
          } else {
            // Fallback to mock execution if no real connection
            const mockResponse = {
              jsonrpc: "2.0",
              id: 1,
              result: {
                content: [
                  {
                    type: "text",
                    text: `${trans.dashboard_mock_notice}\n\nTool: ${reqData.name}\nArguments: ${JSON.stringify(reqData.arguments, null, 2)}\n\n${trans.executed_successfully.replace("{tool}", reqData.name)}`,
                  },
                ],
              },
            };
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(mockResponse));
          }
        } catch (e) {
          res.writeHead(500);
          res.end(
            JSON.stringify({
              error: e instanceof Error ? e.message : trans.execution_failed,
            }),
          );
        }
      });
      return;
    }

    res.writeHead(404);
    res.end(trans.not_found);
  });

  server.listen(port, () => {
    // Optional: Auto open
    // import('open').then(o => o.default(`http://localhost:${port}`));
  });

  // Handle auto-stop timeout if provided
  const timeoutMs = options.timeout ? parseInt(String(options.timeout)) : 0;
  if (timeoutMs > 0) {
    console.log(chalk.gray(t("proxy_auto_stopping", { ms: timeoutMs })));
    return new Promise<void>((resolve) => {
      setTimeout(async () => {
        console.log(chalk.yellow(`\n✅ ${t("goodbye")}`));
        server.close();
        if (toolExecutor) await toolExecutor.close();
        if (transport) transport.close();
        process.exit(0);
      }, timeoutMs);
    });
  }

  // Register cleanup handler
  registerCleanup(async () => {
    console.log(chalk.gray(`\n${trans.dashboard_closing}`));
    if (toolExecutor) {
      await toolExecutor.close();
    }
    if (transport) {
      transport.close();
    }
    server.close();
    console.log(chalk.green(`${trans.dashboard_closed}`));
  });
}
