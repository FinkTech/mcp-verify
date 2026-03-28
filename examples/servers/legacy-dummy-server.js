const http = require('http');
const url = require('url');

const PORT = 3000;

const server = http.createServer((req, res) => {
  // CORS headers para evitar problemas
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  const parsedUrl = url.parse(req.url, true);
  const messageParam = parsedUrl.query.message;

  if (!messageParam) {
    res.writeHead(400);
    res.end('Missing message parameter');
    return;
  }

  // Preparamos headers para SSE (Server-Sent Events)
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  try {
    const jsonRpc = JSON.parse(messageParam);
    console.log(`[DummyServer] Received method: ${jsonRpc.method}`);

    let result = null;

    // Simulamos las respuestas según el método
    switch (jsonRpc.method) {
      case 'initialize':
        result = {
          protocolVersion: '2024-11-05',
          serverInfo: {
            name: 'mock-mcp-server',
            version: '1.0.0'
          }
        };
        break;

      case 'tools/list':
        result = {
          tools: [
            {
              name: 'calculate_sum',
              description: 'Adds two numbers together',
              inputSchema: { type: 'object' }
            },
            {
              name: 'fetch_weather',
              description: 'Gets weather for a location'
            }
          ]
        };
        break;

      case 'resources/list':
        result = {
          resources: [
            {
              name: 'app-logs',
              uri: 'file:///var/log/app.log',
              mimeType: 'text/plain'
            }
          ]
        };
        break;

      case 'prompts/list':
        result = {
          prompts: [
            { name: 'debug-error', description: 'Analyze an error log' }
          ]
        };
        break;

      default:
        // Si no conocemos el método, devolvemos vacío o error
        result = {};
    }

    // Enviamos la respuesta en formato JSON-RPC envuelto en SSE
    const response = {
      jsonrpc: '2.0',
      id: jsonRpc.id,
      result: result
    };

    res.write(`data: ${JSON.stringify(response)}\n\n`);

  } catch (error) {
    console.error('Error parsing JSON:', error);
  }

  // Cerramos la conexión después de enviar (simulando respuesta única del validator actual)
  // Nota: En un server real esto se mantendría abierto, pero tu validator v0.1 cierra al recibir.
  setTimeout(() => res.end(), 100);
});

server.listen(PORT, () => {
  console.log(`\n🚀 Dummy MCP Server running at http://localhost:${PORT}`);
  console.log('Esperando conexiones de mcp-verify...\n');
});
