
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);

    if (request.method === 'test/fragmented') {
      // Send response in 50 chunks of 1 byte each
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { success: true, message: 'Fragmented response' }
      }) + '\n';

      // Send byte by byte
      for (let i = 0; i < response.length; i++) {
        process.stdout.write(response[i]);
        // Small delay to ensure chunks are sent separately
        if (i < response.length - 1) {
          const start = Date.now();
          while (Date.now() - start < 1) {} // Busy wait 1ms
        }
      }
    } else if (request.method === 'test/oversized') {
      // Send a response that exceeds MAX_BUFFER_SIZE (10.1 MB)
      const oversizePayload = 'x'.repeat(10.1 * 1024 * 1024);
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { data: oversizePayload }
      }) + '\n';

      process.stdout.write(response);
    } else if (request.method === 'test/normal') {
      // Normal response for baseline testing
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { success: true }
      }) + '\n';

      process.stdout.write(response);
    } else {
      // Echo back unknown methods
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { method: request.method }
      }) + '\n';

      process.stdout.write(response);
    }
  } catch (e) {
    // Ignore parse errors
  }
});
