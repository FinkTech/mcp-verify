
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);

    // Response with emojis that will be split across byte boundaries
    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: { message: '¡Hola! 👋 Testing UTF-8 émojis 🚀' }
    }) + '\n';

    // Send in chunks that will split multibyte characters
    const chunkSize = 5; // Small chunks to ensure emoji are split
    for (let i = 0; i < response.length; i += chunkSize) {
      process.stdout.write(response.slice(i, i + chunkSize));
      const start = Date.now();
      while (Date.now() - start < 1) {} // Small delay
    }
  } catch (e) {
    // Ignore
  }
});
