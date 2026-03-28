
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);

    // Send response with empty lines before it
    process.stdout.write('\n\n');
    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: { success: true }
    }) + '\n';
    process.stdout.write(response);
  } catch (e) {
    // Ignore
  }
});
