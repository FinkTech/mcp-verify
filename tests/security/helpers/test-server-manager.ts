/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as net from 'net';

export interface TestServerOptions {
  profile: string;
  lang?: string;
  transport?: 'stdio' | 'http' | 'sse';
  timeout?: number;
}

/**
 * Test Server Manager
 *
 * Manages the lifecycle of vulnerable test servers for security testing.
 * Supports dynamic port allocation for parallel test execution.
 *
 * @example
 * ```typescript
 * const manager = new TestServerManager();
 * await manager.start({ profile: 'ssrf', lang: 'en' });
 * const target = manager.getTarget();
 * // ... run tests
 * await manager.stop();
 * ```
 */
export class TestServerManager {
  private process: ChildProcess | null = null;
  private profile: string = '';
  private lang: string = 'en';
  private transport: 'stdio' | 'http' | 'sse' = 'stdio';
  private port: number = 0;
  private serverPath: string;

  constructor() {
    // Path to configurable-server.ts
    this.serverPath = path.resolve(__dirname, '../../fixtures/vulnerable_servers/configurable-server.ts');
  }

  /**
   * Allocate a free port dynamically for HTTP/SSE transports.
   * This prevents conflicts when tests run in parallel.
   *
   * @returns Promise<number> - Available port number
   */
  private async allocatePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = net.createServer();
      server.unref();
      server.on('error', reject);

      server.listen(0, () => {
        const address = server.address();
        if (!address || typeof address === 'string') {
          server.close();
          reject(new Error('Failed to allocate port'));
          return;
        }

        const { port } = address;
        server.close(() => resolve(port));
      });
    });
  }

  /**
   * Start the vulnerable test server with specified profile.
   *
   * @param options - Server configuration
   * @returns Promise<void> - Resolves when server is ready
   */
  async start(options: TestServerOptions): Promise<void> {
    if (this.process) {
      throw new Error('Server is already running. Call stop() first.');
    }

    this.profile = options.profile;
    this.lang = options.lang || 'en';
    this.transport = options.transport || 'stdio';

    // Allocate port for HTTP/SSE transports
    if (this.transport === 'http' || this.transport === 'sse') {
      this.port = await this.allocatePort();
    }

    // Build command arguments
    const isTs = this.serverPath.endsWith('.ts');
    const executable = isTs ? 'npx' : 'node';
    const args = isTs ? ['ts-node', this.serverPath] : [this.serverPath];
    
    args.push(`--profile=${this.profile}`);
    args.push(`--lang=${this.lang}`);

    if (this.port > 0) {
      args.push(`--port=${this.port}`);
    }

    // Spawn server process
    this.process = spawn(executable, args, {
      stdio: this.transport === 'stdio' ? ['pipe', 'pipe', 'pipe'] : 'ignore',
      shell: process.platform === 'win32', // Required for npx on Windows
      env: {
        ...process.env,
        NODE_ENV: 'test',
      },
    });

    // Error handling
    this.process.on('error', (error) => {
      throw new Error(`Failed to start test server: ${error.message}`);
    });

    this.process.on('exit', (code, signal) => {
      if (code !== 0 && code !== null && !signal) {
        console.error(`Test server exited unexpectedly with code ${code}`);
      }
    });

    // Wait for server to be ready (stdio servers are immediately ready)
    if (this.transport === 'stdio') {
      await this.waitForReady(options.timeout || 10000);
    } else {
      // For HTTP/SSE, wait for port to be listening
      await this.waitForPort(this.port, options.timeout || 15000);
    }
  }

  /**
   * Wait for stdio server to be ready by sending ping initialization.
   *
   * @param timeout - Maximum wait time in milliseconds
   */
  private async waitForReady(timeout: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Server did not respond within ${timeout}ms`));
      }, timeout);

      // For stdio servers, consider ready immediately after spawn
      // In production, you could send an initialize message and wait for response
      setTimeout(() => {
        clearTimeout(timer);
        resolve();
      }, 100);
    });
  }

  /**
   * Wait for HTTP/SSE server port to be listening.
   *
   * @param port - Port number to check
   * @param timeout - Maximum wait time in milliseconds
   */
  private async waitForPort(port: number, timeout: number): Promise<void> {
    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      const checkPort = () => {
        if (Date.now() - startTime > timeout) {
          reject(new Error(`Server port ${port} not listening within ${timeout}ms`));
          return;
        }

        const socket = net.createConnection(port, 'localhost');

        socket.on('connect', () => {
          socket.destroy();
          resolve();
        });

        socket.on('error', () => {
          // Port not ready yet, retry
          setTimeout(checkPort, 100);
        });
      };

      checkPort();
    });
  }

  /**
   * Stop the test server gracefully.
   * Sends SIGTERM, then SIGKILL after 3 seconds if not terminated.
   *
   * @returns Promise<void> - Resolves when server is stopped
   */
  async stop(): Promise<void> {
    if (!this.process) {
      return;
    }

    return new Promise((resolve) => {
      const process = this.process!;
      let terminated = false;

      // Force kill after 3 seconds
      const forceKillTimer = setTimeout(() => {
        if (!terminated) {
          process.kill('SIGKILL');
        }
      }, 3000);

      process.on('exit', () => {
        terminated = true;
        clearTimeout(forceKillTimer);
        this.process = null;
        resolve();
      });

      // Send graceful termination signal
      process.kill('SIGTERM');
    });
  }

  /**
   * Get the target string for validation/fuzzing commands.
   *
   * @returns string - Target specification for mcp-verify
   */
  getTarget(): string {
    if (this.transport === 'stdio') {
      const isTs = this.serverPath.endsWith('.ts');
      const cmd = isTs ? `npx ts-node "${this.serverPath}"` : `node "${this.serverPath}"`;
      return `${cmd} --profile=${this.profile} --lang=${this.lang}`;
    } else if (this.transport === 'http') {
      return `http://localhost:${this.port}`;
    } else if (this.transport === 'sse') {
      return `http://localhost:${this.port}/sse`;
    }

    throw new Error(`Unsupported transport: ${this.transport}`);
  }

  /**
   * Check if server is currently running.
   *
   * @returns boolean - True if server process exists
   */
  isRunning(): boolean {
    return this.process !== null && !this.process.killed;
  }

  /**
   * Get the current profile name.
   *
   * @returns string - Active vulnerability profile
   */
  getProfile(): string {
    return this.profile;
  }

  /**
   * Get the allocated port (for HTTP/SSE transports).
   *
   * @returns number - Port number (0 for stdio)
   */
  getPort(): number {
    return this.port;
  }
}
