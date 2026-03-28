/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs/promises';
import { existsSync } from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { ExecutionResult, SandboxOptions } from './types';
import { TaintAnalyzer } from './taint-analyzer';

export class DenoRunner {
  private analyzer: TaintAnalyzer;

  constructor() {
    this.analyzer = new TaintAnalyzer();
  }

  private getDenoExecutable(): string {
    // Check if we are in a Windows environment and if the standard install path exists
    if (process.platform === 'win32') {
      const home = process.env.USERPROFILE || 'C:\\Users\\Usuario';
      const defaultPath = path.join(home, '.deno\\bin\\deno.exe');
      if (existsSync(defaultPath)) {
        return defaultPath;
      }
    }
    return 'deno';
  }

  /**
   * Ejecuta código JS/TS de forma segura dentro de un subproceso Deno.
   */
  async execute(code: string, options: SandboxOptions): Promise<ExecutionResult> {
    const startTime = Date.now();
    const scriptId = randomUUID();
    const scriptPath = path.join(options.cwd, `__agent_script_${scriptId}.ts`);
    const denoExecutable = this.getDenoExecutable();

    // 1. Escribir el código a ejecutar en el sistema de archivos (dentro del CWD permitido)
    // Nota: Escribimos el script físicamente para que Deno pueda cargarlo.
    await fs.writeFile(scriptPath, code, 'utf-8');

    // 2. Construir argumentos de seguridad (The Cage)
    const args = [
      'run',
      '--no-prompt',        // Modo no interactivo (falla si pide input)
      '--no-lock',          // No generar lockfiles
      `--allow-read=${this.formatPathList(options.capabilities.allowRead)}`,
      `--allow-write=${this.formatPathList(options.capabilities.allowWrite)}`,
    ];

    // Red
    if (options.capabilities.allowNet && options.capabilities.allowNet.length > 0) {
      args.push(`--allow-net=${options.capabilities.allowNet.join(',')}`);
    } else {
      args.push('--allow-net=NONE'); // Bloqueo explícito
    }

    // Env Vars
    if (options.capabilities.allowEnv && options.capabilities.allowEnv.length > 0) {
      args.push(`--allow-env=${options.capabilities.allowEnv.join(',')}`);
    } else {
      args.push('--allow-env=NONE'); // Bloqueo explícito
    }

    // Subprocesos (SIEMPRE BLOQUEADO para el agente)
    // args.push('--allow-run=NONE'); // Deno bloquea por defecto si no se pasa el flag. Pasar 'NONE' intenta permitir un binario llamado 'NONE'.

    // Límites de V8
    const memLimit = options.memoryLimitMb || 128;
    args.push(`--v8-flags=--max-old-space-size=${memLimit}`);

    // El script a ejecutar
    args.push(scriptPath);

    // 3. Ejecutar Proceso
    let child: ChildProcess;
    const timeoutMs = options.timeoutMs || 5000;

    return new Promise<ExecutionResult>(async (resolve) => {
      // stdout/stderr buffers
      let stdout = '';
      let stderr = '';

      try {
        child = spawn(denoExecutable, args, {
          cwd: options.cwd,
          env: {}, // Limpieza total de env vars del host
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (err) {
        return resolve({
          stdout: '',
          stderr: `Failed to spawn deno at ${denoExecutable}: ${err}`,
          exitCode: -1,
          durationMs: 0,
          taintCheck: { hasTaint: false, details: [] }
        });
      }

      child.stdout?.on('data', (data) => { stdout += data.toString(); });
      child.stderr?.on('data', (data) => { stderr += data.toString(); });

      // Timeout Safety Valve
      const timer = setTimeout(() => {
        if (!child.killed) {
          child.kill('SIGKILL');
          stderr += `\n[HOST]: Execution timed out after ${timeoutMs}ms`;
        }
      }, timeoutMs);

      child.on('close', async (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - startTime;

        // Limpieza: Borrar el script temporal
        try {
          await fs.unlink(scriptPath);
        } catch (e) {
          // Ignorar error de borrado si no existe
        }

        // Análisis de Seguridad de Salida
        const taintCheck = this.analyzer.analyze(stdout + stderr);

        resolve({
          stdout,
          stderr,
          exitCode: code ?? -1,
          durationMs,
          taintCheck
        });
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({
          stdout,
          stderr: `Failed to start subprocess: ${err.message}`,
          exitCode: -1,
          durationMs: Date.now() - startTime,
          taintCheck: { hasTaint: false, details: [] }
        });
      });
    });
  }

  private formatPathList(paths: string[]): string {
    if (!paths || paths.length === 0) return 'NONE';
    // Resolver paths absolutos para seguridad
    return paths.map(p => path.resolve(p)).join(',');
  }
}
