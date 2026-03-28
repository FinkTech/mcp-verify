/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { DenoRunner } from './deno-runner';
import { SafeJSStaticAnalyzer } from './static-analyzer';
import { SandboxOptions, ExecutionResult } from './types';

export interface SandboxExecutionError {
  stage: 'STATIC_ANALYSIS' | 'EXECUTION' | 'TAINT_ANALYSIS';
  message: string;
  details?: string[];
}

export class SandboxService {
  private runner: DenoRunner;
  private staticAnalyzer: SafeJSStaticAnalyzer;

  constructor() {
    this.runner = new DenoRunner();
    this.staticAnalyzer = new SafeJSStaticAnalyzer();
  }

  /**
   * Ejecuta un script de forma segura aplicando todas las barreras de defensa.
   * @param code Código fuente JS/TS a ejecutar
   * @param options Configuración del entorno (paths, timeouts, etc)
   */
  async runSafe(code: string, options: SandboxOptions): Promise<ExecutionResult> {
    // 1. BARRERA ESTÁTICA: Análisis de Código
    const analysis = this.staticAnalyzer.analyze(code);
    
    if (!analysis.isSafe) {
      const errorMsg = `Static Analysis Failed:\n${analysis.violations.map(v => `- ${v}`).join('\n')}`;
      throw {
        stage: 'STATIC_ANALYSIS',
        message: errorMsg,
        details: analysis.violations
      } as SandboxExecutionError;
    }

    // 2. BARRERA DINÁMICA: Ejecución en Sandbox (Deno)
    // El runner ya maneja la creación de jaula y limpieza
    const result = await this.runner.execute(code, options);

    // 3. BARRERA DE SALIDA: Análisis de Taint
    // (El runner ya ejecuta el TaintAnalyzer internamente, pero aquí evaluamos la política)
    if (result.taintCheck.hasTaint) {
       // Dependiendo de la política, podríamos rechazar el resultado totalmente
       // Por ahora, adjuntamos la advertencia en el resultado, o lanzamos error si es CRITICAL
       const isCritical = result.taintCheck.details.some(d => d.includes('CRITICAL'));
       if (isCritical) {
         throw {
           stage: 'TAINT_ANALYSIS',
           message: 'Security Violation: Critical secret leakage detected',
           details: result.taintCheck.details
         } as SandboxExecutionError;
       }
    }

    return result;
  }
}
