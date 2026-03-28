/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export interface SandboxCapabilities {
  /** Directorios que el script puede leer */
  allowRead: string[];
  /** Directorios donde el script puede escribir */
  allowWrite: string[];
  /** Dominios permitidos (si alguno). Por defecto [] (sin internet) */
  allowNet?: string[];
  /** Variables de entorno permitidas. Por defecto [] (ninguna) */
  allowEnv?: string[];
}

export interface SandboxOptions {
  /** Directorio de trabajo (CWD) dentro del sandbox */
  cwd: string;
  /** Límites y permisos */
  capabilities: SandboxCapabilities;
  /** Tiempo máximo de ejecución en ms. Default: 5000ms */
  timeoutMs?: number;
  /** Memoria máxima en MB (aprox, via V8 flags). Default: 128MB */
  memoryLimitMb?: number;
}

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  /** Si se detectó alguna violación de seguridad en el output */
  taintCheck: {
    hasTaint: boolean;
    details: string[];
  };
}
