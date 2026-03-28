/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Advanced Taint Analyzer
 * Analiza la salida del sandbox buscando fugas de información.
 */
export class TaintAnalyzer {
  
  /**
   * Analiza un texto buscando secretos conocidos o patrones sospechosos.
   * @param output El texto a analizar (stdout/stderr)
   * @param secrets Lista de secretos (API keys, tokens) que NO deben salir
   */
  public analyze(output: string, secrets: string[] = []): { hasTaint: boolean; details: string[] } {
    const details: string[] = [];

    // 1. Búsqueda literal de secretos
    for (const secret of secrets) {
      if (secret.length > 5 && output.includes(secret)) {
        details.push('CRITICAL: Secret leakage detected (Literal match)');
      }
    }

    // 2. Detección de patrones de codificación comunes (Base64 simple)
    // Esto es una heurística básica. En producción se usaría entropía.
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    // Si encontramos cadenas largas (>50 chars) que parecen Base64 sin espacios
    const potentialEncoded = output.match(/[A-Za-z0-9+/]{50,}/g);
    
    if (potentialEncoded) {
       // Aquí podríamos intentar decodificar y buscar secretos de nuevo
       // Por ahora, solo marcamos como sospechoso si la entropía es alta
       details.push('WARNING: High entropy string detected (Possible encoded data)');
    }

    // 3. Patrones de "Env Dump"
    if (output.includes('AWS_ACCESS_KEY') || output.includes('id_rsa')) {
      details.push('CRITICAL: Standard sensitive keywords detected in output');
    }

    return {
      hasTaint: details.length > 0,
      details
    };
  }
}
