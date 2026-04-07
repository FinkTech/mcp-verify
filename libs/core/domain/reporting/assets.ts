/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ============================================
 * ASSETS MODULE - Centralized Image Management
 * ============================================
 *
 * Este módulo gestiona todos los assets visuales para reportes HTML.
 *
 * CÓMO AGREGAR IMÁGENES:
 * ----------------------
 *
 * 1. **SVG (Recomendado para iconos/logos):**
 *    - Pega el código SVG directamente como string
 *    - Optimiza primero con: https://jakearchibald.github.io/svgomg/
 *    - Ejemplo: export const MI_ICONO = `<svg>...</svg>`
 *
 * 2. **WebP/PNG (Para fotos/screenshots):**
 *    - Optimiza la imagen a <20KB
 *    - Convierte a Base64: https://www.base64-image.de/
 *    - Agrega: export const MI_IMAGEN = 'data:image/webp;base64,...'
 *
 * 3. **JPEG (Último recurso, más pesado):**
 *    - Solo si WebP no es opción
 *    - Usa calidad 70-80%
 *    - Base64: export const MI_FOTO = 'data:image/jpeg;base64,...'
 *
 * PERFORMANCE BUDGET:
 * - Iconos SVG: Sin límite (escalables)
 * - Logo/Brand: <5KB
 * - Hero Image: <20KB
 * - Total assets inline: <50KB
 */

// ============================================
// ICONOS (SVG inline)
// ============================================
// TODO: Agrega aquí tus iconos SVG optimizados
// Ejemplo: export const ICON_SECURITY = `<svg>...</svg>`

export const ICONS = {
  // Placeholder - Reemplaza con tus SVGs cuando los tengas
  shield: "", // TODO: Agregar SVG de escudo
  check: "", // TODO: Agregar SVG de check
  alert: "", // TODO: Agregar SVG de alerta
  copy: "", // TODO: Agregar SVG de copiar
  info: "", // TODO: Agregar SVG de info
  download: "", // TODO: Agregar SVG de descarga
  baseline: "", // TODO: Agregar SVG de baseline
};

// ============================================
// YOGUI - MASCOTA OFICIAL (v1.1+)
// ============================================
// Estados de Yogui según severity del scan
// Formato: SVG inline o Base64
// Resolución recomendada: 120x120px

export const YOGUI_STATES = {
  // TODO v1.1: Agregar SVG/PNG de Yogui escaneando
  scanning: "",

  // TODO v1.1: Agregar SVG/PNG de Yogui con escudo (crítico)
  shield: "",

  // TODO v1.1: Agregar SVG/PNG de Yogui celebrando (success)
  celebrating: "",

  // TODO v1.1: Agregar SVG/PNG de Yogui pensativo (warning)
  thinking: "",
};

// ============================================
// LOGO/BRAND
// ============================================
// Logo principal para reportes HTML
// Formatos aceptados: SVG (recomendado) o WebP Base64
// Tamaño: 32x32px o 64x64px

// TODO: Agregar tu logo aquí
// Ejemplo SVG: export const LOGO_SVG = `<svg>...</svg>`
// Ejemplo WebP: export const LOGO_BASE64 = 'data:image/webp;base64,...'
export const LOGO_SVG = "";

// ============================================
// HERO IMAGE (Actual - JPEG pesado)
// ============================================
// IMPORTANTE: Esta imagen pesa mucho (>100KB)
// TODO v1.1: Reemplazar con WebP optimizado <20KB

export { HERO_IMAGE } from "./hero-image";

// ============================================
// ASCII ART - CLI (v1.0 - YA LISTO)
// ============================================
// Arte ASCII para terminal - No requiere imágenes

export const ASCII_ART = {
  welcome: `
   🧸 mcp-verify
  ═══════════════
   Security Scan
  ───────────────
`,

  version: (version: string) => `
   🧸 mcp-verify v${version}
   Enterprise MCP Security Scanner
`,

  scanning: `
   🧸 Yogui is scanning your MCP server...
`,

  success: `
   🧸✨ Scan Complete!
`,

  warning: `
   🧸⚠️  Issues Found
`,
};

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Convierte imagen a Base64 (para uso en Node.js)
 * @param filePath - Ruta del archivo de imagen
 * @returns String Base64 con data URI
 */
export function imageToBase64(
  filePath: string,
  mimeType: "image/webp" | "image/png" | "image/jpeg",
): string {
  // Implementar cuando necesites convertir imágenes locales
  // const fs = require('fs');
  // const imageBuffer = fs.readFileSync(filePath);
  // return `data:${mimeType};base64,${imageBuffer.toString('base64')}`;
  return "";
}

/**
 * Valida que un asset no exceda el performance budget
 * @param base64String - String Base64 a validar
 * @param maxKB - Tamaño máximo en KB
 */
export function validateAssetSize(
  base64String: string,
  maxKB: number,
): boolean {
  const sizeInBytes = (base64String.length * 3) / 4;
  const sizeInKB = sizeInBytes / 1024;
  return sizeInKB <= maxKB;
}
