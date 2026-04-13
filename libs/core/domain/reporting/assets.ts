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
  // Professional Lucide-inspired SVGs for v1.0
  shield: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
  check: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
  alert: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  copy: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`,
  info: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`,
  download: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M12 12v9"/><path d="m8 17 4 4 4-4"/></svg>`,
  baseline: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  terminal: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
  lightbulb: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A5 5 0 0 0 8 8c0 1.3.5 2.6 1.5 3.5.8.3 1.3 1.5 1.5 2.5"/><line x1="9" y1="18" x2="15" y2="18"/><line x1="10" y1="22" x2="14" y2="22"/></svg>`,
  code: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><path d="m18 16 4-4-4-4"/><path d="m6 8-4 4 4 4"/><path d="m14.5 4-5 16"/></svg>`,
  search: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
  target: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide-icon"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`,
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
