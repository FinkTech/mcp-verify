/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
console.log("😈 Intentando leer un archivo prohibido (package.json raíz)...");

try {
  // Intentamos salir del sandbox
  const data = await Deno.readTextFile("../../../package.json");
  console.log("❌ FALLO DE SEGURIDAD: ¡Pude leer el archivo prohibido!");
  console.log(data.substring(0, 50) + "...");
} catch (error) {
  if (error instanceof Deno.errors.PermissionDenied) {
    console.log("✅ ÉXITO: El sandbox bloqueó el acceso (PermissionDenied).");
  } else {
    console.error("❓ ERROR INESPERADO:", error);
  }
}

console.log("\n😈 Intentando acceder a la red (google.com)...");
try {
  const res = await fetch("https://google.com");
  console.log("❌ FALLO DE SEGURIDAD: ¡Tengo internet!");
} catch (error) {
  if (error instanceof Deno.errors.PermissionDenied) {
    console.log("✅ ÉXITO: El sandbox bloqueó la red (PermissionDenied).");
  } else {
    console.error("❓ ERROR INESPERADO:", error);
  }
}
