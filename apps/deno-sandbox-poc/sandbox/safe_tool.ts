/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
try {
  const data = await Deno.readTextFile("./apps/deno-sandbox-poc/sandbox/data/allowed.txt");
  console.log("✅ ÉXITO: Pude leer el archivo permitido.");
  console.log("Contenido:", data);
} catch (error) {
  console.error("❌ ERROR: No pude leer el archivo permitido.", error);
  Deno.exit(1);
}