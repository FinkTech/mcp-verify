/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import fs from "fs";
import path from "path";
import os from "os";
import { spawn } from "child_process";
import { t } from "./i18n-helper";

export class ExternalEditor {
  static async edit(
    initialContent: string = "",
    extension: string = ".json",
  ): Promise<string> {
    const tempDir = os.tmpdir();
    const tempFile = path.join(tempDir, `mcp-input-${Date.now()}${extension}`);

    // Write initial content
    fs.writeFileSync(tempFile, initialContent);

    const editor =
      process.env.EDITOR ||
      (process.platform === "win32" ? "notepad.exe" : "vi");

    return new Promise((resolve, reject) => {
      // Spawn editor. 'stdio: inherit' ensures the editor takes over the terminal
      const child = spawn(editor, [tempFile], {
        stdio: "inherit",
        shell: true,
      });

      child.on("exit", (code) => {
        if (code === 0) {
          try {
            const content = fs.readFileSync(tempFile, "utf8");
            // Cleanup
            fs.unlinkSync(tempFile);
            resolve(content);
          } catch (err) {
            reject(err);
          }
        } else {
          reject(
            new Error(
              t("editor_exited_with_code", { code: code ?? "unknown" }),
            ),
          );
        }
      });

      child.on("error", (err) => {
        reject(err);
      });
    });
  }
}
