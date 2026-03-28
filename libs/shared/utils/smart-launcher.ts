/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import fs from 'fs';
import path from 'path';

export class SmartLauncher {
  /**
   * Detects the appropriate runtime command for a given target file.
   * e.g., "server.js" -> { command: "node", args: ["server.js"] }
   */
  static detect(target: string): { command: string; args: string[] } | null {
    // 1. If it's a URL, ignore
    if (target.startsWith('http://') || target.startsWith('https://')) {
      return null;
    }

    // 2. If file doesn't exist locally, assume it's a raw command string
    // e.g. "docker run -i my-image" or "git"
    if (!fs.existsSync(target)) {
        return null; // Let the caller handle it as a raw command string
    }

    // 3. Detect by extension
    const ext = path.extname(target).toLowerCase();

    switch (ext) {
        case '.js':
        case '.mjs':
        case '.cjs':
            return { command: 'node', args: [target] };
        
        case '.ts':
            // Requires ts-node to be installed or accessible via npx
            return { command: 'npx', args: ['ts-node', target] };
        
        case '.py':
            // On Windows often 'python', on Mac/Linux often 'python3'. 
            // Defaulting to 'python' for now, checking env could be an improvement.
            return { command: 'python', args: [target] };
            
        case '.sh':
            return { command: 'bash', args: [target] };
        
        case '.bat':
        case '.cmd':
        case '.exe':
            return { command: target, args: [] };
    }

    // 4. If no extension but executable (Linux/Mac), treat as binary
    // Simple return for now
    return { command: target, args: [] };
  }
}
