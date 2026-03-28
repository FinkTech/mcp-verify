/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { DenoSandbox } from '../deno-sandbox';
import path from 'path';

describe('DenoSandbox', () => {
    it('should wrap command with deno run', () => {
        const sandbox = new DenoSandbox();
        const [cmd, args] = sandbox.wrap('server.js', []);

        expect(cmd).toBe('deno');
        expect(args[0]).toBe('run');
        expect(args).toContain('server.js');
    });

    it('should add --allow-env by default', () => {
        const sandbox = new DenoSandbox();
        const [_, args] = sandbox.wrap('server.js', []);
        expect(args).toContain('--allow-env');
    });

    it('should restrict network by default', () => {
        const sandbox = new DenoSandbox();
        const [_, args] = sandbox.wrap('server.js', []);
        // Should NOT contain allow-net unless specified
        const netArg = args.find(a => a.startsWith('--allow-net'));
        expect(netArg).toBeUndefined();
    });

    it('should allow specific network domains', () => {
        const sandbox = new DenoSandbox({
            allowNet: ['google.com', 'api.test']
        });
        const [_, args] = sandbox.wrap('server.js', []);
        expect(args).toContain('--allow-net=google.com,api.test');
    });

    it('should handle node/npx commands adaptation', () => {
        const sandbox = new DenoSandbox();
        const [cmd, args] = sandbox.wrap('node', ['index.js']);
        // Deno run index.js directly, skipping 'node' keyword as Deno 1.34+ handles compat
        expect(cmd).toBe('deno');
        expect(args).toContain('run');
        expect(args).toContain('index.js');
        expect(args).not.toContain('node');
    });

    it('should throw SECURITY WARNING for unsupported runtimes (Python)', () => {
        const sandbox = new DenoSandbox();
        expect(() => {
            sandbox.wrap('python', ['server.py']);
        }).toThrow(/SANDBOX LIMITATION/);
    });
});
