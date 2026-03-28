/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Path Validator Tests - Security Fix for CRITICAL-2
 *
 * Tests path traversal prevention for output paths and baseline paths.
 *
 * @module libs/shared/utils/__tests__/path-validator.spec
 */

import { PathValidator } from '../path-validator';
import path from 'path';
import fs from 'fs';
import os from 'os';

describe('PathValidator', () => {
  // Create temp directory for tests
  const tempDir = path.join(os.tmpdir(), 'mcp-verify-test-' + Date.now());

  beforeAll(() => {
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
  });

  afterAll(() => {
    // Cleanup temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('validateOutputPath', () => {
    it('should allow paths within base directory', () => {
      const baseDir = path.join(tempDir, 'reportes');

      const result = PathValidator.validateOutputPath('custom/report.json', baseDir);

      expect(result).toContain('reportes');
      expect(result).toContain('custom');
      expect(result).toContain('report.json');
      expect(path.isAbsolute(result)).toBe(true);
    });

    it('should allow simple filenames', () => {
      const baseDir = path.join(tempDir, 'reportes');

      const result = PathValidator.validateOutputPath('report.html', baseDir);

      expect(result).toContain('reportes');
      expect(result).toContain('report.html');
    });

    it('should allow nested directories', () => {
      const baseDir = path.join(tempDir, 'reportes');

      const result = PathValidator.validateOutputPath('2024/01/15/scan.json', baseDir);

      expect(result).toContain('reportes');
      expect(result).toContain('2024');
      expect(result).toContain('01');
      expect(result).toContain('15');
    });

    it('should block path traversal with ../', () => {
      const baseDir = path.join(tempDir, 'reportes');

      expect(() => {
        PathValidator.validateOutputPath('../../../etc/passwd', baseDir);
      }).toThrow(/Invalid output path/);

      expect(() => {
        PathValidator.validateOutputPath('../../../etc/passwd', baseDir);
      }).toThrow(/outside allowed directory/);
    });

    it('should block path traversal with complex patterns', () => {
      const baseDir = path.join(tempDir, 'reportes');

      expect(() => {
        PathValidator.validateOutputPath('./foo/../../bar/../../../etc/passwd', baseDir);
      }).toThrow(/Invalid output path/);
    });

    it('should block absolute paths outside base', () => {
      const baseDir = path.join(tempDir, 'reportes');

      expect(() => {
        PathValidator.validateOutputPath('/etc/passwd', baseDir);
      }).toThrow(/Invalid output path/);

      expect(() => {
        PathValidator.validateOutputPath('C:\\Windows\\System32\\config\\sam', baseDir);
      }).toThrow(/Invalid output path/);
    });

    it('should handle URL-encoded paths safely', () => {
      const baseDir = path.join(tempDir, 'reportes');

      // URL-encoded paths are NOT decoded by path.normalize()
      // So '..%2f..%2f' is treated as a literal filename, not traversal
      // This is safe behavior - it creates a weird filename inside baseDir
      const result = PathValidator.validateOutputPath('..%2f..%2f..%2fetc%2fpasswd', baseDir);

      // Should create file with literal name inside baseDir
      expect(result).toContain('reportes');
      expect(result).toContain('..%2f..%2f..%2fetc%2fpasswd');

      // Note: This is NOT a security issue because:
      // - Node.js doesn't decode %2f to /
      // - Filesystem doesn't interpret %2f as directory separator
      // - File is created inside baseDir with a weird name
    });

    it('should create directories if they do not exist', () => {
      const baseDir = path.join(tempDir, 'reportes-new');
      const nestedPath = 'deeply/nested/structure/report.json';

      const result = PathValidator.validateOutputPath(nestedPath, baseDir);

      // Check that parent directories were created
      const dir = path.dirname(result);
      expect(fs.existsSync(dir)).toBe(true);

      // Cleanup
      fs.rmSync(baseDir, { recursive: true, force: true });
    });
  });

  describe('validateBaselinePath', () => {
    const originalCwd = process.cwd();

    beforeEach(() => {
      // Change to temp directory for isolation
      process.chdir(tempDir);
    });

    afterEach(() => {
      // Restore original directory
      process.chdir(originalCwd);
    });

    it('should allow baseline within project', () => {
      const result = PathValidator.validateBaselinePath('./baseline.json');

      expect(result).toContain(tempDir);
      expect(result).toContain('baseline.json');
      expect(path.isAbsolute(result)).toBe(true);
    });

    it('should allow baseline in subdirectories', () => {
      const result = PathValidator.validateBaselinePath('config/security/baseline.json');

      expect(result).toContain(tempDir);
      expect(result).toContain('config');
      expect(result).toContain('security');
    });

    it('should block baseline outside project', () => {
      expect(() => {
        PathValidator.validateBaselinePath('../../outside/baseline.json');
      }).toThrow(/outside project directory/);
    });

    it('should block absolute paths outside project', () => {
      expect(() => {
        PathValidator.validateBaselinePath('/tmp/malicious-baseline.json');
      }).toThrow(/outside project directory/);
    });

    it('should block complex traversals', () => {
      expect(() => {
        PathValidator.validateBaselinePath('./foo/../../bar/../../../tmp/baseline.json');
      }).toThrow(/outside project directory/);
    });
  });

  describe('isSafeOutputPath', () => {
    it('should return true for safe paths', () => {
      const baseDir = path.join(tempDir, 'reportes');

      expect(PathValidator.isSafeOutputPath('report.json', baseDir)).toBe(true);
      expect(PathValidator.isSafeOutputPath('custom/report.html', baseDir)).toBe(true);
    });

    it('should return false for unsafe paths', () => {
      const baseDir = path.join(tempDir, 'reportes');

      expect(PathValidator.isSafeOutputPath('../../../etc/passwd', baseDir)).toBe(false);
      expect(PathValidator.isSafeOutputPath('/etc/passwd', baseDir)).toBe(false);
    });
  });

  describe('isSafeBaselinePath', () => {
    const originalCwd = process.cwd();

    beforeEach(() => {
      process.chdir(tempDir);
    });

    afterEach(() => {
      process.chdir(originalCwd);
    });

    it('should return true for safe baseline paths', () => {
      expect(PathValidator.isSafeBaselinePath('./baseline.json')).toBe(true);
      expect(PathValidator.isSafeBaselinePath('config/baseline.json')).toBe(true);
    });

    it('should return false for unsafe baseline paths', () => {
      expect(PathValidator.isSafeBaselinePath('../../outside/baseline.json')).toBe(false);
      expect(PathValidator.isSafeBaselinePath('/tmp/baseline.json')).toBe(false);
    });
  });

  describe('error messages', () => {
    it('should provide clear error messages for output path violations', () => {
      const baseDir = path.join(tempDir, 'reportes');

      try {
        PathValidator.validateOutputPath('../../../etc/passwd', baseDir);
        fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).toContain('[Security]');
        expect(error.message).toContain('Invalid output path');
        expect(error.message).toContain('Allowed:');
        expect(error.message).toContain('Attempted:');
        expect(error.message).toContain('path traversal');
      }
    });

    it('should provide clear error messages for baseline path violations', () => {
      const originalCwd = process.cwd();
      process.chdir(tempDir);

      try {
        PathValidator.validateBaselinePath('../../outside/baseline.json');
        fail('Should have thrown error');
      } catch (error: any) {
        expect(error.message).toContain('[Security]');
        expect(error.message).toContain('Invalid baseline path');
        expect(error.message).toContain('Project:');
        expect(error.message).toContain('Attempted:');
      } finally {
        process.chdir(originalCwd);
      }
    });
  });
});
