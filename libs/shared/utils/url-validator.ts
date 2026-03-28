/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * URL Validator - Detects Private/Reserved IP Addresses
 *
 * Provides warnings when connecting to private or reserved IP ranges
 * to help users be aware of potential SSRF risks.
 *
 * Security Feature: SSRF awareness (not blocking, just warning)
 *
 * @module libs/shared/utils/url-validator
 */

export class URLValidator {
  private static readonly PRIVATE_IP_RANGES = [
    /^10\./,                           // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[01])\./,  // 172.16.0.0/12
    /^192\.168\./,                     // 192.168.0.0/16
    /^127\./,                          // 127.0.0.0/8 (loopback)
    /^169\.254\./,                     // 169.254.0.0/16 (link-local)
    /^0\.0\.0\.0$/,                    // 0.0.0.0 (any address)
    /^localhost$/i,                    // localhost
    /^\[::1\]$/,                       // IPv6 loopback
    /^\[fe80:/i,                       // IPv6 link-local
  ];

  /**
   * Check if a URL points to a private or reserved IP address
   *
   * @param url - URL to check (http://localhost:3000, http://192.168.1.1, etc)
   * @returns true if URL points to private/reserved IP
   *
   * @example
   * isPrivateOrLocalhost('http://localhost:3000')      // true
   * isPrivateOrLocalhost('http://192.168.1.1')         // true
   * isPrivateOrLocalhost('http://10.0.0.1:8080')       // true
   * isPrivateOrLocalhost('http://example.com')         // false
   * isPrivateOrLocalhost('https://api.production.com') // false
   */
  static isPrivateOrLocalhost(url: string): boolean {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;

      return this.PRIVATE_IP_RANGES.some((regex) => regex.test(hostname));
    } catch {
      // If URL parsing fails, assume it's not a URL (e.g., STDIO command)
      return false;
    }
  }

  /**
   * Get human-readable description of why an IP is considered private/reserved
   */
  static getPrivateIPReason(url: string): string | null {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;

      if (/^10\./.test(hostname)) {
        return 'Private network (10.0.0.0/8)';
      }
      if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(hostname)) {
        return 'Private network (172.16.0.0/12)';
      }
      if (/^192\.168\./.test(hostname)) {
        return 'Private network (192.168.0.0/16)';
      }
      if (/^127\./.test(hostname)) {
        return 'Loopback address (localhost)';
      }
      if (/^169\.254\./.test(hostname)) {
        return 'Link-local address (169.254.0.0/16)';
      }
      if (/^localhost$/i.test(hostname)) {
        return 'Localhost';
      }
      if (/^\[::1\]$/.test(hostname)) {
        return 'IPv6 loopback';
      }
      if (/^\[fe80:/i.test(hostname)) {
        return 'IPv6 link-local';
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Check if URL is suitable for security warning
   * (HTTP/HTTPS URLs only, not STDIO commands)
   */
  static isURL(target: string): boolean {
    return target.startsWith('http://') || target.startsWith('https://');
  }
}
