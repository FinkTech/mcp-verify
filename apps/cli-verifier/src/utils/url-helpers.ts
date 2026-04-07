/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * URL Helpers
 *
 * Utilities for URL detection, validation, and parsing
 */

/**
 * Check if string is an HTTP/HTTPS URL
 * @param str String to check
 * @returns true if valid HTTP/HTTPS URL
 */
export function isHttpUrl(str: string): boolean {
  return str.startsWith("http://") || str.startsWith("https://");
}

/**
 * Check if string is a valid URL
 * @param str String to check
 * @returns true if valid URL
 */
export function isValidUrl(str: string): boolean {
  try {
    new URL(str);
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract hostname from URL
 * @param url URL string
 * @returns hostname or null if invalid
 */
export function getHostname(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Extract port from URL
 * @param url URL string
 * @returns port number or null if not specified/invalid
 */
export function getPort(url: string): number | null {
  try {
    const parsed = new URL(url);
    return parsed.port ? parseInt(parsed.port, 10) : null;
  } catch {
    return null;
  }
}

/**
 * Normalize URL (add protocol if missing)
 * @param url URL string
 * @returns normalized URL with protocol
 */
export function normalizeUrl(url: string): string {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return `http://${url}`;
  }
  return url;
}

/**
 * Check if URL points to localhost
 * @param url URL string
 * @returns true if localhost
 */
export function isLocalhost(url: string): boolean {
  const hostname = getHostname(url);
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "0.0.0.0"
  );
}

/**
 * Build URL with query parameters
 * @param base Base URL
 * @param params Query parameters
 * @returns Complete URL with query string
 */
export function buildUrlWithParams(
  base: string,
  params: Record<string, string>,
): string {
  const url = new URL(base);
  Object.entries(params).forEach(([key, value]) => {
    url.searchParams.append(key, value);
  });
  return url.toString();
}
