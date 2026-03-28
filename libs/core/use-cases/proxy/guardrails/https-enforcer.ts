/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * HTTPS Enforcer Guardrail
 *
 * Enforces HTTPS-only communication by blocking insecure HTTP URLs
 * in requests to prevent man-in-the-middle attacks and data leakage.
 *
 * Features:
 * - Detects HTTP URLs in request parameters
 * - Optional auto-upgrade HTTP to HTTPS
 * - Whitelist support for localhost/testing
 * - Configurable strictness levels
 *
 * @module libs/core/use-cases/proxy/guardrails/https-enforcer
 */

import { t } from '@mcp-verify/shared';
import type { IGuardrail, InterceptResult } from '../proxy.types';
import type { JsonValue } from '../../../domain/shared/common.types';

export class HttpsEnforcer implements IGuardrail {
  name = t('guardrail_https_enforcement');

  /**
   * Configuration
   */
  private config = {
    enabled: true,
    autoUpgrade: false,        // Auto-convert http:// to https://
    allowLocalhost: true,      // Allow http://localhost and http://127.0.0.1
    allowedHttpHosts: [] as string[], // Additional whitelisted hosts
    blockMixedContent: true,   // Block if both HTTP and HTTPS URLs present
    logViolations: true
  };

  /**
   * Regex patterns for detecting URLs
   */
  private patterns = {
    httpUrl: /https?:\/\/[^\s"'<>]+/gi,
    insecureHttp: /http:\/\/[^\s"'<>]+/gi,
    localhost: /http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(:\d+)?/gi
  };

  inspectRequest(message: JsonValue): InterceptResult {
    if (!this.config.enabled) {
      return { action: 'allow' };
    }

    const result = this.analyzeMessage(message);

    // Check for mixed content
    if (this.config.blockMixedContent && result.hasMixedContent) {
      return {
        action: 'block',
        reason: t('guardrail_mixed_content')
      };
    }

    if (result.hasInsecureUrls) {
      // If auto-upgrade is enabled, upgrade HTTP to HTTPS
      if (this.config.autoUpgrade) {
        return {
          action: 'modify',
          modifiedMessage: result.upgradedMessage,
          reason: t('guardrail_auto_upgrade', { count: result.insecureUrls.length })
        };
      }

      // Otherwise, block the request
      return {
        action: 'block',
        reason: t('guardrail_insecure_detected', { urls: result.insecureUrls.join(', ') })
      };
    }

    return { action: 'allow' };
  }

  inspectResponse(message: JsonValue): InterceptResult {
    // We could also check responses for leaked HTTP URLs
    return { action: 'allow' };
  }

  /**
   * Analyze message for HTTP URLs
   */
  private analyzeMessage(message: JsonValue): {
    hasInsecureUrls: boolean;
    insecureUrls: string[];
    hasMixedContent: boolean;
    upgradedMessage: JsonValue;
  } {
    const messageStr = JSON.stringify(message);
    const allUrls = messageStr.match(this.patterns.httpUrl) || [];
    const insecureUrls: string[] = [];
    const secureUrls: string[] = [];

    // Classify URLs
    for (const url of allUrls) {
      if (url.startsWith('https://')) {
        secureUrls.push(url);
      } else if (url.startsWith('http://')) {
        // Check if it's whitelisted
        if (!this.isWhitelisted(url)) {
          insecureUrls.push(url);
        }
      }
    }

    // Prepare upgraded message
    let upgradedStr = messageStr;
    if (this.config.autoUpgrade && insecureUrls.length > 0) {
      for (const insecureUrl of insecureUrls) {
        const secureUrl = insecureUrl.replace('http://', 'https://');
        upgradedStr = upgradedStr.replace(insecureUrl, secureUrl);
      }
    }

    const upgradedMessage = upgradedStr !== messageStr
      ? JSON.parse(upgradedStr)
      : message;

    return {
      hasInsecureUrls: insecureUrls.length > 0,
      insecureUrls,
      hasMixedContent: secureUrls.length > 0 && insecureUrls.length > 0,
      upgradedMessage
    };
  }

  /**
   * Check if a URL is whitelisted
   */
  private isWhitelisted(url: string): boolean {
    // Check localhost
    if (this.config.allowLocalhost && this.patterns.localhost.test(url)) {
      this.patterns.localhost.lastIndex = 0; // Reset regex
      return true;
    }

    // Check custom whitelist
    try {
      const hostname = new URL(url).hostname;
      for (const allowedHost of this.config.allowedHttpHosts) {
        if (hostname === allowedHost || hostname.endsWith('.' + allowedHost)) {
          return true;
        }
      }
    } catch (e) {
      // Invalid URL syntax, fallback to simpler check (unsafe but unlikely to match)
      return false;
    }

    return false;
  }

  /**
   * Configure the enforcer
   */
  configure(options: Partial<typeof this.config>) {
    Object.assign(this.config, options);
  }

  /**
   * Add a host to the HTTP whitelist
   */
  allowHttpHost(host: string) {
    if (!this.config.allowedHttpHosts.includes(host)) {
      this.config.allowedHttpHosts.push(host);
    }
  }

  /**
   * Remove a host from the HTTP whitelist
   */
  disallowHttpHost(host: string) {
    this.config.allowedHttpHosts = this.config.allowedHttpHosts.filter(h => h !== host);
  }

  /**
   * Get current configuration
   */
  getConfig() {
    return { ...this.config };
  }
}
