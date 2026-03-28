/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-057: Data Exfiltration via Steganography
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Severity: High
 * Type: Static + Behavioral
 *
 * Detects tools that embed data in images, audio, or other media
 * for covert exfiltration. Common in APT and insider threats.
 *
 * Detection:
 * Static:
 * - Tools with "encode", "embed", "hide" + media keywords
 * - Steganography libraries or algorithms mentioned
 * - Tools accepting both data and image/audio inputs
 *
 * Behavioral:
 * - Monitor for unusual image/audio generation patterns
 * - Detect high-entropy regions in media files
 *
 * References:
 * - NIST Data Loss Prevention (DLP)
 * - Steganography Detection Methods
 * - CWE-311: Missing Encryption of Sensitive Data
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class DataExfiltrationSteganographyRule implements ISecurityRule {
  code = 'SEC-057';
  name = 'Data Exfiltration via Steganography';
  severity: 'high' = 'high';

  private readonly STEGANOGRAPHY_KEYWORDS = [
    'steganography', 'stego', 'lsb', 'least significant bit',
    'embed.*data', 'hide.*data', 'conceal.*data',
    'covert.*channel', 'hidden.*message', 'watermark'
  ];

  private readonly MEDIA_KEYWORDS = [
    'image', 'audio', 'video', 'media', 'picture',
    'photo', 'sound', 'png', 'jpg', 'jpeg', 'wav', 'mp3'
  ];

  private readonly ENCODING_PATTERNS = [
    /encode.*in.*image/i, /hide.*in.*audio/i, /embed.*in.*media/i,
    /conceal.*in.*file/i, /steg.*encode/i, /lsb.*encode/i
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isSteganographyTool = this.isSteganographyCapable(tool);

      if (isSteganographyTool) {
        findings.push({
          severity: this.severity,
          message: t('sec_057_steganography', {
            toolName: tool.name
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t('sec_057_recommendation'),
          references: [
            'NIST Data Loss Prevention (DLP)',
            'Steganography Detection in Digital Forensics',
            'CWE-311: Missing Encryption of Sensitive Data'
          ]
        });
      }
    }

    return findings;
  }

  private isSteganographyCapable(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.ENCODING_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check for steganography keywords in name
    const nameLower = tool.name.toLowerCase();
    const nameHasStegoKeyword = this.STEGANOGRAPHY_KEYWORDS.some(keyword => {
      const pattern = typeof keyword === 'string'
        ? new RegExp(keyword.replace(/\.\*/g, '.*'), 'i')
        : keyword;
      return pattern.test(nameLower);
    });
    if (nameHasStegoKeyword) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();

      const descMatches = this.ENCODING_PATTERNS.some(pattern =>
        pattern.test(descLower)
      );
      if (descMatches) return true;

      const descHasStegoKeyword = this.STEGANOGRAPHY_KEYWORDS.some(keyword => {
        const pattern = typeof keyword === 'string'
          ? new RegExp(keyword.replace(/\.\*/g, '.*'), 'i')
          : keyword;
        return pattern.test(descLower);
      });
      if (descHasStegoKeyword) return true;
    }

    // Check if tool accepts both data and media inputs
    if (tool.inputSchema?.properties) {
      let hasDataParam = false;
      let hasMediaParam = false;

      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();

        if (propLower.includes('data') || propLower.includes('payload') || propLower.includes('message')) {
          hasDataParam = true;
        }

        const isMediaParam = this.MEDIA_KEYWORDS.some(media =>
          propLower.includes(media)
        );
        if (isMediaParam) {
          hasMediaParam = true;
        }
      }

      // If tool accepts both data and media, and involves encoding, it's suspicious
      if (hasDataParam && hasMediaParam) {
        const nameLower = tool.name.toLowerCase();
        const descLower = tool.description?.toLowerCase() || '';

        const involvesEncoding = nameLower.includes('encode') || nameLower.includes('embed') || nameLower.includes('hide') ||
          descLower.includes('encode') || descLower.includes('embed') || descLower.includes('hide');

        if (involvesEncoding) return true;
      }
    }

    return false;
  }
}
