/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { t } from '@mcp-verify/shared';
import type { Report } from '../mcp-server/entities/validation.types';

export class BadgeGenerator {
  static generate(report: Report): { markdown: string; html: string; url: string } {
    const score = report.security.score;
    let color = 'red';
    if (score >= 90) color = 'brightgreen';
    else if (score >= 70) color = 'yellow';
    
    // Using shields.io
    // Format: https://img.shields.io/badge/MCP_Security-{SCORE}%-{COLOR}
    const safeScore = Math.round(score);
    const url = `https://img.shields.io/badge/MCP_Security-${safeScore}%25-${color}`;
    
    return {
      url,
      markdown: `![${t('mcp_security_score')}](${url})`,
      html: `<img src="${url}" alt="${t('mcp_security_score')}" />`
    };
  }
}
