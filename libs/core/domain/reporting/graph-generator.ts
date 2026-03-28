/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { DiscoveryResult } from '../mcp-server/entities/validation.types';

export type MermaidTheme = 'dark' | 'light';

export class GraphGenerator {
  static generateMermaid(discovery: DiscoveryResult, theme: MermaidTheme = 'dark'): string {
    const lines = ['graph TD'];
    lines.push('    Server[MCP Server]:::server');

    // Tools Subgraph
    if (discovery.tools && discovery.tools.length > 0) {
      lines.push('    subgraph Tools');
      discovery.tools.forEach((tool, i) => {
        const id = `T${i}`;
        const safeName = (tool.name || 'unknown').replace(/[^a-zA-Z0-9]/g, '_');
        lines.push(`        ${id}(["🛠️ ${safeName}"]):::tool`);
        lines.push(`        Server --> ${id}`);
      });
      lines.push('    end');
    }

    // Resources Subgraph
    if (discovery.resources && discovery.resources.length > 0) {
      lines.push('    subgraph Resources');
      discovery.resources.forEach((resource, i) => {
        const id = `R${i}`;
        const safeName = (resource.name || 'unknown').replace(/[^a-zA-Z0-9]/g, '_');
        lines.push(`        ${id}[("📄 ${safeName}")]:::resource`);
        lines.push(`        Server -.-> ${id}`);
      });
      lines.push('    end');
    }

    // Prompts Subgraph
    if (discovery.prompts && discovery.prompts.length > 0) {
      lines.push('    subgraph Prompts');
      discovery.prompts.forEach((prompt, i) => {
        const id = `P${i}`;
        const safeName = (prompt.name || 'unknown').replace(/[^a-zA-Z0-9]/g, '_');
        lines.push(`        ${id}{{"💬 ${safeName}"}}:::prompt`);
        lines.push(`        Server ==> ${id}`);
      });
      lines.push('    end');
    }

    // Styles - theme-aware colors
    if (theme === 'light') {
      lines.push('    classDef server fill:#f1f5f9,stroke:#3b82f6,stroke-width:2px,color:#1e293b');
      lines.push('    classDef tool fill:#e2e8f0,stroke:#22c55e,stroke-width:1px,color:#1e293b');
      lines.push('    classDef resource fill:#e2e8f0,stroke:#eab308,stroke-width:1px,color:#1e293b');
      lines.push('    classDef prompt fill:#e2e8f0,stroke:#a855f7,stroke-width:1px,color:#1e293b');
    } else {
      lines.push('    classDef server fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#fff');
      lines.push('    classDef tool fill:#1e293b,stroke:#22c55e,stroke-width:1px,color:#fff');
      lines.push('    classDef resource fill:#1e293b,stroke:#eab308,stroke-width:1px,color:#fff');
      lines.push('    classDef prompt fill:#1e293b,stroke:#a855f7,stroke-width:1px,color:#fff');
    }

    return lines.join('\n');
  }
}
