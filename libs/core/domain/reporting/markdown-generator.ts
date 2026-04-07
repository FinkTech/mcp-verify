/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import type { Report } from "../mcp-server/entities/validation.types";
import { translations } from "./i18n";
import type { Language } from "./i18n";

export class MarkdownReportGenerator {
  static generate(report: Report, lang: Language = "en"): string {
    const t = translations[lang];
    const serverName = report.server_name || t.unknown_server;
    const protocolVersion = report.protocol_version || t.unknown_version;
    const securityScore = report.security.score;
    const qualityScore = report.quality.score;
    const complianceScore = report.protocolCompliance?.score || 0;
    const now = new Date(report.timestamp).toLocaleString(
      lang === "es" ? "es-ES" : "en-US",
    );

    const securityBadgeColor = this.getBadgeColor(securityScore, "security");
    const qualityBadgeColor = this.getBadgeColor(qualityScore, "quality");
    const complianceBadgeColor = this.getBadgeColor(complianceScore, "quality");

    let markdown = `# 📋 ${t.md_executive_security_report}\n\n`;

    // Badges
    if (securityScore !== undefined && securityBadgeColor) {
      markdown += `![${t.mcp_security_score}](https://img.shields.io/badge/Security-${securityScore}-${securityBadgeColor}?style=flat-square) `;
      markdown += `![${t.quality_score}](https://img.shields.io/badge/Quality-${qualityScore}%25-${qualityBadgeColor}?style=flat-square) `;
    }
    markdown += `![${t.table_status}](https://img.shields.io/badge/Status-${report.status.toUpperCase()}-${report.status === "valid" ? "green" : "red"}?style=flat-square) `;
    markdown += `![${t.md_protocol_compliance}](https://img.shields.io/badge/Compliance-${complianceScore}%25-${complianceBadgeColor}?style=flat-square)\n\n`;

    // Executive Summary
    markdown += `## 📊 ${t.md_executive_summary}\n\n`;
    markdown += `| ${t.md_property} | ${t.md_value} |\n`;
    markdown += `|----------|-------|\n`;
    markdown += `| ${t.md_server_name} | ${this.escapeMarkdown(serverName)} |\n`;
    markdown += `| ${t.md_protocol_version} | ${this.escapeMarkdown(protocolVersion)} |\n`;
    markdown += `| ${t.mcp_security_score} | ${securityScore}/100 |\n`;
    markdown += `| ${t.quality_score} | ${qualityScore}% |\n`;
    markdown += `| ${t.md_report_date} | ${this.escapeMarkdown(now)} |\n\n`;

    // Security Findings
    if (report.security.findings.length > 0) {
      markdown += `## 🔒 ${t.md_security_findings}\n\n`;

      report.security.findings.forEach((finding) => {
        const severityIcon = this.getSeverityIcon(finding.severity);
        markdown += `> ${severityIcon} **${t.md_finding}:** ${this.escapeMarkdown(finding.message)}\n\n`;
        markdown += `| ${t.md_severity} | ${t.md_rule} | ${t.details_header} |\n`;
        markdown += `|----------|------|----------|\n`;

        const ruleLink = finding.ruleCode
          ? `[${this.escapeMarkdown(finding.ruleCode)}](${this.getRulePdfUrl(finding.ruleCode, lang)})`
          : "N/A";

        const severityLabel =
          t[finding.severity as keyof typeof t] || finding.severity;
        markdown += `| ${severityIcon} ${severityLabel} | ${ruleLink} | ${this.escapeMarkdown(finding.component)} |\n\n`;

        if (finding.remediation) {
          markdown += `<details>\n`;
          markdown += `<summary>🔧 ${t.md_remediation}</summary>\n\n`;
          markdown += `\`\`\`bash\n`;
          markdown += `# ${t.suggested_solution}\n`;
          markdown += this.escapeMarkdown(finding.remediation, true);
          markdown += `\n\`\`\`\n\n`;
          markdown += `</details>\n\n`;
        }
        markdown += `---\n\n`;
      });
    } else {
      markdown += `## 🔒 ${t.md_security_findings}\n\n✅ ${t.md_no_critical_findings}\n\n`;
    }

    // Tools / Capabilities
    if (report.tools.items && report.tools.items.length > 0) {
      markdown += `## 🛠️ ${t.md_capabilities_overview}\n\n`;
      report.tools.items.forEach((tool) => {
        markdown += `- **${this.escapeMarkdown(tool.name)}**\n`;
        if (tool.description) {
          markdown += `  - ${t.table_desc}: ${this.escapeMarkdown(tool.description)}\n`;
        }
        markdown += `  - ${t.table_status}: ${tool.status === "valid" ? t.md_valid : t.md_invalid}\n`;
      });
      markdown += `\n`;

      markdown += `### ${t.md_tools}\n\n`;
      markdown += `| ${t.tool_label} | ${t.md_valid} | ${t.table_desc} |\n`;
      markdown += `|------|-------|-------------|\n`;
      report.tools.items.forEach((tool) => {
        const desc = tool.description
          ? tool.description.slice(0, 50) +
            (tool.description.length > 50 ? "..." : "")
          : "N/A";
        markdown += `| ${this.escapeMarkdown(tool.name)} | ${tool.status === "valid" ? t.md_valid : t.md_invalid} | ${this.escapeMarkdown(desc)} |\n`;
      });
      markdown += `\n`;
    }

    // Architecture Diagram
    markdown += `## 📈 ${t.architecture_diagram}\n\n`;
    markdown += `\`\`\`mermaid\n`;
    markdown += `graph LR\n`;
    markdown += `    A["🖥️ ${t.client_label}"] -->|${t.protocol}| B["🌐 ${t.transport_label}"]\n`;
    markdown += `    B -->|${protocolVersion}| C["🔐 ${t.server}: ${serverName}"]\n`;
    markdown += `    C -->|${report.tools.count} ${t.tools}| D["⚙️ ${t.functionality_label}"]\n`;
    markdown += `    C -->|${securityScore}% ${t.mcp_security_score}| E["🛡️ ${t.safety_layer_label}"]\n`;
    markdown += `\`\`\`\n\n`;

    // Compliance Status
    markdown += `## ✅ ${t.md_protocol_compliance}\n\n`;
    const complianceBar = this.generateProgressBar(complianceScore);
    markdown += `**${t.md_protocol_compliance}:** \`${complianceBar}\`\n\n`;

    // Si tuviéramos detalles de compliance específicos, los listaríamos aquí.
    // Por ahora usamos el protocolCompliance report si existe.
    if (
      report.protocolCompliance &&
      report.protocolCompliance.issues.length === 0
    ) {
      markdown += `| Standard | Status |\n`;
      markdown += `|----------|--------|\n`;
      markdown += `| ${t.protocol_spec} | ✅ ${t.md_passed} |\n`;
      markdown += `| ${t.schema_valid} | ✅ ${t.md_passed} |\n\n`;
    } else if (report.protocolCompliance) {
      markdown += `> ⚠️ **${t.protocol_issues_detected}**\n\n`;
      markdown += `| Code | Message | ${t.md_severity} |\n`;
      markdown += `|------|---------|----------|\n`;
      report.protocolCompliance.issues.slice(0, 5).forEach((issue) => {
        markdown += `| ${issue.code} | ${this.escapeMarkdown(issue.message)} | ${issue.severity} |\n`;
      });
      markdown += `\n`;
    }

    // Disclaimer Section
    if (report.disclaimer) {
      markdown += `## ⚠️ ${t.disclaimer_title || "Important Disclaimer"}\n\n`;
      markdown += `${report.disclaimer.text}\n\n`;

      markdown += `### ${t.disclaimer_scope_title || "What this tool analyzes:"}\n\n`;
      report.disclaimer.scope.forEach((item) => {
        markdown += `- ${item}\n`;
      });
      markdown += `\n`;

      markdown += `### ${t.disclaimer_limitations_title || "What this tool does NOT analyze:"}\n\n`;
      report.disclaimer.limitations.forEach((item) => {
        markdown += `- ${item}\n`;
      });
      markdown += `\n`;

      if (report.disclaimer.llmNotice) {
        markdown += `> 🤖 ${report.disclaimer.llmNotice}\n\n`;
      }

      markdown += `*${t.disclaimer_professional_audit || "For production deployments, a professional security audit is recommended."}*\n\n`;
    }

    markdown += `---\n\n`;
    markdown += `**${t.md_report_generated_by}:** [mcp-verify](https://github.com/FinkTech/mcp-verify) CLI\n`;
    markdown += `**${t.security_standards}:** [mcp-security](https://github.com/FinkTech/mcp-security)\n`;
    markdown += `**${t.md_report_date}:** ${this.escapeMarkdown(now)}\n`;
    markdown += `**${t.md_tools} ${t.md_total}:** ${report.tools.count}\n`;
    markdown += `**${t.md_security_findings}:** ${report.security.findings.length}\n`;

    return markdown;
  }

  private static getRulePdfUrl(
    ruleCode: string,
    lang: Language = "en",
  ): string {
    const baseUrl = `https://github.com/FinkTech/mcp-security/blob/main/docs/pdf/${lang}/`;
    const map: Record<string, string> = {
      "SEC-001": "SEC-001-Authentication.pdf",
      "SEC-002": "SEC-002-CommandInject.pdf",
      "SEC-003": "SEC-003-SQLInjection.pdf",
      "SEC-004": "SEC-004-SSRF.pdf",
      "SEC-005": "SEC-005-XXE.pdf",
      "SEC-006": "SEC-006-Deserializat.pdf",
      "SEC-007": "SEC-007-PathTraversal.pdf",
      "SEC-008": "SEC-008-DataLeakage.pdf",
      "SEC-009": "SEC-009-SensDataExp.pdf",
      "SEC-010": "SEC-010-RateLimiting.pdf",
      "SEC-011": "SEC-011-ReDoS.pdf",
      "SEC-012": "SEC-012-WeakCrypto.pdf",
    };
    return baseUrl + (map[ruleCode] || "README.md");
  }

  private static escapeMarkdown(text: string, insideCodeBlock = false): string {
    if (!text) return "";
    if (insideCodeBlock) return text;

    return text
      .replace(/\\/g, "\\\\")
      .replace(/\*/g, "\\*")
      .replace(/_/g, "\\_")
      .replace(/\[/g, "\\[")
      .replace(/\]/g, "\\]")
      .replace(/\(/g, "\\(")
      .replace(/\)/g, "\\)")
      .replace(/#/g, "\\#")
      .replace(/\+/g, "\\+")
      .replace(/\-/g, "\\-") // dash
      .replace(/\./g, "\\.")
      .replace(/!/g, "\\!");
  }

  private static generateProgressBar(percentage: number): string {
    const total = 20;
    const filled = Math.round((percentage / 100) * total);
    const empty = total - filled;
    // Evitar negativos si filled > total por alguna razón extraña
    const safeFilled = Math.max(0, Math.min(total, filled));
    const safeEmpty = Math.max(0, total - safeFilled);

    return "█".repeat(safeFilled) + "░".repeat(safeEmpty) + ` ${percentage}%`;
  }

  private static getSeverityIcon(severity: string): string {
    const icons: { [key: string]: string } = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🟢",
      info: "ℹ️",
    };
    return icons[severity.toLowerCase()] || "⚪";
  }

  private static getBadgeColor(
    score: number | string,
    type: "security" | "quality",
  ): string {
    if (type === "security") {
      // Assuming score is numeric 0-100 for report consistency usually
      const num = typeof score === "string" ? parseInt(score) : score;
      if (num >= 90) return "green";
      if (num >= 75) return "yellowgreen";
      if (num >= 60) return "yellow";
      return "red";
    }
    const num = typeof score === "string" ? parseInt(score) : score;
    if (num >= 90) return "green";
    if (num >= 75) return "yellowgreen";
    if (num >= 60) return "yellow";
    return "red";
  }
}
