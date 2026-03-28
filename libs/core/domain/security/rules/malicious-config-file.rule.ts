/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-053: Malicious MCP Config File (Pre-Execution Scanner)
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Inspired by: CVE-2025-59536 (Check Point Research)
 * Severity: Critical
 * Type: Static (Pre-Execution)
 *
 * Detects malicious `.mcp.json` files with shell injection commands that execute
 * automatically when opening a project, bypassing user consent dialogs.
 *
 * This is the EXACT vector of CVE-2025-59536: cloning a repo with malicious
 * .mcp.json executed commands without confirmation.
 *
 * Detection Patterns (Unix/Linux):
 * - Shell dangerous patterns: `curl | bash`, `wget | sh`, reverse shells
 * - Command chaining: `;`, `&&`, `||`, `$(...)`, backticks
 * - Obfuscation: base64 decode + exec, hex encoding
 * - Remote payload downloads via curl/wget
 *
 * Detection Patterns (Windows):
 * - PowerShell: `IWR | IEX`, Invoke-Expression, reverse shells
 * - Certutil abuse: binary download/decode via certutil
 * - Bitsadmin abuse: file download via bitsadmin
 * - Registry manipulation, scheduled tasks, destructive commands
 *
 * Severity Escalation:
 * - If .mcp.json is in a Git repo (.git/config present) → Critical (supply chain)
 * - Otherwise → High
 *
 * References:
 * - CVE-2025-59536 - Malicious .mcp.json execution without consent
 * - Check Point Research - MCP Security Analysis (Feb 2026)
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import { t } from '@mcp-verify/shared';
import * as fs from 'fs';
import * as path from 'path';

/**
 * MCP Config structure (simplified)
 */
export interface McpConfigFile {
  mcpServers?: Record<string, McpServerConfig>;
  [key: string]: unknown;
}

export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  [key: string]: unknown;
}

/**
 * Dangerous shell patterns that indicate malicious intent
 */
const DANGEROUS_PATTERNS = [
  // Pipe to shell execution
  { pattern: /curl\s+[^\s]+\s*\|\s*(bash|sh|zsh|fish)/i, description: 'curl piped to shell' },
  { pattern: /wget\s+[^\s]+\s*\|\s*(bash|sh|zsh|fish)/i, description: 'wget piped to shell' },
  { pattern: /fetch\s+[^\s]+\s*\|\s*(bash|sh|zsh|fish)/i, description: 'fetch piped to shell' },

  // Reverse shells
  { pattern: /bash\s+-i\s+>&\s+\/dev\/tcp\//i, description: 'bash reverse shell' },
  { pattern: /nc\s+-e\s+\/bin\/(ba)?sh/i, description: 'netcat reverse shell' },
  { pattern: /\/bin\/(ba)?sh\s+-i\s*>/i, description: 'interactive shell redirection' },
  { pattern: /mkfifo.*nc.*sh/i, description: 'named pipe reverse shell' },

  // Remote payload execution
  { pattern: /curl.*https?:\/\/.*\.(sh|bash|py|pl|rb)/i, description: 'remote script download' },
  { pattern: /wget.*https?:\/\/.*\.(sh|bash|py|pl|rb)/i, description: 'remote script download' },

  // Command chaining (suspicious in MCP context)
  { pattern: /;\s*(curl|wget|nc|bash|sh|rm|dd)/i, description: 'command chaining with dangerous command' },
  { pattern: /&&\s*(curl|wget|nc|bash|sh|rm|dd)/i, description: 'AND chaining with dangerous command' },
  { pattern: /\|\|\s*(curl|wget|nc|bash|sh|rm|dd)/i, description: 'OR chaining with dangerous command' },

  // Command substitution
  { pattern: /\$\(.*(?:curl|wget|nc|bash|sh|eval)\)/i, description: 'command substitution with dangerous command' },
  { pattern: /`.*(?:curl|wget|nc|bash|sh|eval)`/i, description: 'backtick command substitution' },

  // Obfuscation
  { pattern: /base64\s+-d.*\|\s*(bash|sh|eval)/i, description: 'base64 decode piped to execution' },
  { pattern: /echo.*\|\s*base64\s+-d.*\|\s*(bash|sh)/i, description: 'base64 encoded command execution' },
  { pattern: /xxd.*\|\s*(bash|sh|eval)/i, description: 'hex decode to execution' },

  // Data exfiltration
  { pattern: /curl.*-d.*@/i, description: 'curl POST with file upload' },
  { pattern: /wget.*--post-file/i, description: 'wget file upload' },

  // Destructive commands (when used in init scripts)
  { pattern: /rm\s+-rf\s+\//, description: 'recursive forced delete from root' },
  { pattern: /dd\s+if=.*of=\/dev\//, description: 'disk write operation' },
  { pattern: /mkfs/i, description: 'filesystem formatting' },
  { pattern: /:\(\)\{.*:\|:&\};:/i, description: 'fork bomb' },

  // ===== WINDOWS PATTERNS =====

  // PowerShell remote execution
  { pattern: /Invoke-WebRequest.*\|\s*Invoke-Expression/i, description: 'PowerShell IWR piped to IEX' },
  { pattern: /iwr\s+.*\|\s*iex/i, description: 'PowerShell iwr piped to iex (alias)' },
  { pattern: /Invoke-Expression.*\(.*Invoke-WebRequest/i, description: 'PowerShell nested IEX with IWR' },
  { pattern: /wget.*\|\s*iex/i, description: 'PowerShell wget alias piped to iex' },
  { pattern: /curl.*\|\s*iex/i, description: 'PowerShell curl alias piped to iex' },

  // Certutil abuse (binary download/decode)
  { pattern: /certutil.*-urlcache.*http/i, description: 'certutil binary download abuse' },
  { pattern: /certutil.*-decode/i, description: 'certutil decode abuse' },

  // Bitsadmin abuse (binary download)
  { pattern: /bitsadmin.*\/transfer/i, description: 'bitsadmin binary download' },
  { pattern: /bitsadmin.*\/download/i, description: 'bitsadmin file download' },

  // PowerShell reverse shells
  { pattern: /\$client\s*=\s*New-Object.*Net\.Sockets\.TcpClient/i, description: 'PowerShell TCP reverse shell' },
  { pattern: /New-Object.*System\.Net\.Sockets\.TcpClient/i, description: 'PowerShell socket-based reverse shell' },
  { pattern: /\$stream\s*=\s*\$client\.GetStream/i, description: 'PowerShell stream-based reverse shell' },

  // PowerShell obfuscation
  { pattern: /FromBase64String/i, description: 'PowerShell base64 decode' },
  { pattern: /-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}/i, description: 'PowerShell encoded command execution' },
  { pattern: /\[System\.Text\.Encoding\]::UTF8\.GetString/i, description: 'PowerShell string decoding' },

  // Windows destructive commands
  { pattern: /Remove-Item.*-Recurse.*-Force/i, description: 'PowerShell recursive forced delete' },
  { pattern: /rd\s+\/s\s+\/q\s+C:\\/i, description: 'CMD recursive directory delete' },
  { pattern: /del\s+\/f\s+\/s\s+\/q/i, description: 'CMD forced file deletion' },
  { pattern: /format\s+[A-Z]:/i, description: 'Windows drive formatting' },

  // Windows registry manipulation
  { pattern: /reg\s+add.*\/f/i, description: 'forced registry key addition' },
  { pattern: /Set-ItemProperty.*HKLM/i, description: 'PowerShell HKLM registry write' },

  // Windows scheduled tasks (persistence)
  { pattern: /schtasks.*\/create/i, description: 'Windows scheduled task creation' },
  { pattern: /Register-ScheduledTask/i, description: 'PowerShell scheduled task registration' }
];

export class MaliciousConfigFileRule implements ISecurityRule {
  code = 'SEC-053';
  name = 'Malicious MCP Config File';
  severity: 'critical' = 'critical';

  /**
   * Special evaluation for config files (not MCP server discovery)
   * Call this directly from scan-config command
   */
  evaluateConfigFile(configPath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // 1. Check if file exists
    if (!fs.existsSync(configPath)) {
      return [{
        severity: 'info' as const,
        message: `Config file not found: ${configPath}`,
        component: 'config',
        ruleCode: this.code
      }];
    }

    // 2. Read and parse config
    let config: McpConfigFile;
    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      config = JSON.parse(content);
    } catch (error) {
      return [{
        severity: 'medium' as const,
        message: `Failed to parse config file: ${error instanceof Error ? error.message : String(error)}`,
        component: 'config',
        ruleCode: this.code
      }];
    }

    // 3. Check each MCP server configuration
    if (config.mcpServers) {
      for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
        const serverFindings = this.analyzeServerConfig(serverName, serverConfig, configPath);
        findings.push(...serverFindings);
      }
    }

    // 4. Check if in Git repo (supply chain escalation)
    const isInGitRepo = this.isInGitRepository(configPath);
    if (isInGitRepo && findings.some(f => f.severity === 'critical')) {
      // Add supply chain warning
      findings.push({
        severity: 'critical',
        message: t('sec_053_supply_chain_warning'),
        component: 'config',
        ruleCode: this.code,
        remediation: t('sec_053_supply_chain_recommendation')
      });
    }

    return findings;
  }

  /**
   * Not applicable for this rule (use evaluateConfigFile instead)
   */
  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    return [];
  }

  /**
   * Analyze individual MCP server configuration
   */
  private analyzeServerConfig(
    serverName: string,
    serverConfig: McpServerConfig,
    configPath: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check command + args
    const fullCommand = this.reconstructCommand(serverConfig);

    if (!fullCommand) {
      return findings; // No command to analyze
    }

    // Check against dangerous patterns
    for (const { pattern, description } of DANGEROUS_PATTERNS) {
      if (pattern.test(fullCommand)) {
        findings.push({
          severity: this.severity,
          message: t('sec_053_malicious_pattern', {
            serverName,
            pattern: description,
            command: this.truncateCommand(fullCommand)
          }),
          component: `config:${serverName}`,
          ruleCode: this.code,
          remediation: t('sec_053_recommendation'),
          references: [
            'CVE-2025-59536 - Malicious .mcp.json auto-execution',
            'Check Point Research - MCP Security (Feb 2026)',
            'CWE-78: OS Command Injection'
          ]
        });
      }
    }

    // Check environment variables for endpoint hijacking (related to SEC-054)
    if (serverConfig.env) {
      const suspiciousEnvVars = this.detectSuspiciousEnvVars(serverConfig.env);
      for (const envVar of suspiciousEnvVars) {
        findings.push({
          severity: 'critical',
          message: t('sec_053_env_hijacking', {
            serverName,
            envVar: envVar.name,
            value: envVar.value
          }),
          component: `config:${serverName}`,
          ruleCode: 'SEC-054', // Related to API endpoint hijacking
          remediation: t('sec_054_recommendation')
        });
      }
    }

    return findings;
  }

  /**
   * Reconstruct full command from config
   */
  private reconstructCommand(config: McpServerConfig): string {
    if (!config.command) {
      return '';
    }

    const parts = [config.command];

    if (config.args && Array.isArray(config.args)) {
      parts.push(...config.args);
    }

    return parts.join(' ');
  }

  /**
   * Truncate command for display
   */
  private truncateCommand(cmd: string, maxLength: number = 100): string {
    if (cmd.length <= maxLength) {
      return cmd;
    }
    return cmd.substring(0, maxLength) + '...';
  }

  /**
   * Detect suspicious environment variable overrides
   */
  private detectSuspiciousEnvVars(env: Record<string, string>): Array<{ name: string; value: string }> {
    const suspicious: Array<{ name: string; value: string }> = [];

    const LEGITIMATE_ENDPOINTS = [
      'api.anthropic.com',
      'api.openai.com',
      'generativelanguage.googleapis.com',
      'localhost',
      '127.0.0.1'
    ];

    const API_ENDPOINT_VARS = [
      'ANTHROPIC_BASE_URL',
      'OPENAI_BASE_URL',
      'API_BASE_URL',
      'BASE_URL'
    ];

    for (const [key, value] of Object.entries(env)) {
      if (API_ENDPOINT_VARS.some(v => key.toUpperCase().includes(v.toUpperCase()))) {
        // Check if value points to non-legitimate endpoint
        const isLegitimate = LEGITIMATE_ENDPOINTS.some(endpoint =>
          value.toLowerCase().includes(endpoint.toLowerCase())
        );

        if (!isLegitimate) {
          suspicious.push({ name: key, value });
        }
      }
    }

    return suspicious;
  }

  /**
   * Check if config file is in a Git repository
   */
  private isInGitRepository(configPath: string): boolean {
    let dir = path.dirname(configPath);

    // Traverse up to 10 levels
    for (let i = 0; i < 10; i++) {
      const gitDir = path.join(dir, '.git');
      if (fs.existsSync(gitDir)) {
        return true;
      }

      const parent = path.dirname(dir);
      if (parent === dir) {
        break; // Reached root
      }
      dir = parent;
    }

    return false;
  }
}
