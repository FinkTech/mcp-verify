/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Command Injection Detection Rule Tests (SEC-002)
 * 
 * Comprehensive tests for Command Injection vulnerability detection.
 * Tests cover EXECUTION_KEYWORDS, SHELL_CHARACTERS, and edge cases.
 */

import { CommandInjectionRule } from './command-injection.rule';
import { DiscoveryResult } from '../../mcp-server/entities/validation.types';

describe('CommandInjectionRule', () => {
  let rule: CommandInjectionRule;

  beforeEach(() => {
    rule = new CommandInjectionRule();
  });

  describe('Rule Metadata', () => {
    it('should have correct code SEC-002', () => {
      expect(rule.code).toBe('SEC-002');
    });

    it('should have valid tags for CWE and OWASP mapping', () => {
      expect(rule.tags).toContain('CWE-78');
      expect(rule.tags).toContain('OWASP-A03:2021');
      expect(rule.tags).toContain('OS Command Injection');
    });

    it('should have a helpUri pointing to OWASP resource', () => {
      expect(rule.helpUri).toContain('owasp.org');
      expect(rule.helpUri).toContain('Command_Injection');
    });
  });

  describe('Execution Keyword Detection', () => {
    it('should detect tools with "exec" in name (Critical)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'exec_command',
            description: 'Executes a command',
            inputSchema: {
              type: 'object',
              properties: {
                cmd: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('critical');
    });

    it('should detect tools with "run" in name', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_script',
            inputSchema: {
              type: 'object',
              properties: {
                script: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect tools with "system" in description', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'do_operation',
            description: 'Runs system commands on the server',
            inputSchema: {
              type: 'object',
              properties: {
                operation: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect tools with "spawn" keyword', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'spawn_process',
            inputSchema: {
              type: 'object',
              properties: {
                args: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect tools with "shell" keyword', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'shell_exec',
            inputSchema: {
              type: 'object',
              properties: {
                command: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect tools with "bash" keyword', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'bash_script',
            description: 'Runs a bash script',
            inputSchema: {
              type: 'object',
              properties: {
                code: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect tools with "powershell" keyword', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'invoke_powershell',
            inputSchema: {
              type: 'object',
              properties: {
                script: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Parameter Validation Detection', () => {
    it('should detect unvalidated parameters lacking pattern (Critical)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'execute_script',
            description: 'Runs a bash script',
            inputSchema: {
              type: 'object',
              properties: {
                code: { type: 'string' } // No pattern
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].message).toContain('lacks validation pattern');
    });

    it('should detect weak patterns allowing shell metacharacters (Critical)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_cmd',
            inputSchema: {
              type: 'object',
              properties: {
                arg: {
                  type: 'string',
                  pattern: '.*' // Allows everything
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].evidence).toBeDefined();
      expect(findings[0].evidence!.allowedShellChars).toBeDefined();
      expect(Array.isArray(findings[0].evidence!.allowedShellChars)).toBe(true);
    });

    it('should detect patterns allowing semicolon (;)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'exec_tool',
            inputSchema: {
              type: 'object',
              properties: {
                input: {
                  type: 'string',
                  pattern: '^[a-z;]+$' // Allows semicolon
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      const finding = findings.find(f =>
        (f.evidence?.allowedShellChars as string[] | undefined)?.includes(';')
      );
      expect(finding).toBeDefined();
    });

    it('should detect patterns allowing pipe (|)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_operation',
            inputSchema: {
              type: 'object',
              properties: {
                cmd: {
                  type: 'string',
                  pattern: '^[a-z|]+$' // Allows pipe
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect patterns allowing ampersand (&)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'system_call',
            inputSchema: {
              type: 'object',
              properties: {
                arg: {
                  type: 'string',
                  pattern: '^[a-z&]+$' // Allows ampersand
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect patterns allowing backtick (`)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'execute',
            inputSchema: {
              type: 'object',
              properties: {
                command: {
                  type: 'string',
                  pattern: '^.+$' // Matches backtick
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect patterns allowing dollar sign ($)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'shell_command',
            inputSchema: {
              type: 'object',
              properties: {
                input: {
                  type: 'string',
                  pattern: '.*' // Allows $
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      const finding = findings.find(f =>
        (f.evidence?.allowedShellChars as string[] | undefined)?.includes('$')
      );
      expect(finding).toBeDefined();
    });

    it('should provide proper remediation advice', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_script',
            inputSchema: {
              type: 'object',
              properties: {
                script: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings[0].remediation).toContain('whitelist');
      expect(findings[0].remediation).toContain('metacharacter');
    });
  });

  describe('Argument Parameter Detection', () => {
    it('should detect "arg" parameter without validation', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'process_data',
            inputSchema: {
              type: 'object',
              properties: {
                arg: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect "args" parameter without validation', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'utility_tool',
            inputSchema: {
              type: 'object',
              properties: {
                args: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect "command" parameter without validation', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'dispatcher',
            inputSchema: {
              type: 'object',
              properties: {
                command: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect "input" parameter in execution context', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'execute_task',
            inputSchema: {
              type: 'object',
              properties: {
                input: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect "script" parameter without validation', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_automation',
            inputSchema: {
              type: 'object',
              properties: {
                script: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Safe Implementations (No Findings Expected)', () => {
    it('should pass for strict alphanumeric patterns', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_cmd',
            inputSchema: {
              type: 'object',
              properties: {
                arg: {
                  type: 'string',
                  pattern: '^[a-zA-Z0-9]+$' // Strict alphanumeric
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should pass for strict numeric patterns', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'exec_job',
            inputSchema: {
              type: 'object',
              properties: {
                job_id: {
                  type: 'string',
                  pattern: '^[0-9]+$' // Only digits
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should pass for patterns with underscores and hyphens only', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_process',
            inputSchema: {
              type: 'object',
              properties: {
                name: {
                  type: 'string',
                  pattern: '^[a-zA-Z0-9_-]+$' // Safe characters
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should ignore non-execution tools without risky parameters', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'calculate_sum',
            description: 'Adds two numbers',
            inputSchema: {
              type: 'object',
              properties: {
                a: { type: 'number' },
                b: { type: 'number' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should ignore non-string parameters', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'exec_operation',
            inputSchema: {
              type: 'object',
              properties: {
                count: { type: 'number' },
                enabled: { type: 'boolean' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });
  });

  describe('Execution Tools Without Schema', () => {
    it('should detect execution tools without inputSchema (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_fixed_command',
            description: 'Runs a predefined shell command'
            // No inputSchema
          } as any
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('medium');
    });

    it('should not flag non-execution tools without schema', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'get_status',
            description: 'Gets current status'
            // No inputSchema, but not an execution tool
          } as any
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty discovery result', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should handle undefined tools', () => {
      const discovery = {
        tools: undefined,
        resources: [],
        prompts: []
      } as unknown as DiscoveryResult;

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should handle tool with empty properties', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'exec_empty',
            description: 'Executes something',
            inputSchema: {
              type: 'object',
              properties: {}
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should include proper location metadata for findings', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'run_script',
            inputSchema: {
              type: 'object',
              properties: {
                script: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings[0].location).toEqual({
        type: 'tool',
        name: 'run_script',
        parameter: 'script'
      });
    });

    it('should include component identifier in findings', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'shell_exec',
            inputSchema: {
              type: 'object',
              properties: {
                cmd: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings[0].component).toBe('tool:shell_exec');
    });

    it('should handle very long patterns gracefully (ReDoS protection)', () => {
      const longPattern = 'a'.repeat(1001);
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'exec_test',
            inputSchema: {
              type: 'object',
              properties: {
                input: {
                  type: 'string',
                  pattern: longPattern
                }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      // Should not throw, should detect as weak
      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].evidence?.allowedShellChars).toContain('Pattern too long (>500 chars)');
    });
  });
});

