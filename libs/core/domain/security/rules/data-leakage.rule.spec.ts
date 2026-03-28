/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Data Leakage Detection Rule Tests (SEC-004)
 * 
 * Comprehensive tests for Data Leakage vulnerability detection.
 * Tests cover all SENSITIVE_KEYWORDS and RISKY_RESOURCE_EXTENSIONS.
 */

import { DataLeakageRule } from './data-leakage.rule';
import { DiscoveryResult } from '../../mcp-server/entities/validation.types';

describe('DataLeakageRule', () => {
  let rule: DataLeakageRule;

  beforeEach(() => {
    rule = new DataLeakageRule();
  });

  describe('Rule Metadata', () => {
    it('should have correct code SEC-008', () => {
      expect(rule.code).toBe('SEC-008');
    });

    it('should have valid tags for CWE and OWASP mapping', () => {
      expect(rule.tags).toContain('CWE-200');
      expect(rule.tags).toContain('OWASP-A01:2021');
      expect(rule.tags).toContain('Information Disclosure');
    });

    it('should have a helpUri pointing to OWASP resource', () => {
      expect(rule.helpUri).toContain('owasp.org');
    });
  });

  describe('Tool Input Leakage Detection', () => {
    it('should detect tools requesting API keys (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'login_service',
            inputSchema: {
              type: 'object',
              properties: {
                api_key: { type: 'string', description: 'Your service API Token' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].message).toContain('accepts sensitive data');
      expect(findings[0].message).toContain('api_key');
    });

    it('should detect password parameters (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'authenticate',
            inputSchema: {
              type: 'object',
              properties: {
                username: { type: 'string' },
                password: { type: 'string', description: 'User password' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      const passwordFinding = findings.find(f => f.message.includes('password'));
      expect(passwordFinding).toBeDefined();
      expect(passwordFinding!.severity).toBe('medium');
    });

    it('should detect secret parameters (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'send_notification',
            inputSchema: {
              type: 'object',
              properties: {
                client_secret: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('client_secret');
    });

    it('should detect token parameters (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'refresh_session',
            inputSchema: {
              type: 'object',
              properties: {
                refresh_token: { type: 'string', description: 'OAuth refresh token' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('refresh_token');
    });

    it('should detect access_key parameters (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'aws_operation',
            inputSchema: {
              type: 'object',
              properties: {
                access_key: { type: 'string' },
                secret_key: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(2); // access_key AND secret (from secret_key)
    });

    it('should detect private_key parameters (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'sign_document',
            inputSchema: {
              type: 'object',
              properties: {
                private_key: { type: 'string', description: 'PEM encoded private key' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].component).toBe('tool:sign_document');
    });

    it('should detect credential parameters (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'database_connect',
            inputSchema: {
              type: 'object',
              properties: {
                db_credentials: { type: 'string', description: 'Connection string with credentials' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('db_credentials');
    });

    it('should detect PII like SSN (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'verify_identity',
            inputSchema: {
              type: 'object',
              properties: {
                social_security_number: { type: 'string', description: 'User SSN for verification' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].evidence).toEqual({ parameter: 'social_security_number' });
    });

    it('should detect credit_card parameters (Medium)', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'process_payment',
            inputSchema: {
              type: 'object',
              properties: {
                credit_card: { type: 'string' },
                cvv: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      const ccFinding = findings.find(f => f.message.includes('credit_card'));
      expect(ccFinding).toBeDefined();
    });

    it('should detect sensitive keywords in description even if param name is safe', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'generic_update',
            inputSchema: {
              type: 'object',
              properties: {
                value: { type: 'string', description: 'Enter your password here' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('value');
    });

    it('should provide proper remediation advice', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'set_api_key',
            inputSchema: {
              type: 'object',
              properties: {
                apikey: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings[0].remediation).toContain('environment variables');
      expect(findings[0].remediation).toContain('MCP resource templates');
    });
  });

  describe('Resource Leakage Detection', () => {
    it('should detect .env files as critical (Critical)', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'Environment Config',
            uri: 'file:///app/.env',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].message).toContain('exposes potentially sensitive file');
    });

    it('should detect .key files as critical', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'SSL Private Key',
            uri: 'file:///etc/ssl/private/server.key',
            mimeType: 'application/x-pem-file'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('critical');
    });

    it('should detect .pem files as critical', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'Certificate Chain',
            uri: 'file:///certs/private.pem',
            mimeType: 'application/x-pem-file'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
    });

    it('should detect .p12/.pfx files (PKCS#12)', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'Key Store',
            uri: 'file:///keys/signing.p12',
            mimeType: 'application/x-pkcs12'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
    });

    it('should detect .kdbx (KeePass database) files', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'Password Database',
            uri: 'file:///data/passwords.kdbx',
            mimeType: 'application/octet-stream'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
      expect(findings[0].evidence).toHaveProperty('uri');
    });

    it('should detect id_rsa files (SSH keys)', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'SSH Key',
            uri: 'file:///home/user/.ssh/id_rsa',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
    });

    it('should detect config.json files (potential secrets)', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'App Configuration',
            uri: 'file:///app/config.json',
            mimeType: 'application/json'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
    });

    it('should detect settings.xml files (Maven credentials)', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'Maven Settings',
            uri: 'file:///home/user/.m2/settings.xml',
            mimeType: 'application/xml'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
    });

    it('should detect risky extensions in resource name (not just URI)', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'production.env',
            uri: 'resource:///configs/prod',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
    });

    it('should provide proper remediation for resource leakage', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'secrets',
            uri: 'file:///secrets/.env',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings[0].remediation).toContain('Do not expose configuration files');
      expect(findings[0].remediation).toContain('scoped data access');
    });

    it('should detect multiple risky resources', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          { name: 'env_file', uri: 'file:///app/.env', mimeType: 'text/plain' },
          { name: 'ssh_key', uri: 'file:///home/.ssh/id_rsa', mimeType: 'text/plain' },
          { name: 'ssl_cert', uri: 'file:///certs/server.pem', mimeType: 'text/plain' }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(3);
      findings.forEach(f => expect(f.severity).toBe('critical'));
    });
  });

  describe('Safe Implementations (No Findings Expected)', () => {
    it('should ignore safe tool inputs', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'search',
            inputSchema: {
              type: 'object',
              properties: {
                query: { type: 'string', description: 'Search term' }
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

    it('should ignore safe resource URIs', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'Public Document',
            uri: 'file:///docs/readme.md',
            mimeType: 'text/markdown'
          },
          {
            name: 'API Data',
            uri: 'https://api.example.com/data',
            mimeType: 'application/json'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should handle tools without inputSchema properties', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'simple_tool',
            inputSchema: { type: 'object' } // No properties defined
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should handle tools with empty properties', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'empty_tool',
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

    it('should handle empty discovery result', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should handle undefined tools and resources', () => {
      const discovery = {
        tools: undefined,
        resources: undefined,
        prompts: []
      } as unknown as DiscoveryResult;

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });
  });

  describe('Combined Tool and Resource Leakage', () => {
    it('should detect issues in both tools and resources', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'api_client',
            inputSchema: {
              type: 'object',
              properties: {
                api_key: { type: 'string' }
              }
            }
          }
        ],
        resources: [
          {
            name: 'Config',
            uri: 'file:///app/.env',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(2);

      const toolFinding = findings.find(f => f.component === 'tool:api_client');
      const resourceFinding = findings.find(f => f.component === 'resource:Config');

      expect(toolFinding).toBeDefined();
      expect(toolFinding!.severity).toBe('medium');

      expect(resourceFinding).toBeDefined();
      expect(resourceFinding!.severity).toBe('critical');
    });
  });

  describe('Edge Cases', () => {
    it('should be case-insensitive for keyword detection', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'mixed_case',
            inputSchema: {
              type: 'object',
              properties: {
                USER_PASSWORD: { type: 'string' },
                ApiKey: { type: 'string' }
              }
            }
          }
        ],
        resources: [],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      // Should detect both PASSWORD and APIKEY
      expect(findings.length).toBe(2);
    });

    it('should handle resource with empty uri gracefully', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: 'Empty URI Resource',
            uri: '',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      // Should not throw
      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(0);
    });

    it('should handle resource with empty name gracefully', () => {
      const discovery: DiscoveryResult = {
        tools: [],
        resources: [
          {
            name: '',
            uri: 'file:///app/.env',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);
      expect(findings.length).toBe(1);
    });

    it('should include proper location metadata for findings', () => {
      const discovery: DiscoveryResult = {
        tools: [
          {
            name: 'test_tool',
            inputSchema: {
              type: 'object',
              properties: {
                secret: { type: 'string' }
              }
            }
          }
        ],
        resources: [
          {
            name: 'test_resource',
            uri: 'file:///test.env',
            mimeType: 'text/plain'
          }
        ],
        prompts: []
      };

      const findings = rule.evaluate(discovery);

      const toolFinding = findings.find(f => f.component?.includes('tool'));
      expect(toolFinding!.location).toEqual({
        type: 'tool',
        name: 'test_tool',
        parameter: 'secret'
      });

      const resourceFinding = findings.find(f => f.component?.includes('resource'));
      expect(resourceFinding!.location).toEqual({
        type: 'resource',
        uri: 'file:///test.env'
      });
    });
  });
});
