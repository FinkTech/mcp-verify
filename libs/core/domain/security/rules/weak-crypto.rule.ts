/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Weak Cryptography Rule (SEC-012)
 *
 * Detects weak, deprecated, or insecure cryptographic algorithms in MCP tool
 * definitions. Covers weak ciphers (DES, RC4), weak hashes (MD5, SHA-1),
 * insecure PRNGs (Math.random, rand()), dangerously short key sizes, and
 * tools that perform cryptography without specifying a strong algorithm.
 *
 * FIX (v1.0.1): All pattern matching now uses pre-compiled word-boundary
 * RegExp instead of .includes() on lowercased strings. This eliminates the
 * false positive where "diagnostic" triggered the DES rule because it contains
 * the substring "d-e-s".
 *
 * @see https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
 * @see https://cwe.mitre.org/data/definitions/327.html
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type {
  DiscoveryResult,
  SecurityFinding,
} from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

// ─── Internal Pattern Descriptor Types ───────────────────────────────────────

interface EncryptionEntry {
  name:     string;
  pattern:  RegExp;
  severity: 'critical' | 'high';
}

interface HashEntry {
  name:    string;
  pattern: RegExp;
}

interface PrngEntry {
  method:  string;
  pattern: RegExp;
}

// ─── Pre-compiled Pattern Tables ─────────────────────────────────────────────
// All patterns use \b word boundaries so they never match substrings.
// Compiled once at module load — zero per-call allocation cost.

const WEAK_ENCRYPTION: ReadonlyArray<EncryptionEntry> = [
  { name: 'DES',      pattern: /\bDES\b/i,                              severity: 'critical' },
  { name: '3DES',     pattern: /\b(?:3DES|TDES|Triple[-_]?DES)\b/i,    severity: 'critical' },
  { name: 'RC4',      pattern: /\bRC4\b|\bArcFour\b/i,                  severity: 'critical' },
  { name: 'RC2',      pattern: /\bRC2\b/i,                              severity: 'critical' },
  { name: 'Blowfish', pattern: /\bBlowfish\b/i,                         severity: 'critical' },
  { name: 'AES-128',  pattern: /\bAES[-_]?128\b/i,                      severity: 'high'     },
  { name: 'RSA-1024', pattern: /\bRSA[-_]?1024\b/i,                     severity: 'high'     },
  { name: 'RSA-512',  pattern: /\bRSA[-_]?512\b/i,                      severity: 'high'     },
];

const WEAK_HASHES: ReadonlyArray<HashEntry> = [
  { name: 'MD5',   pattern: /\bMD5\b/i       },
  { name: 'MD4',   pattern: /\bMD4\b/i       },
  { name: 'SHA-1', pattern: /\bSHA[-_]?1\b(?!\d)/i },
  { name: 'CRC32', pattern: /\bCRC[-_]?32\b/i },
];

const INSECURE_PRNGS: ReadonlyArray<PrngEntry> = [
  { method: 'Math.random()', pattern: /\bMath\.random\b/i          },
  { method: 'rand()',        pattern: /\brand\s*\(\s*\)/i           },
  { method: 'srand()',       pattern: /\bsrand\s*\(\s*\)/i          },
  { method: 'random()',      pattern: /\brandom\s*\(\s*\)/i         },
];

const STRONG_CRYPTO: ReadonlyArray<RegExp> = [
  /\bAES[-_]?(?:192|256)\b/i,
  /\bChaCha20(?:[-_]Poly1305)?\b/i,
  /\bSHA[-_]?(?:256|384|512)\b/i,
  /\bSHA[-_]?3\b/i,
  /\bArgon2(?:id|i|d)?\b/i,
  /\bbcrypt\b/i,
  /\bscrypt\b/i,
  /\bPBKDF2\b/i,
  /\bRSA[-_]?(?:2048|3072|4096)\b/i,
  /\bECDSA\b/i,
  /\bEd25519\b/i,
  /\bX25519\b/i,
];

const CRYPTO_CONTEXT = /\b(?:encrypt(?:s|ed|ing|ion)?|decrypt(?:s|ed|ing|ion)?|cipher|hash(?:es|ed|ing)?|sign(?:s|ed|ing)?|verify|verif(?:ies|ied|ying)|digest|crypt(?:o(?:graph(?:y|ic|ically))?)?|hmac|mac|token)/i;
const KEY_SIZE_PARAM = /^(?:key(?:_?size|_?len(?:gth)?|bits)|bits|key[-_]?length)$/i;
const ALGO_PARAM = /^(?:algorithm|algo|cipher|hash[-_]?type|enc(?:oding|ryption)?[-_]?(?:type|algo(?:rithm)?))$/i;

const WEAK_ALGO_NAMES: ReadonlySet<string> = new Set([
  ...WEAK_ENCRYPTION.map(e => e.name.toLowerCase()),
  ...WEAK_HASHES.map(h => h.name.toLowerCase()),
]);

const MIN_KEY_BITS    = 128;

// ─── Rule Class ───────────────────────────────────────────────────────────────

export class WeakCryptographyRule implements ISecurityRule {
  /** Public identifier — always emitted in every finding. */
  readonly code    = 'SEC-012';
  get name() { return t('sec_weak_crypto_name'); }
  get description() { return t('sec_weak_crypto_desc'); }
  readonly helpUri = 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure';

  // ── Public API ──────────────────────────────────────────────────────────────

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const tools = discovery?.tools;
    if (!Array.isArray(tools) || tools.length === 0) return [];
    return tools.flatMap(t => this.evaluateTool(t as McpTool));
  }

  // ── Per-Tool Orchestration ──────────────────────────────────────────────────

  private evaluateTool(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const desc   = tool.description ?? '';
    const schema = tool.inputSchema;

    // Order matters: specific detectors run before the catch-all "unspecified".
    const enc  = this.detectWeakEncryption(tool.name, desc);
    const hash = this.detectWeakHashing(tool.name, desc);
    const prng = this.detectInsecureRandom(tool.name, desc);
    const enm  = this.detectWeakAlgorithmEnum(tool.name, schema);
    const key  = this.detectShortKeyLength(tool.name, desc, schema);

    if (enc)  findings.push(enc);
    if (hash) findings.push(hash);
    if (prng) findings.push(prng);
    if (enm)  findings.push(enm);
    if (key)  findings.push(key);

    // Medium "unspecified" warning only fires when nothing more specific fired.
    const unspec = this.detectUnspecifiedAlgorithm(tool.name, desc, findings);
    if (unspec) findings.push(unspec);

    return findings;
  }

  // ── Detection Methods ───────────────────────────────────────────────────────

  private detectWeakEncryption(toolName: string, text: string): SecurityFinding | null {
    for (const { name, pattern, severity } of WEAK_ENCRYPTION) {
      if (pattern.test(text)) {
        return this.makeFinding({
          toolName,
          severity,
          message:  t('finding_crypto_weak_encryption', { tool: toolName, algo: name }),
          evidence: { algorithm: name, matched_in: 'description', risk: t('risk_crypto_broken', { algo: name }) },
          remediation: t('replace_with_aes256gcm_chacha20poly1305_or_xchacha')
        });
      }
    }
    return null;
  }

  private detectWeakHashing(toolName: string, text: string): SecurityFinding | null {
    for (const { name, pattern } of WEAK_HASHES) {
      if (pattern.test(text)) {
        return this.makeFinding({
          toolName,
          severity: 'critical',
          message:  t('finding_crypto_weak_hashing', { tool: toolName, algo: name }),
          evidence: { algorithm: name, matched_in: 'description', risk: t('risk_crypto_collision', { algo: name }) },
          remediation: t('replace_with_sha256_sha384_sha512_sha3_or_blake2bl')
        });
      }
    }
    return null;
  }

  private detectInsecureRandom(toolName: string, text: string): SecurityFinding | null {
    for (const { method, pattern } of INSECURE_PRNGS) {
      if (pattern.test(text)) {
        return this.makeFinding({
          toolName,
          severity: 'high',
          message:  t('finding_crypto_insecure_random', { tool: toolName, method }),
          evidence: { method, matched_in: 'description', risk: t('risk_crypto_predictable') },
          remediation: t('use_cryptographically_secure_random_number_generat')
        });
      }
    }
    return null;
  }

  private detectWeakAlgorithmEnum(
    toolName: string,
    schema:   McpTool['inputSchema'] | undefined,
  ): SecurityFinding | null {
    if (!schema?.properties) return null;

    for (const [paramName, raw] of Object.entries(schema.properties)) {
      if (typeof raw !== 'object' || raw === null) continue;
      if (!ALGO_PARAM.test(paramName)) continue;

      const ps         = raw as Record<string, unknown>;
      const enumValues = ps['enum'];
      if (!Array.isArray(enumValues)) continue;

      const weakFound = enumValues
        .filter((v): v is string => typeof v === 'string')
        .filter(v => this.isWeakAlgorithm(v));

      if (weakFound.length > 0) {
        return this.makeFinding({
          toolName,
          severity: 'high',
          message:  t('finding_crypto_weak_selection', { param: paramName }),
          evidence: { parameter: paramName, weak_options: weakFound, risk: t('risk_crypto_weak_selection') },
          remediation: t('remove_weak_algorithms_from_enum_only_allow_aes256')
        });
      }
    }
    return null;
  }

  private detectShortKeyLength(
    toolName: string,
    desc:     string,
    schema:   McpTool['inputSchema'] | undefined,
  ): SecurityFinding | null {
    if (!schema?.properties) return null;
    if (!CRYPTO_CONTEXT.test(desc)) return null;

    for (const [paramName, raw] of Object.entries(schema.properties)) {
      if (typeof raw !== 'object' || raw === null) continue;
      if (!KEY_SIZE_PARAM.test(paramName)) continue;

      const ps      = raw as Record<string, unknown>;
      const minimum = typeof ps['minimum'] === 'number' ? ps['minimum'] : null;
      const maximum = typeof ps['maximum'] === 'number' ? ps['maximum'] : null;

      if (maximum !== null && maximum < 256) {
        return this.makeFinding({
          toolName,
          severity: 'high',
          message: t('finding_crypto_short_key', { param: paramName }),
          evidence: { parameter: paramName, maximum_bits: maximum, safe_minimum: 256 },
          remediation: t('set_minimum_key_length_to_256_bits_for_symmetric_e')
        });
      }

      if (minimum !== null && minimum < MIN_KEY_BITS) {
        return this.makeFinding({
          toolName,
          severity: 'critical',
          message:  t('finding_crypto_danger_short', { param: paramName }),
          evidence: { parameter: paramName, minimum_bits: minimum, safe_minimum: MIN_KEY_BITS, risk: t('risk_crypto_brute_force') },
          remediation: t('enforce_minimum_256_bits_for_aes_2048_bits_for_rsa')
        });
      }
    }
    return null;
  }

  private detectUnspecifiedAlgorithm(
    toolName:        string,
    desc:            string,
    existingFindings: SecurityFinding[],
  ): SecurityFinding | null {
    if (existingFindings.length > 0) return null;
    if (!CRYPTO_CONTEXT.test(desc)) return null;
    if (this.hasStrongCryptography(desc)) return null;

    return this.makeFinding({
      toolName,
      severity: 'medium',
      message:  t('finding_crypto_no_algorithms', { tool: toolName }),
      evidence: { matched_in: 'description', risk: t('unclear_if_strong_cryptography_is_used') },
      remediation: t('document_cryptographic_algorithms_aes256gcm_for_en')
    });
  }

  // ── Helper Methods ──────────────────────────────────────────────────────────

  private hasStrongCryptography(text: string): boolean {
    return STRONG_CRYPTO.some(p => p.test(text));
  }

  private isWeakAlgorithm(name: string): boolean {
    return WEAK_ALGO_NAMES.has(name.toLowerCase());
  }

  private makeFinding(params: {
    toolName:  string;
    severity:  'critical' | 'high' | 'medium' | 'low' | 'info';
    message:   string;
    evidence:  Record<string, JsonValue>;
    remediation?: string;
  }): SecurityFinding {
    return {
      ruleCode:  this.code,
      message:   params.message,
      severity:  params.severity,
      component: `tool:${params.toolName}`,
      location:  { type: 'tool', name: params.toolName },
      evidence:  params.evidence,
      remediation: params.remediation
    };
  }
}
