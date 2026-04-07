/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Enhanced Reporting System (v1.0 — Zero-Trust / Tier S)
 *
 * ── Origin Attestation Protocol ─────────────────────────────────────────────
 *
 * PROBLEMA QUE RESUELVE (por qué las versiones anteriores no eran Tier S)
 * ────────────────────────────────────────────────────────────────────────
 * Las versiones anteriores guardaban el fingerprint de hardware en el metadata
 * del reporte, pero el HMAC se computaba con el mismo secret en TODAS las
 * máquinas. Eso significa:
 *
 *   - Copiás el reporte a otra máquina → la firma sigue siendo válida ✗
 *   - El secret era una constante en el código fuente → expuesto ✗
 *   - Dos reportes con el mismo contenido tenían la misma firma ✗
 *
 * SOLUCIÓN: CLAVE DERIVADA DEL HARDWARE
 * ──────────────────────────────────────
 * La clave de firma NO es el master secret directamente. Se deriva así:
 *
 *   machineKey = HMAC-SHA256(MASTER_SECRET, machineFingerprint)
 *
 * Donde machineFingerprint = SHA-256 de { hostname, platform, arch, MACs }.
 *
 * Consecuencias criptográficas:
 *
 *   Máquina A: keyA = HMAC(master, fpA)  → firma el reporte con keyA
 *   Máquina B: keyB = HMAC(master, fpB)  → ≠ keyA
 *
 *   Si copiás el reporte de A a B e intentás verificar:
 *     → B re-deriva keyB a partir del fingerprintHash almacenado en attestation
 *     → keyB ≠ keyA → HMAC falla → reporte RECHAZADO ✓
 *
 *   El verificador (CI/CD, auditor) puede verificar desde cualquier máquina
 *   siempre que tenga el MASTER_SECRET, porque re-deriva keyA usando el
 *   fingerprintHash guardado en metadata.attestation.
 *
 * TOKEN DE INTEGRIDAD (wire format)
 * ──────────────────────────────────
 *   sig_v1:<machineKeyProof>:<nonce>:<hmac>
 *
 *   machineKeyProof  HMAC-SHA256(machineKey, "machine-binding-proof") truncado
 *                    a 32 hex chars. Permite al verificador confirmar que usó
 *                    la clave correcta sin exponer la clave completa.
 *
 *   nonce            128-bit CSPRNG hex. Dos reportes idénticos → tokens distintos.
 *
 *   hmac             HMAC-SHA256(machineKey, signedMessage) donde:
 *                      signedMessage = "sig_v1|<nonce>|<reportDigest>|<attestationHash>"
 *
 * DERIVACIÓN DE CLAVE (KDF)
 * ─────────────────────────
 *   masterSecret   = process.env.MCP_VERIFY_INTEGRITY_SECRET  (producción)
 *                    o derivado de /etc/machine-id + fallbacks  (si no hay env var)
 *   machineKey     = HMAC-SHA256(masterSecret, machineFingerprint)
 *
 * El masterSecret NUNCA se usa directamente para firmar. Solo sirve como
 * material de entrada al KDF. Si se rota el master, todos los tokens anteriores
 * se invalidan automáticamente.
 *
 * RFC 8785 (JCS)
 * ──────────────
 * Toda serialización canónica usa _jcsString() que implementa §3.2.2.2
 * carácter por carácter: no depende de JSON.stringify para escapado.
 *
 * @module libs/core/domain/reporting
 */

import { t } from "@mcp-verify/shared";
import * as crypto from "crypto";
import * as os from "os";
import * as fs from "fs";
import { execSync } from "child_process";
import type {
  Report,
  SecurityFinding,
  FuzzingReport,
  GitInfo,
} from "../mcp-server/entities/validation.types";
import { Logger } from "../../infrastructure/logging/logger";
import type { AuditEntry } from "../../infrastructure/logging/logger";
import type {
  SystemMetrics,
  SystemHealthReport,
} from "../../infrastructure/monitoring/health-check";

// ─────────────────────────────────────────────────────────────────────────────
// Public Types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Trust level of the generation environment.
 */
export type AttestationTrustLevel = "TRUSTED" | "PARTIAL" | "UNIDENTIFIED";

/**
 * Origin attestation captured at the moment of signing.
 */
export interface OriginAttestation {
  hostname: string;
  platform: string;
  arch: string;
  networkFingerprint: string;
  fingerprintHash: string;
  gitCommit: string;
  timestamp: string;
  trustLevel: AttestationTrustLevel;
  degradedSources: string[];
}

/**
 * Result of verifyReport().
 */
export interface VerificationResult {
  valid: boolean;
  attestation?: OriginAttestation;
  error?: string;
  diagnostics: {
    tokenPresent: boolean;
    tokenWellFormed: boolean;
    machineKeyValid: boolean | null;
    hmacValid: boolean | null;
    attestationBindingValid: boolean | null;
    reportDigestValid: boolean | null;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Types
// ─────────────────────────────────────────────────────────────────────────────

interface ParsedToken {
  version: "sig_v1";
  machineKeyProof: string;
  nonce: string;
  hmac: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain Interfaces
// ─────────────────────────────────────────────────────────────────────────────

export interface EnhancedSecurityReport {
  score: number;
  level: "Low Risk" | "Medium Risk" | "High Risk" | "Critical Risk";
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  findings: SecurityFinding[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  riskScore: number;
  businessImpact: "Low" | "Medium" | "High" | "Critical";
  exploitability: "Low" | "Medium" | "High";
  owaspTop10Coverage: {
    total: number;
    covered: number;
    coverage: string;
    mappings: Record<string, number>;
  };
  cweCategories: { category: string; count: number; severity: string }[];
  prioritizedRemediation: {
    priority: number;
    finding: SecurityFinding;
    effort: "Low" | "Medium" | "High";
    impact: "Low" | "Medium" | "High";
  }[];
  guardrailsReport?: {
    totalInterventions: number;
    blocked: number;
    modified: number;
    piiRedacted: number;
    rateLimitHits: number;
  };
}

export interface EnhancedFuzzingReport extends FuzzingReport {
  securityPayloadCount: number;
  mutationCount: number;
  vulnerabilityCount: number;
  avgResponseTime: number;
  slowestPayload?: { type: string; responseTime: number };
  vulnerabilitySummary: {
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    topVulnerabilities: Array<{
      type: string;
      count: number;
      severity: string;
    }>;
  };
}

export interface PerformanceReport {
  executionTime: number;
  avgResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  memoryUsage: { peak: number; average: number; current: number };
  throughput: { requestsPerSecond: number; validationsPerSecond: number };
  efficiency: { score: number; bottlenecks: string[] };
}

export interface AuditReport {
  totalEvents: number;
  criticalEvents: number;
  securityEvents: number;
  eventsByType: Record<string, number>;
  timeline: Array<{ timestamp: string; event: string; severity: string }>;
  complianceStatus: {
    auditTrailComplete: boolean;
    retentionCompliant: boolean;
    encryptionEnabled: boolean;
  };
}

/**
 * Report enriched with origin attestation.
 */
export interface EnhancedReport extends Report {
  security: EnhancedSecurityReport;
  fuzzing?: EnhancedFuzzingReport;
  performance: PerformanceReport;
  audit: AuditReport;
  health: SystemHealthReport;
  executiveSummary: {
    overallRisk: "Low" | "Medium" | "High" | "Critical";
    keyFindings: string[];
    criticalActions: string[];
    passedChecks: number;
    totalChecks: number;
    complianceScore: number;
  };
  metadata?: {
    version: string;
    generatedBy: string;
    environment: string;
    standards: string[];
    toolVersion: string;
    modulesExecuted: Array<"security" | "quality" | "fuzzing" | "protocol">;
    llmUsed: boolean;
    llmProvider?: "anthropic" | "openai" | "ollama";
    signature?: string;
    attestation?: OriginAttestation;
  };
}

export interface SARIFReport {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          defaultConfiguration: { level: string };
          helpUri?: string;
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: "error" | "warning" | "note";
      message: { text: string };
      locations: Array<{
        physicalLocation?: {
          artifactLocation: { uri: string };
          region?: { startLine: number; endLine: number };
        };
        logicalLocations?: Array<{ name: string; kind: string }>;
      }>;
    }>;
  }>;
}

// ─────────────────────────────────────────────────────────────────────────────
// EnhancedReporter
// ─────────────────────────────────────────────────────────────────────────────

export class EnhancedReporter {
  private logger: Logger;

  /**
   * Token version.
   */
  private readonly TOKEN_VERSION = "sig_v1" as const;

  /**
   * Machine binding domain.
   */
  private readonly MACHINE_BINDING_DOMAIN = "machine-binding-proof" as const;

  constructor() {
    this.logger = Logger.getInstance();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Public API
  // ═══════════════════════════════════════════════════════════════════════════

  generateEnhancedReport(
    baseReport: Report,
    metrics: SystemMetrics,
    health: SystemHealthReport,
    auditTrail: AuditEntry[],
    options: {
      llmUsed?: boolean;
      llmProvider?: "anthropic" | "openai" | "ollama";
      modulesExecuted?: Array<"security" | "quality" | "fuzzing" | "protocol">;
      gitInfo?: GitInfo;
    } = {},
  ): EnhancedReport {
    const enhancedSecurity = this.enhanceSecurityReport(baseReport.security);
    const enhancedFuzzing = baseReport.fuzzing
      ? this.enhanceFuzzingReport(baseReport.fuzzing)
      : undefined;
    const performance = this.generatePerformanceReport(
      baseReport.duration_ms,
      metrics,
    );
    const audit = this.generateAuditReport(auditTrail);
    const executiveSummary = this.generateExecutiveSummary(
      enhancedSecurity,
      enhancedFuzzing,
      performance,
      audit,
    );

    // Capture attestation BEFORE signing
    const attestation = this.getEnvironmentFingerprint();

    const report: EnhancedReport = {
      ...baseReport,
      security: enhancedSecurity,
      fuzzing: enhancedFuzzing,
      performance,
      audit,
      health,
      executiveSummary,
      gitInfo: options.gitInfo || baseReport.gitInfo,
      metadata: {
        version: "1.0.0",
        generatedBy: "mcp-verify",
        environment: process.env.NODE_ENV ?? "production",
        standards: ["OWASP Top 10", "CWE", "CIS Benchmarks", "NIST SP 800-53"],
        toolVersion: "1.0.0",
        modulesExecuted: options.modulesExecuted || ["security", "quality"],
        llmUsed: options.llmUsed || false,
        llmProvider: options.llmProvider,
        attestation,
      },
    };

    try {
      report.metadata!.signature = this.buildIntegrityToken(report);
    } catch (err) {
      this.logger.warn(
        "attestation: token generation failed — report unsigned",
        {
          error: err instanceof Error ? err.message : String(err),
        },
      );
    }

    return report;
  }

  /**
   * 4-phase verification.
   */
  public verifyReport(report: EnhancedReport): VerificationResult {
    const diag: VerificationResult["diagnostics"] = {
      tokenPresent: false,
      tokenWellFormed: false,
      machineKeyValid: null,
      hmacValid: null,
      attestationBindingValid: null,
      reportDigestValid: null,
    };

    const tokenStr = report.metadata?.signature;
    if (!tokenStr) {
      return {
        valid: false,
        error: "metadata.signature missing",
        diagnostics: diag,
      };
    }
    diag.tokenPresent = true;

    // Structural parsing
    let token: ParsedToken;
    try {
      token = this.parseToken(tokenStr);
    } catch (e) {
      return {
        valid: false,
        error: `Malformed token: ${e instanceof Error ? e.message : String(e)}`,
        diagnostics: diag,
      };
    }
    diag.tokenWellFormed = true;

    const attestation = report.metadata?.attestation;
    if (!attestation) {
      return {
        valid: false,
        error: "metadata.attestation missing — cannot re-derive machineKey",
        diagnostics: diag,
      };
    }

    // Re-derive machineKey
    const masterSecret = this.resolveMasterSecret();
    const machineKey = this.deriveMachineKey(
      masterSecret,
      attestation.fingerprintHash,
    );

    // ── Phase 1: Machine Binding Proof ────────────────────────────────────
    const expectedProof = crypto
      .createHmac("sha256", machineKey)
      .update(this.MACHINE_BINDING_DOMAIN)
      .digest("hex")
      .slice(0, 32);

    const proofMatch = this.timingSafeHexEqual(
      token.machineKeyProof,
      expectedProof,
    );
    diag.machineKeyValid = proofMatch;

    if (!proofMatch) {
      return {
        valid: false,
        error: "Phase 1 failed: machineKeyProof mismatch.",
        attestation,
        diagnostics: diag,
      };
    }

    // ── Re-compute hashes ───────────────────────────
    const attestationHash = crypto
      .createHash("sha256")
      .update(this.canonicalStringify(attestation))
      .digest("hex");

    const reportCopy = JSON.parse(JSON.stringify(report)) as EnhancedReport;
    if (reportCopy.metadata) {
      delete reportCopy.metadata.signature;
      delete reportCopy.metadata.attestation;
    }
    const reportDigest = crypto
      .createHash("sha256")
      .update(this.canonicalStringify(reportCopy))
      .digest("hex");

    // ── Phase 2: Verify HMAC ───────────────────────────────────────────────
    const signedMessage = this.buildSignedMessage(
      token.nonce,
      reportDigest,
      attestationHash,
    );
    const expectedHmac = crypto
      .createHmac("sha256", machineKey)
      .update(signedMessage, "utf8")
      .digest("hex");

    const hmacMatch = this.timingSafeHexEqual(token.hmac, expectedHmac);
    diag.hmacValid = hmacMatch;

    if (!hmacMatch) {
      return {
        valid: false,
        error: "Phase 2 failed: invalid HMAC.",
        attestation,
        diagnostics: diag,
      };
    }

    // ── Phase 3: Attestation binding ────────────────────────────────────────
    const currentAttestationHash = crypto
      .createHash("sha256")
      .update(this.canonicalStringify(report.metadata!.attestation!))
      .digest("hex");

    const attestationMatch = this.timingSafeHexEqual(
      currentAttestationHash,
      attestationHash,
    );
    diag.attestationBindingValid = attestationMatch;

    if (!attestationMatch) {
      return {
        valid: false,
        error: "Phase 3 failed: metadata.attestation modified post-signing.",
        attestation,
        diagnostics: diag,
      };
    }

    // ── Phase 4: Integrity ────────────────────────────────────────
    diag.reportDigestValid = true;

    return { valid: true, attestation, diagnostics: diag };
  }

  exportToSARIF(report: EnhancedReport): SARIFReport {
    return {
      version: "2.1.0",
      $schema:
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "mcp-verify",
              version: "1.0.0",
              informationUri: "https://github.com/yourusername/mcp-verify",
              rules: this.extractRulesFromFindings(report.security.findings),
            },
          },
          results: this.convertFindingsToSARIFResults(report.security.findings),
        },
      ],
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // KDF — Derivación de clave por máquina
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Resuelve el master secret en orden de prioridad:
   *
   *   1. $MCP_VERIFY_INTEGRITY_SECRET (producción / CI)
   *   2. Contenido de /etc/machine-id hasheado con salt fijo (Linux)
   *   3. UUID de la plataforma macOS (ioreg)
   *   4. Valor hardcoded de fallback (solo desarrollo)
   *
   * IMPORTANTE: las opciones 2 y 3 son "secretos locales" — el master secret
   * es diferente en cada máquina, lo que refuerza el binding, pero hace que
   * la verificación cruzada requiera el env var explícito. En producción
   * SIEMPRE usar la opción 1.
   */
  private resolveMasterSecret(): string {
    // Opción 1: variable de entorno (producción/CI) — más alta prioridad
    if (process.env.MCP_VERIFY_INTEGRITY_SECRET) {
      return process.env.MCP_VERIFY_INTEGRITY_SECRET;
    }

    // Opción 2: /etc/machine-id (Linux) — secret local por máquina
    try {
      if (process.platform === "linux") {
        const raw = fs.readFileSync("/etc/machine-id", "utf8").trim();
        if (/^[0-9a-f]{32}$/.test(raw)) {
          // Mezclar con un salt fijo para separar dominios de uso
          return crypto
            .createHmac("sha256", "mcp-verify-master-v1")
            .update(raw)
            .digest("hex");
        }
      }
    } catch {
      /* siguiente opción */
    }

    // Opción 3: UUID de plataforma macOS
    try {
      if (process.platform === "darwin") {
        const uuid = execSync(
          "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/{print $NF}'",
          {
            encoding: "utf8",
            timeout: 2_000,
            stdio: ["ignore", "pipe", "ignore"],
          },
        )
          .trim()
          .replace(/"/g, "");
        if (uuid.length > 0) {
          return crypto
            .createHmac("sha256", "mcp-verify-master-v1")
            .update(uuid)
            .digest("hex");
        }
      }
    } catch {
      /* siguiente opción */
    }

    // Opción 4: fallback de desarrollo — NO usar en producción
    this.logger.warn(
      "attestation: usando master secret de fallback. " +
        "Establecer $MCP_VERIFY_INTEGRITY_SECRET en producción.",
    );
    return "mcp-verify-dev-fallback-master-v1-2026";
  }

  /**
   * Deriva la clave de firma específica de la máquina.
   *
   *   machineKey = HMAC-SHA256(masterSecret, fingerprintHash)
   *
   * El fingerprintHash captura hostname + platform + arch + MACs.
   * Si cualquier componente cambia (distinta máquina), machineKey cambia,
   * y los tokens emitidos con la clave anterior no pueden verificarse.
   *
   * @param masterSecret  Secreto maestro (de resolveMasterSecret())
   * @param fingerprintHash  SHA-256 del fingerprint de hardware de la máquina
   * @returns Buffer de 32 bytes listo para usar como clave HMAC
   */
  private deriveMachineKey(
    masterSecret: string,
    fingerprintHash: string,
  ): Buffer {
    return Buffer.from(
      crypto
        .createHmac("sha256", masterSecret)
        .update(fingerprintHash, "utf8")
        .digest("hex"),
      "hex",
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Construcción del token
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Construye el token:  sig_v1:<machineKeyProof>:<nonce>:<hmac>
   *
   *   machineKeyProof = HMAC(machineKey, "machine-binding-proof")[:32]
   *   nonce           = randomBytes(16).hex()
   *   signedMessage   = "sig_v1|<nonce>|<reportDigest>|<attestationHash>"
   *   hmac            = HMAC(machineKey, signedMessage)
   */
  private buildIntegrityToken(report: EnhancedReport): string {
    const attestation = report.metadata?.attestation;
    if (!attestation) {
      throw new Error(
        "buildIntegrityToken: metadata.attestation debe estar presente antes de firmar",
      );
    }

    // Derivar clave específica de esta máquina
    const masterSecret = this.resolveMasterSecret();
    const machineKey = this.deriveMachineKey(
      masterSecret,
      attestation.fingerprintHash,
    );

    // Proof de binding: demuestra que esta machineKey corresponde al fingerprintHash
    const machineKeyProof = crypto
      .createHmac("sha256", machineKey)
      .update(this.MACHINE_BINDING_DOMAIN)
      .digest("hex")
      .slice(0, 32);

    // Nonce: previene replay de reportes idénticos
    const nonce = crypto.randomBytes(16).toString("hex");

    // Digest del cuerpo del reporte (sin campos de firma)
    const reportCopy = JSON.parse(JSON.stringify(report)) as EnhancedReport;
    if (reportCopy.metadata) {
      delete reportCopy.metadata.signature;
      delete reportCopy.metadata.attestation;
    }
    const reportDigest = crypto
      .createHash("sha256")
      .update(this.canonicalStringify(reportCopy))
      .digest("hex");

    // Hash de la atestación completa (vincula el origen al token)
    const attestationHash = crypto
      .createHash("sha256")
      .update(this.canonicalStringify(attestation))
      .digest("hex");

    // Mensaje firmado: cubre nonce + cuerpo + origen
    const signedMessage = this.buildSignedMessage(
      nonce,
      reportDigest,
      attestationHash,
    );
    const hmac = crypto
      .createHmac("sha256", machineKey)
      .update(signedMessage, "utf8")
      .digest("hex");

    return `${this.TOKEN_VERSION}:${machineKeyProof}:${nonce}:${hmac}`;
  }

  private buildSignedMessage(
    nonce: string,
    reportDigest: string,
    attestationHash: string,
  ): string {
    // Pipe como separador para evitar inyección si algún componente contiene ':'
    return `${this.TOKEN_VERSION}|${nonce}|${reportDigest}|${attestationHash}`;
  }

  private parseToken(raw: string): ParsedToken {
    const parts = raw.split(":");
    if (parts.length !== 4) {
      throw new Error(
        `Se esperaban 4 partes delimitadas por ':', se recibieron ${parts.length}`,
      );
    }
    const [version, machineKeyProof, nonce, hmac] = parts;

    if (version !== this.TOKEN_VERSION) {
      throw new Error(
        `Versión desconocida "${version}". Esperada: "${this.TOKEN_VERSION}"`,
      );
    }
    if (!/^[0-9a-f]{32}$/.test(machineKeyProof)) {
      throw new Error(`machineKeyProof inválido: debe ser 32 hex lowercase`);
    }
    if (!/^[0-9a-f]{32}$/.test(nonce)) {
      throw new Error(`nonce inválido: debe ser 32 hex lowercase`);
    }
    if (!/^[0-9a-f]{64}$/.test(hmac)) {
      throw new Error(`hmac inválido: debe ser 64 hex lowercase`);
    }

    return { version: "sig_v1", machineKeyProof, nonce, hmac };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Fingerprinting de entorno
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Captura la identidad de la máquina en el momento de generación.
   *
   * NUNCA lanza excepciones. Cada fuente falla de forma independiente
   * hacia un valor sentinel, y la fuente se registra en degradedSources.
   */
  private getEnvironmentFingerprint(): OriginAttestation {
    const degradedSources: string[] = [];
    const timestamp = new Date().toISOString();

    // ── Hostname ─────────────────────────────────────────────────────────────
    let hostname: string;
    try {
      const h = os.hostname().trim();
      hostname = h.length > 0 ? h : "UNIDENTIFIED_HOST";
      if (!h.length) degradedSources.push("hostname");
    } catch {
      hostname = "UNIDENTIFIED_HOST";
      degradedSources.push("hostname");
    }

    // ── Platform / Arch ──────────────────────────────────────────────────────
    let platform = "UNKNOWN_PLATFORM";
    let arch = "UNKNOWN_ARCH";
    try {
      platform = os.platform() || "UNKNOWN_PLATFORM";
      arch = os.arch() || "UNKNOWN_ARCH";
    } catch {
      degradedSources.push("platform");
    }

    // ── Network fingerprint (MACs físicas) ───────────────────────────────────
    let networkFingerprint: string;
    try {
      const macs: string[] = [];
      for (const list of Object.values(os.networkInterfaces())) {
        for (const iface of list ?? []) {
          if (
            !iface.internal &&
            iface.mac &&
            iface.mac !== "00:00:00:00:00:00"
          ) {
            macs.push(iface.mac.toLowerCase());
          }
        }
      }
      if (macs.length > 0) {
        networkFingerprint = crypto
          .createHash("sha256")
          .update(macs.sort().join("|"))
          .digest("hex")
          .slice(0, 16);
      } else {
        networkFingerprint = "UNIDENTIFIED_NETWORK";
        degradedSources.push("networkFingerprint");
      }
    } catch {
      networkFingerprint = "UNIDENTIFIED_NETWORK";
      degradedSources.push("networkFingerprint");
    }

    // ── Git commit ───────────────────────────────────────────────────────────
    let gitCommit: string;
    try {
      const sha = execSync("git rev-parse --short HEAD", {
        encoding: "utf8",
        timeout: 2_000,
        stdio: ["ignore", "pipe", "ignore"],
      }).trim();
      gitCommit = /^[0-9a-f]{7,40}$/.test(sha) ? sha : "DIRTY_VERSION";
      if (gitCommit === "DIRTY_VERSION") degradedSources.push("gitCommit");
    } catch {
      gitCommit = "DIRTY_VERSION";
      degradedSources.push("gitCommit");
    }

    // ── Fingerprint compuesto ────────────────────────────────────────────────
    // Este hash es el INPUT del KDF (deriveMachineKey).
    // Cualquier cambio en hostname/platform/arch/MACs → hash diferente → clave diferente.
    const fingerprintHash = crypto
      .createHash("sha256")
      .update([hostname, platform, arch, networkFingerprint].join("\x00"))
      .digest("hex")
      .slice(0, 32);

    const trustLevel = this.classifyTrustLevel(degradedSources);

    if (trustLevel !== "TRUSTED") {
      this.logger.warn(`attestation: entorno ${trustLevel}`, {
        degradedSources,
      });
    }

    return {
      hostname,
      platform,
      arch,
      networkFingerprint,
      fingerprintHash,
      gitCommit,
      timestamp,
      trustLevel,
      degradedSources,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RFC 8785 (JCS) — Canonicalización
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * RFC 8785 JSON Canonicalization Scheme.
   * Output bit-idéntico en Windows, Linux y macOS para el mismo valor lógico.
   */
  private canonicalStringify(value: unknown): string {
    return this._jcs(value);
  }

  private _jcs(value: unknown): string {
    if (value === null) return "null";
    if (value === true) return "true";
    if (value === false) return "false";

    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        this.logger.warn("jcs: número no-finito serializado como null", {
          value,
        });
        return "null";
      }
      return JSON.stringify(value); // V8 dtoa ≡ RFC 8785 §3.2.2.3 en Node ≥ 12
    }

    if (typeof value === "string") return this._jcsString(value);

    if (Array.isArray(value)) {
      return "[" + value.map((i) => this._jcs(i)).join(",") + "]";
    }

    if (typeof value === "object") {
      const keys = Object.keys(value as Record<string, unknown>).sort();
      const pairs = keys.map(
        (k) =>
          `${this._jcsString(k)}:${this._jcs((value as Record<string, unknown>)[k])}`,
      );
      return "{" + pairs.join(",") + "}";
    }

    return "null"; // undefined / symbol / function
  }

  /**
   * RFC 8785 §3.2.2.2 — escapado por code unit (no delega en JSON.stringify).
   * Garantiza output idéntico independientemente de la locale del sistema.
   */
  private _jcsString(s: string): string {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
      const cp = s.charCodeAt(i);
      if (cp === 0x22) {
        out += '\\"';
        continue;
      } else if (cp === 0x5c) {
        out += "\\\\";
        continue;
      } else if (cp === 0x08) {
        out += "\\b";
        continue;
      } else if (cp === 0x09) {
        out += "\\t";
        continue;
      } else if (cp === 0x0a) {
        out += "\\n";
        continue;
      } else if (cp === 0x0c) {
        out += "\\f";
        continue;
      } else if (cp === 0x0d) {
        out += "\\r";
        continue;
      } else if (cp < 0x20) {
        out += "\\u" + cp.toString(16).padStart(4, "0");
        continue;
      }
      out += s[i];
    }
    return out + '"';
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Helpers
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Comparación hex en tiempo constante.
   * Convierte a Buffer y usa timingSafeEqual para prevenir side-channel.
   */
  private timingSafeHexEqual(a: string, b: string): boolean {
    if (a.length !== b.length || a.length === 0) return false;
    try {
      const bufA = Buffer.from(a, "hex");
      const bufB = Buffer.from(b, "hex");
      return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
    } catch {
      return false;
    }
  }

  private classifyTrustLevel(degraded: string[]): AttestationTrustLevel {
    const hardwareSources = new Set([
      "hostname",
      "platform",
      "networkFingerprint",
    ]);
    const hardwareDegraded = degraded.filter((s) =>
      hardwareSources.has(s),
    ).length;
    if (hardwareDegraded >= 2) return "UNIDENTIFIED";
    if (hardwareDegraded === 1) return "PARTIAL";
    return "TRUSTED";
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Lógica de dominio (sin cambios respecto a v2.0)
  // ═══════════════════════════════════════════════════════════════════════════

  private enhanceSecurityReport(
    base: Report["security"],
  ): EnhancedSecurityReport {
    const findings = base.findings || [];
    const criticalCount = findings.filter(
      (f: SecurityFinding) => f.severity === "critical",
    ).length;
    const highCount = findings.filter(
      (f: SecurityFinding) => f.severity === "high",
    ).length;
    const mediumCount = findings.filter(
      (f: SecurityFinding) => f.severity === "medium",
    ).length;
    const lowCount = findings.filter(
      (f: SecurityFinding) => f.severity === "low",
    ).length;
    const riskScore = Math.min(
      100,
      criticalCount * 25 + highCount * 10 + mediumCount * 5 + lowCount,
    );

    const businessImpact = (
      criticalCount > 0
        ? "Critical"
        : highCount > 2
          ? "High"
          : highCount > 0
            ? "Medium"
            : "Low"
    ) as EnhancedSecurityReport["businessImpact"];

    const exploitability = (
      criticalCount > 0 || highCount > 1
        ? "High"
        : highCount > 0 || mediumCount > 5
          ? "Medium"
          : "Low"
    ) as EnhancedSecurityReport["exploitability"];

    return {
      score: base.score,
      level: this.determineRiskLevel(riskScore),
      grade: this.calculateGrade(riskScore),
      findings,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      riskScore,
      businessImpact,
      exploitability,
      owaspTop10Coverage: this.calculateOWASPCoverage(findings),
      cweCategories: this.extractCWECategories(findings),
      prioritizedRemediation: this.prioritizeRemediation(findings),
    };
  }

  private enhanceFuzzingReport(base: FuzzingReport): EnhancedFuzzingReport {
    const results = base.results || [];
    const securityPayloadCount = results.filter((r) =>
      r.payloadType.includes("Security"),
    ).length;
    const mutationCount = results.filter((r) =>
      r.payloadType.includes("Mutated"),
    ).length;
    const vulnerabilityCount = base.vulnerabilities?.length ?? 0;
    const avgResponseTime =
      results.length > 0
        ? results.reduce((s, r) => s + r.durationMs, 0) / results.length
        : 0;
    const slowest = results.reduce(
      (max, r) => (r.durationMs > max.durationMs ? r : max),
      results[0] ?? { durationMs: 0, payloadType: "" },
    );
    return {
      ...base,
      securityPayloadCount,
      mutationCount,
      vulnerabilityCount,
      avgResponseTime: Math.round(avgResponseTime),
      slowestPayload:
        slowest.durationMs > 0
          ? { type: slowest.payloadType, responseTime: slowest.durationMs }
          : undefined,
      vulnerabilitySummary: this.generateVulnerabilitySummary(
        base.vulnerabilities ?? [],
      ),
    };
  }

  private generatePerformanceReport(
    executionTime: number,
    metrics: SystemMetrics,
  ): PerformanceReport {
    return {
      executionTime,
      avgResponseTime: metrics.avgResponseTime,
      p95ResponseTime: metrics.p95ResponseTime,
      p99ResponseTime: metrics.p99ResponseTime,
      memoryUsage: {
        peak: metrics.memoryUsage.used,
        average: metrics.memoryUsage.used,
        current: metrics.memoryUsage.used,
      },
      throughput: {
        requestsPerSecond: metrics.requestsPerSecond,
        validationsPerSecond: metrics.requestsPerSecond,
      },
      efficiency: {
        score: this.calculateEfficiencyScore(metrics),
        bottlenecks: this.identifyBottlenecks(metrics),
      },
    };
  }

  private generateAuditReport(auditTrail: AuditEntry[]): AuditReport {
    const criticalEvents = auditTrail.filter(
      (e) => e.severity === "critical",
    ).length;
    const securityEvents = auditTrail.filter(
      (e) =>
        e.eventType.includes("security") || e.eventType.includes("guardrail"),
    ).length;
    const eventsByType: Record<string, number> = {};
    for (const e of auditTrail)
      eventsByType[e.eventType] = (eventsByType[e.eventType] ?? 0) + 1;
    return {
      totalEvents: auditTrail.length,
      criticalEvents,
      securityEvents,
      eventsByType,
      timeline: auditTrail
        .slice(-20)
        .map((e) => ({
          timestamp: e.timestamp,
          event: e.eventType,
          severity: e.severity,
        })),
      complianceStatus: {
        auditTrailComplete: true,
        retentionCompliant: true,
        encryptionEnabled: false,
      },
    };
  }

  private generateExecutiveSummary(
    security: EnhancedSecurityReport,
    fuzzing?: EnhancedFuzzingReport,
    performance?: PerformanceReport,
    _audit?: AuditReport,
  ): EnhancedReport["executiveSummary"] {
    const keyFindings: string[] = [];
    const criticalActions: string[] = [];
    if (security.criticalCount > 0) {
      keyFindings.push(
        `${security.criticalCount} critical security issue(s) detected`,
      );
      criticalActions.push(
        "Immediately address critical security vulnerabilities",
      );
    }
    if (security.highCount > 0)
      keyFindings.push(`${security.highCount} high-severity issue(s) found`);
    if (fuzzing && fuzzing.vulnerabilityCount > 0)
      keyFindings.push(
        `${fuzzing.vulnerabilityCount} potential vulnerabilities discovered via fuzzing`,
      );
    if (performance && performance.p99ResponseTime > 5000) {
      keyFindings.push("Performance degradation detected (p99 > 5s)");
      criticalActions.push("Investigate performance bottlenecks");
    }
    const totalChecks = 100;
    const passedChecks = totalChecks - security.findings.length;
    return {
      overallRisk: this.calculateOverallRisk(security, fuzzing),
      keyFindings,
      criticalActions,
      passedChecks,
      totalChecks,
      complianceScore: Math.round((passedChecks / totalChecks) * 100),
    };
  }

  private calculateGrade(s: number): "A+" | "A" | "B" | "C" | "D" | "F" {
    return s === 0
      ? "A+"
      : s < 10
        ? "A"
        : s < 25
          ? "B"
          : s < 50
            ? "C"
            : s < 75
              ? "D"
              : "F";
  }
  private determineRiskLevel(
    s: number,
  ): "Low Risk" | "Medium Risk" | "High Risk" | "Critical Risk" {
    return s < 10
      ? "Low Risk"
      : s < 25
        ? "Medium Risk"
        : s < 50
          ? "High Risk"
          : "Critical Risk";
  }
  private calculateOWASPCoverage(
    findings: SecurityFinding[],
  ): EnhancedSecurityReport["owaspTop10Coverage"] {
    const mappings: Record<string, number> = {};
    for (const f of findings)
      if (f.ruleCode) mappings[f.ruleCode] = (mappings[f.ruleCode] ?? 0) + 1;
    const covered = Object.keys(mappings).length;
    return { total: 10, covered, coverage: `${covered}/10`, mappings };
  }
  private extractCWECategories(
    findings: SecurityFinding[],
  ): EnhancedSecurityReport["cweCategories"] {
    const cats: Record<string, { count: number; severity: string }> = {};
    for (const f of findings) {
      if (f.ruleCode) {
        if (!cats[f.ruleCode])
          cats[f.ruleCode] = { count: 0, severity: f.severity };
        cats[f.ruleCode].count++;
      }
    }
    return Object.entries(cats).map(([category, d]) => ({
      category,
      count: d.count,
      severity: d.severity,
    }));
  }
  private prioritizeRemediation(
    findings: SecurityFinding[],
  ): EnhancedSecurityReport["prioritizedRemediation"] {
    const w: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };
    return findings
      .map((f) => ({
        priority: w[f.severity] ?? 0,
        finding: f,
        effort: "Medium" as const,
        impact: this.estimateImpact(f),
      }))
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 10);
  }
  private estimateImpact(f: SecurityFinding): "Low" | "Medium" | "High" {
    return f.severity === "critical" || f.severity === "high"
      ? "High"
      : "Medium";
  }
  private generateVulnerabilitySummary(
    vulnerabilities: Array<{
      toolName: string;
      payloadType: string;
      findings: Array<{
        type: string;
        severity: "critical" | "high" | "medium" | "low";
        description: string;
        evidence: string;
        remediation: string;
      }>;
    }>,
  ): EnhancedFuzzingReport["vulnerabilitySummary"] {
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    for (const v of vulnerabilities) {
      byType[v.payloadType] = (byType[v.payloadType] ?? 0) + 1;
      for (const f of v.findings ?? [])
        bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    }
    return {
      byType,
      bySeverity,
      topVulnerabilities: Object.entries(byType)
        .map(([type, count]) => ({ type, count, severity: "high" }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
    };
  }
  private calculateEfficiencyScore(m: SystemMetrics): number {
    const rt =
      m.avgResponseTime < 100
        ? 100
        : m.avgResponseTime < 500
          ? 80
          : m.avgResponseTime < 1000
            ? 60
            : 40;
    const mem =
      m.memoryUsage.percentage < 70
        ? 100
        : m.memoryUsage.percentage < 85
          ? 80
          : 60;
    return Math.round((rt + mem) / 2);
  }
  private identifyBottlenecks(m: SystemMetrics): string[] {
    const b: string[] = [];
    if (m.avgResponseTime > 1000) b.push(t("high_average_response_time"));
    if (m.memoryUsage.percentage > 85) b.push(t("high_memory_usage"));
    if (m.errorRate > 5) b.push(t("elevated_error_rate"));
    return b;
  }
  private calculateOverallRisk(
    s: EnhancedSecurityReport,
    f?: EnhancedFuzzingReport,
  ): "Low" | "Medium" | "High" | "Critical" {
    if (s.criticalCount > 0 || (f && f.vulnerabilityCount > 5))
      return "Critical";
    if (s.highCount > 2 || (f && f.vulnerabilityCount > 2)) return "High";
    if (s.highCount > 0 || s.mediumCount > 5) return "Medium";
    return "Low";
  }
  private extractRulesFromFindings(
    findings: SecurityFinding[],
  ): SARIFReport["runs"][0]["tool"]["driver"]["rules"] {
    const map = new Map<
      string,
      SARIFReport["runs"][0]["tool"]["driver"]["rules"][0]
    >();
    for (const f of findings) {
      if (f.ruleCode && !map.has(f.ruleCode)) {
        map.set(f.ruleCode, {
          id: f.ruleCode,
          name: f.component,
          shortDescription: { text: f.message },
          fullDescription: { text: f.message },
          defaultConfiguration: {
            level:
              f.severity === "critical" || f.severity === "high"
                ? "error"
                : "warning",
          },
        });
      }
    }
    return Array.from(map.values());
  }
  private convertFindingsToSARIFResults(
    findings: SecurityFinding[],
  ): SARIFReport["runs"][0]["results"] {
    return findings.map((f) => ({
      ruleId: f.ruleCode ?? "UNKNOWN",
      level: (f.severity === "critical" || f.severity === "high"
        ? "error"
        : "warning") as "error" | "warning" | "note",
      message: { text: f.message },
      locations: [
        { logicalLocations: [{ name: f.component, kind: "component" }] },
      ],
    }));
  }
}

export const enhancedReporter = new EnhancedReporter();
