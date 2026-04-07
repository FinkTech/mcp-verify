/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { t } from "@mcp-verify/shared";
import type { Report } from "../mcp-server/entities/validation.types";
import type { ScanHistory, StorageConfig } from "./types";

/**
 * Manages scan history storage and retrieval
 */
export class ScanHistoryManager {
  private baseDir: string;
  private maxScans: number;

  constructor(config: StorageConfig = {}) {
    this.baseDir = config.baseDir || ".mcp-verify/history";
    this.maxScans = config.maxScans || 100;
    this.ensureDirectoryExists();
  }

  /**
   * Ensure the history directory exists
   */
  private ensureDirectoryExists(): void {
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true });
    }
  }

  /**
   * Generate a unique scan ID
   */
  private generateScanId(): string {
    const timestamp = new Date()
      .toISOString()
      .replace(/[:.]/g, "-")
      .slice(0, -5);
    const random = Math.random().toString(36).substring(2, 8);
    return `scan_${timestamp}_${random}`;
  }

  /**
   * Validate scan ID to prevent path traversal attacks
   * Only allows alphanumeric characters, underscores, and hyphens
   */
  private validateScanId(scanId: string): void {
    const validPattern = /^[a-zA-Z0-9_-]+$/;
    if (!validPattern.test(scanId)) {
      throw new Error(
        `Invalid scan ID: ${scanId}. Only alphanumeric characters, underscores, and hyphens are allowed.`,
      );
    }
  }

  /**
   * Get git information if available
   */
  private getGitInfo(): { commit?: string; branch?: string } {
    try {
      const commit = execSync("git rev-parse HEAD", {
        encoding: "utf-8",
        timeout: 5000, // 5 seconds timeout to prevent hang
        windowsHide: true, // Hide console window on Windows
      }).trim();

      const branch = execSync("git rev-parse --abbrev-ref HEAD", {
        encoding: "utf-8",
        timeout: 5000, // 5 seconds timeout to prevent hang
        windowsHide: true,
      }).trim();

      return { commit, branch };
    } catch {
      // Not a git repo, git not available, or timeout exceeded
      return {};
    }
  }

  /**
   * Save a scan to history
   */
  async saveScan(
    report: Report,
    options: { baseline?: boolean; version?: string } = {},
  ): Promise<ScanHistory> {
    const scanId = this.generateScanId();
    const gitInfo = this.getGitInfo();

    const scanHistory: ScanHistory = {
      scan_id: scanId,
      timestamp: new Date().toISOString(),
      server_name: report.server_name,
      version: options.version || "unknown",
      security_score: report.security.score,
      quality_score: report.quality ? report.quality.score : 0,
      protocol_score: report.protocolCompliance
        ? report.protocolCompliance.score
        : 100,
      total_findings: report.security.findings.length,
      critical_count: report.security.criticalCount || 0,
      high_count: report.security.highCount || 0,
      medium_count: report.security.mediumCount || 0,
      low_count: report.security.lowCount || 0,
      baseline: options.baseline || false,
      git_commit: gitInfo.commit,
      git_branch: gitInfo.branch,
      report,
    };

    // Save to disk
    const filePath = path.join(this.baseDir, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify(scanHistory, null, 2), "utf-8");

    // Clean up old scans if needed
    await this.cleanupOldScans();

    return scanHistory;
  }

  /**
   * Load a specific scan by ID
   */
  async loadScan(scanId: string): Promise<ScanHistory | null> {
    this.validateScanId(scanId);
    const filePath = path.join(this.baseDir, `${scanId}.json`);

    if (!fs.existsSync(filePath)) {
      return null;
    }

    try {
      const content = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(content) as ScanHistory;
    } catch (error) {
      throw new Error(
        t("failed_parse_scan_file", {
          id: scanId,
          error: (error as Error).message,
        }),
      );
    }
  }

  /**
   * List all scans (sorted by timestamp, newest first)
   */
  async listScans(
    options: { serverName?: string; limit?: number } = {},
  ): Promise<ScanHistory[]> {
    const files = fs
      .readdirSync(this.baseDir)
      .filter((f) => f.endsWith(".json"));

    const scans: ScanHistory[] = [];

    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(this.baseDir, file), "utf-8");
        const scan = JSON.parse(content) as ScanHistory;

        // Filter by server name if specified
        if (options.serverName && scan.server_name !== options.serverName) {
          continue;
        }

        scans.push(scan);
      } catch (error) {
        // Skip corrupted scan files
        console.warn(
          t("failed_parse_scan_file", {
            id: file,
            error: (error as Error).message,
          }),
        );
        continue;
      }
    }

    // Sort by timestamp (newest first)
    scans.sort(
      (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );

    // Limit results if specified
    if (options.limit) {
      return scans.slice(0, options.limit);
    }

    return scans;
  }

  /**
   * Get the baseline scan for a server
   */
  async getBaseline(serverName: string): Promise<ScanHistory | null> {
    const scans = await this.listScans({ serverName });
    return scans.find((s) => s.baseline) || null;
  }

  /**
   * Get the latest scan for a server
   */
  async getLatestScan(serverName: string): Promise<ScanHistory | null> {
    const scans = await this.listScans({ serverName, limit: 1 });
    return scans[0] || null;
  }

  /**
   * Mark a scan as baseline (and unmark others for the same server)
   */
  async setBaseline(scanId: string): Promise<void> {
    this.validateScanId(scanId);
    const scan = await this.loadScan(scanId);
    if (!scan) {
      throw new Error(t("scan_not_found", { id: scanId }));
    }

    // Unmark all baselines for this server
    const allScans = await this.listScans({ serverName: scan.server_name });
    for (const s of allScans) {
      if (s.baseline && s.scan_id !== scanId) {
        // Validate scan_id before using it in file path (prevent path traversal)
        this.validateScanId(s.scan_id);
        s.baseline = false;
        const filePath = path.join(this.baseDir, `${s.scan_id}.json`);
        fs.writeFileSync(filePath, JSON.stringify(s, null, 2), "utf-8");
      }
    }

    // Mark this scan as baseline
    scan.baseline = true;
    const filePath = path.join(this.baseDir, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify(scan, null, 2), "utf-8");
  }

  /**
   * Delete old scans if exceeding maxScans limit
   */
  private async cleanupOldScans(): Promise<void> {
    const scans = await this.listScans();

    if (scans.length <= this.maxScans) {
      return;
    }

    // Keep newest maxScans, delete the rest (but preserve baselines)
    const toDelete = scans.slice(this.maxScans).filter((s) => !s.baseline);

    for (const scan of toDelete) {
      // Validate scan_id before using it in file path (prevent path traversal)
      this.validateScanId(scan.scan_id);
      const filePath = path.join(this.baseDir, `${scan.scan_id}.json`);
      fs.unlinkSync(filePath);
    }
  }

  /**
   * Delete a specific scan
   */
  async deleteScan(scanId: string): Promise<void> {
    this.validateScanId(scanId);
    const filePath = path.join(this.baseDir, `${scanId}.json`);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  /**
   * Clear all scan history
   */
  async clearAll(): Promise<void> {
    const files = fs
      .readdirSync(this.baseDir)
      .filter((f) => f.endsWith(".json"));
    for (const file of files) {
      fs.unlinkSync(path.join(this.baseDir, file));
    }
  }

  /**
   * Get scan history statistics
   */
  async getStats(): Promise<{
    total_scans: number;
    servers: number;
    baselines: number;
    oldest_scan: string;
    newest_scan: string;
  }> {
    const scans = await this.listScans();

    if (scans.length === 0) {
      return {
        total_scans: 0,
        servers: 0,
        baselines: 0,
        oldest_scan: "N/A",
        newest_scan: "N/A",
      };
    }

    const servers = new Set(scans.map((s) => s.server_name));
    const baselines = scans.filter((s) => s.baseline).length;
    const oldest = scans[scans.length - 1];
    const newest = scans[0];

    return {
      total_scans: scans.length,
      servers: servers.size,
      baselines,
      oldest_scan: oldest.timestamp,
      newest_scan: newest.timestamp,
    };
  }
}
