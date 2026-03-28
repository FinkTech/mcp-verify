/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Git Info Utility
 *
 * Captures git repository information for SARIF versionControlProvenance.
 * This enables GitHub Code Scanning to map findings to source code.
 */

import { execSync } from 'child_process';

export interface GitInfo {
  /** Repository URL (e.g., https://github.com/org/repo) */
  repositoryUri: string;
  /** Current commit SHA */
  revisionId: string;
  /** Current branch name */
  branch: string;
}

/**
 * Execute a git command and return the output
 * Returns null if the command fails
 */
function execGit(command: string, cwd?: string): string | null {
  try {
    const result = execSync(command, {
      cwd: cwd || process.cwd(),
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'], // Suppress stderr
      timeout: 5000 // 5 second timeout
    });
    return result.trim();
  } catch {
    return null;
  }
}

/**
 * Normalize git remote URL to HTTPS format
 * Converts SSH URLs (git@github.com:org/repo.git) to HTTPS
 */
function normalizeGitUrl(url: string): string {
  // Remove trailing .git
  let normalized = url.replace(/\.git$/, '');

  // Convert SSH to HTTPS: git@github.com:org/repo -> https://github.com/org/repo
  const sshMatch = normalized.match(/^git@([^:]+):(.+)$/);
  if (sshMatch) {
    normalized = `https://${sshMatch[1]}/${sshMatch[2]}`;
  }

  return normalized;
}

/**
 * Capture git repository information
 * Returns null if not in a git repository or git is not available
 *
 * @param cwd - Working directory (defaults to process.cwd())
 */
export function captureGitInfo(cwd?: string): GitInfo | null {
  // Check if we're in a git repository
  const isGitRepo = execGit('git rev-parse --is-inside-work-tree', cwd);
  if (isGitRepo !== 'true') {
    return null;
  }

  // Get repository URL
  const remoteUrl = execGit('git config --get remote.origin.url', cwd);
  if (!remoteUrl) {
    return null; // No remote configured
  }

  // Get current commit SHA
  const commitSha = execGit('git rev-parse HEAD', cwd);
  if (!commitSha) {
    return null;
  }

  // Get current branch name
  const branch = execGit('git rev-parse --abbrev-ref HEAD', cwd);
  if (!branch) {
    return null;
  }

  return {
    repositoryUri: normalizeGitUrl(remoteUrl),
    revisionId: commitSha,
    branch
  };
}

/**
 * Check if current directory is a git repository
 */
export function isGitRepository(cwd?: string): boolean {
  const result = execGit('git rev-parse --is-inside-work-tree', cwd);
  return result === 'true';
}
