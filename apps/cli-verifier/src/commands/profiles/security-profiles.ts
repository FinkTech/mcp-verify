/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Security Profile Presets
 *
 * Hardcoded security profiles that control fuzzing intensity and validation strictness
 * Users can switch between presets or create custom profiles
 *
 * Presets:
 * - light: Minimal testing (25 payloads, no mutations, basic detectors)
 * - balanced: Standard testing (50 payloads, 3 mutations, full detection) [DEFAULT]
 * - aggressive: Maximum testing (100 payloads, 5 mutations, maximum sensitivity)
 */

import { SecurityProfile, SecurityProfilePreset } from '../types/workspace-context';

/**
 * Light security profile
 * Use for: Quick sanity checks, CI/CD pipelines, development
 * Trade-off: Fast but may miss edge cases
 * Enabled blocks: OWASP + MCP + Operational (C)
 */
const LIGHT_PROFILE: SecurityProfile = {
  name: 'light',
  isPreset: true,
  enabledBlocks: ['OWASP', 'MCP', 'C'],  // Basic compliance + operational rules
  fuzzing: {
    useMutations: false,
    mutationsPerPayload: 0,
    maxPayloadsPerTool: 25,
    enableFeedbackLoop: false,
  },
  validation: {
    minSecurityScore: 60,
    failOnCritical: true,
    failOnHigh: false,
  },
  generators: {
    enablePromptInjection: true,
    enableClassicPayloads: true,
    enablePrototypePollution: false,
    enableJwtAttacks: false,
  },
  detectors: {
    enableTimingDetection: false,
    timingAnomalyMultiplier: 3.0,
    enableErrorDetection: true,
  },
};

/**
 * Balanced security profile (DEFAULT)
 * Use for: Regular testing, staging environments, balanced coverage
 * Trade-off: Good coverage with reasonable performance
 * Enabled blocks: OWASP + MCP + OWASP LLM (A) + Multi-Agent (B) + Operational (C)
 */
const BALANCED_PROFILE: SecurityProfile = {
  name: 'balanced',
  isPreset: true,
  enabledBlocks: ['OWASP', 'MCP', 'A', 'B', 'C'],  // All except AI Weaponization (D)
  fuzzing: {
    useMutations: true,
    mutationsPerPayload: 3,
    maxPayloadsPerTool: 50,
    enableFeedbackLoop: true,
  },
  validation: {
    minSecurityScore: 70,
    failOnCritical: true,
    failOnHigh: false,
  },
  generators: {
    enablePromptInjection: true,
    enableClassicPayloads: true,
    enablePrototypePollution: true,
    enableJwtAttacks: true,
  },
  detectors: {
    enableTimingDetection: true,
    timingAnomalyMultiplier: 2.5,
    enableErrorDetection: true,
  },
};

/**
 * Aggressive security profile
 * Use for: Pre-production, security audits, penetration testing
 * Trade-off: Maximum coverage but slower execution
 * Enabled blocks: ALL (including AI Weaponization D)
 */
const AGGRESSIVE_PROFILE: SecurityProfile = {
  name: 'aggressive',
  isPreset: true,
  enabledBlocks: ['OWASP', 'MCP', 'A', 'B', 'C', 'D'],  // All blocks including AI Weaponization
  fuzzing: {
    useMutations: true,
    mutationsPerPayload: 5,
    maxPayloadsPerTool: 100,
    enableFeedbackLoop: true,
  },
  validation: {
    minSecurityScore: 90,
    failOnCritical: true,
    failOnHigh: true,
  },
  generators: {
    enablePromptInjection: true,
    enableClassicPayloads: true,
    enablePrototypePollution: true,
    enableJwtAttacks: true,
  },
  detectors: {
    enableTimingDetection: true,
    timingAnomalyMultiplier: 2.5,
    enableErrorDetection: true,
  },
};

/**
 * Map of preset names to profile configurations
 */
export const SECURITY_PROFILES: Readonly<Record<SecurityProfilePreset, SecurityProfile>> = {
  light: LIGHT_PROFILE,
  balanced: BALANCED_PROFILE,
  aggressive: AGGRESSIVE_PROFILE,
};

/**
 * Get a security profile by name (preset or custom)
 *
 * @param name - Profile name ('light', 'balanced', 'aggressive', or custom name)
 * @param customProfiles - Map of user-defined custom profiles
 * @returns Security profile configuration, or balanced if not found
 */
export function getSecurityProfile(
  name: string,
  customProfiles: Record<string, SecurityProfile> = {}
): SecurityProfile {
  // Check if it's a preset
  if (name in SECURITY_PROFILES) {
    return SECURITY_PROFILES[name as SecurityProfilePreset];
  }

  // Check if it's a custom profile
  if (name in customProfiles) {
    return customProfiles[name];
  }

  // Fallback to balanced
  return SECURITY_PROFILES.balanced;
}

/**
 * Get list of all available profile names (presets + custom)
 *
 * @param customProfiles - Map of user-defined custom profiles
 * @returns Array of profile names
 */
export function getAvailableProfiles(
  customProfiles: Record<string, SecurityProfile> = {}
): string[] {
  const presets = Object.keys(SECURITY_PROFILES);
  const custom = Object.keys(customProfiles);
  return [...presets, ...custom];
}

/**
 * Check if a profile name is a hardcoded preset
 *
 * @param name - Profile name to check
 * @returns True if it's a preset (light/balanced/aggressive)
 */
export function isPresetProfile(name: string): boolean {
  return name in SECURITY_PROFILES;
}
