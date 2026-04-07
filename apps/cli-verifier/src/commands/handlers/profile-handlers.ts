/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Profile Command Handlers
 *
 * Handlers for security profile commands:
 * - profile set <name>: Switch to a profile
 * - profile save <name>: Save current profile as custom
 * - profile list: List all available profiles
 * - profile show: Show current profile details
 */

import chalk from "chalk";
import { t } from "@mcp-verify/shared";
import type { ShellSession } from "../interactive/session";
import {
  SECURITY_PROFILES,
  getAvailableProfiles,
  isPresetProfile,
} from "../profiles/security-profiles";

/**
 * Main profile command dispatcher
 *
 * @param args - Command arguments [subcommand, ...args]
 * @param session - Shell session
 */
export function handleProfileCommand(
  args: string[],
  session: ShellSession,
): void {
  if (args.length === 0) {
    showProfileHelp();
    return;
  }

  const [subcommand, ...rest] = args;

  switch (subcommand) {
    case "set":
      setProfile(rest, session);
      break;

    case "save":
      saveProfile(rest, session);
      break;

    case "list":
      listProfiles(session);
      break;

    case "show":
      showCurrentProfile(session);
      break;

    default:
      console.log(chalk.red(`✗ Unknown profile subcommand: ${subcommand}`));
      showProfileHelp();
  }
}

/**
 * Switch to a security profile
 *
 * @param args - Arguments [profile-name]
 * @param session - Shell session
 */
function setProfile(args: string[], session: ShellSession): void {
  if (args.length === 0) {
    console.log(chalk.red("✗ Error: Profile name required"));
    console.log(chalk.dim("  Usage: profile set <name>"));
    console.log(
      chalk.dim("  Available: light, balanced, aggressive, or custom profiles"),
    );
    return;
  }

  const profileName = args[0];
  const availableProfiles = getAvailableProfiles(
    session.state.globalConfig.customProfiles,
  );

  // Check if profile exists
  if (!availableProfiles.includes(profileName)) {
    console.log(chalk.red(`✗ Profile not found: ${profileName}`));
    console.log(chalk.dim('  Use "profile list" to see available profiles'));
    return;
  }

  // Set the profile
  session.setProfile(profileName);

  const isPreset = isPresetProfile(profileName);
  const typeLabel = isPreset ? chalk.dim("(preset)") : chalk.dim("(custom)");

  console.log(
    chalk.green(
      `✓ Switched to profile: ${chalk.bold(profileName)} ${typeLabel}`,
    ),
  );
  console.log(chalk.dim(`  Context: ${session.state.activeContextName}`));
}

/**
 * Save current profile as a custom profile
 *
 * @param args - Arguments [profile-name]
 * @param session - Shell session
 */
function saveProfile(args: string[], session: ShellSession): void {
  if (args.length === 0) {
    console.log(chalk.red("✗ Error: Profile name required"));
    console.log(chalk.dim("  Usage: profile save <name>"));
    return;
  }

  const profileName = args[0];

  // Check if trying to overwrite a preset
  if (isPresetProfile(profileName)) {
    console.log(chalk.red("✗ Cannot overwrite preset profile"));
    console.log(chalk.dim("  Preset profiles: light, balanced, aggressive"));
    console.log(chalk.dim("  Choose a different name for your custom profile"));
    return;
  }

  // Save the profile
  session.saveCustomProfile(profileName);

  console.log(
    chalk.green(`✓ Saved custom profile: ${chalk.bold(profileName)}`),
  );
  console.log(
    chalk.dim(
      "  Based on current settings in context: " +
        session.state.activeContextName,
    ),
  );
  console.log(
    chalk.dim('  Use "profile set ' + profileName + '" to switch to it'),
  );
}

/**
 * List all available profiles (presets + custom)
 *
 * @param session - Shell session
 */
function listProfiles(session: ShellSession): void {
  const customProfiles = session.state.globalConfig.customProfiles;
  const availableProfiles = getAvailableProfiles(customProfiles);
  const currentProfile = session.getActiveContext().profile.name;

  console.log(chalk.bold.white("\n  Available Profiles:\n"));

  // Preset profiles
  console.log(chalk.dim("  Presets:"));
  for (const name of Object.keys(SECURITY_PROFILES)) {
    const profile = SECURITY_PROFILES[name as keyof typeof SECURITY_PROFILES];
    const isCurrent = name === currentProfile;
    const marker = isCurrent ? chalk.green("●") : chalk.dim("○");
    const nameDisplay = isCurrent
      ? chalk.green.bold(name.padEnd(12))
      : chalk.cyan(name.padEnd(12));

    const maxPayloads = profile.fuzzing.maxPayloadsPerTool;
    const mutations = profile.fuzzing.mutationsPerPayload;
    const stats = chalk.dim(`${maxPayloads} payloads, ${mutations} mutations`);

    console.log(`    ${marker} ${nameDisplay}  ${stats}`);
  }

  // Custom profiles (if any)
  const customProfileNames = Object.keys(customProfiles);
  if (customProfileNames.length > 0) {
    console.log(chalk.dim("\n  Custom:"));
    for (const name of customProfileNames.sort()) {
      const isCurrent = name === currentProfile;
      const marker = isCurrent ? chalk.green("●") : chalk.dim("○");
      const nameDisplay = isCurrent
        ? chalk.green.bold(name.padEnd(12))
        : chalk.cyan(name.padEnd(12));

      console.log(
        `    ${marker} ${nameDisplay}  ${chalk.dim("(user-defined)")}`,
      );
    }
  }

  console.log(); // Empty line at end
}

/**
 * Show details of the current profile
 *
 * @param session - Shell session
 */
function showCurrentProfile(session: ShellSession): void {
  const context = session.getActiveContext();
  const profile = context.profile;

  console.log(chalk.bold.white(`\n  Profile: ${chalk.yellow(profile.name)}\n`));

  const typeLabel = profile.isPreset
    ? chalk.dim("Preset")
    : chalk.dim("Custom");
  console.log(`  Type: ${typeLabel}`);
  console.log(`  Context: ${chalk.cyan(session.state.activeContextName)}\n`);

  // Fuzzing settings
  console.log(chalk.bold("  Fuzzing:"));
  console.log(`    Max Payloads:       ${profile.fuzzing.maxPayloadsPerTool}`);
  console.log(
    `    Mutations:          ${profile.fuzzing.useMutations ? profile.fuzzing.mutationsPerPayload : "disabled"}`,
  );
  console.log(
    `    Feedback Loop:      ${profile.fuzzing.enableFeedbackLoop ? "enabled" : "disabled"}`,
  );

  // Validation settings
  console.log(chalk.bold("\n  Validation:"));
  console.log(`    Min Security Score: ${profile.validation.minSecurityScore}`);
  console.log(
    `    Fail on Critical:   ${profile.validation.failOnCritical ? "yes" : "no"}`,
  );
  console.log(
    `    Fail on High:       ${profile.validation.failOnHigh ? "yes" : "no"}`,
  );

  // Generators
  console.log(chalk.bold("\n  Generators:"));
  console.log(
    `    Prompt Injection:   ${profile.generators.enablePromptInjection ? "enabled" : "disabled"}`,
  );
  console.log(
    `    Classic Payloads:   ${profile.generators.enableClassicPayloads ? "enabled" : "disabled"}`,
  );
  console.log(
    `    Prototype Pollution: ${profile.generators.enablePrototypePollution ? "enabled" : "disabled"}`,
  );
  console.log(
    `    JWT Attacks:        ${profile.generators.enableJwtAttacks ? "enabled" : "disabled"}`,
  );

  // Detectors
  console.log(chalk.bold("\n  Detectors:"));
  console.log(
    `    Timing Detection:   ${profile.detectors.enableTimingDetection ? "enabled" : "disabled"}`,
  );
  if (profile.detectors.enableTimingDetection) {
    console.log(
      `    Timing Multiplier:  ${profile.detectors.timingAnomalyMultiplier}x`,
    );
  }
  console.log(
    `    Error Detection:    ${profile.detectors.enableErrorDetection ? "enabled" : "disabled"}`,
  );

  console.log(); // Empty line at end
}

/**
 * Show help for profile commands
 */
function showProfileHelp(): void {
  console.log(chalk.bold.white(`\n  ${t("profile_help_title")}\n`));
  console.log(
    `    ${chalk.cyan("profile set <name>")}      ${t("profile_help_set")}`,
  );
  console.log(
    `    ${chalk.cyan("profile save <name>")}     ${t("profile_help_save")}`,
  );
  console.log(
    `    ${chalk.cyan("profile list")}            ${t("profile_help_list")}`,
  );
  console.log(
    `    ${chalk.cyan("profile show")}            ${t("profile_help_show")}\n`,
  );
}
