/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Context Clone Command Handler
 *
 * Syntax: context clone <source> <new_name> [--target "new_url"]
 *
 * Clones an existing context with all its configuration (profile, config, language)
 * into a new context. Optionally overrides the target URL/command.
 */

import chalk from 'chalk';
import { t } from '@mcp-verify/shared';
import type { ShellSession } from '../session';
import { ShellParser } from '../parser';

export function handleContextClone(args: string[], session: ShellSession): void {
  // Parse positional arguments and flags
  const positionals = ShellParser.extractPositionals(args);
  const flags = ShellParser.extractFlags(args);

  // Validate arguments
  if (positionals.length < 2) {
    console.log(chalk.red(`  ✗ ${t('context_clone_invalid_syntax')}`));
    console.log(chalk.dim(`  ${t('context_clone_example')}`));
    console.log('');
    return;
  }

  const [sourceName, targetName] = positionals;

  // Extract --target flag override if provided
  const targetOverride = typeof flags['target'] === 'string' ? flags['target'] : undefined;

  // Attempt to clone the context
  const success = session.cloneContext(
    sourceName,
    targetName,
    targetOverride ? { target: targetOverride } : undefined
  );

  if (!success) {
    // Check which validation failed
    if (!(sourceName in session.state.contexts)) {
      console.log(chalk.red(`  ✗ ${t('context_clone_source_not_exist', { source: chalk.white(sourceName) })}`));
      console.log(chalk.dim(`  ${t('context_clone_available_contexts')}: ${Object.keys(session.state.contexts).join(', ')}`));
    } else if (targetName in session.state.contexts) {
      console.log(chalk.red(`  ✗ ${t('context_clone_target_exists', { target: chalk.white(targetName) })}`));
      console.log(chalk.dim(`  ${t('context_clone_choose_different')}`));
    } else {
      console.log(chalk.red(`  ✗ ${t('context_clone_failed', { source: sourceName, target: targetName })}`));
    }
    console.log('');
    return;
  }

  // Success feedback
  console.log(chalk.green(`  ✓ ${t('context_clone_success')}: ${chalk.white(sourceName)} → ${chalk.white(targetName)}`));

  // Show what was cloned
  const clonedContext = session.state.contexts[targetName];
  console.log(chalk.dim(`  ${t('context_clone_config_title')}`));
  console.log(`    ${chalk.gray(t('context_clone_target_label'))}   ${clonedContext.target ?? chalk.dim('(not set)')}`);
  console.log(`    ${chalk.gray(t('context_clone_language_label'))} ${chalk.cyan(clonedContext.lang)}`);
  console.log(`    ${chalk.gray(t('context_clone_profile_label'))}  ${chalk.cyan(clonedContext.profile.name)}`);

  if (targetOverride) {
    console.log(chalk.yellow(`  ⚠️  ${t('context_clone_target_overridden')}: ${chalk.white(targetOverride)}`));
  }

  console.log(chalk.dim(`\n  ${t('context_clone_switch_hint')}: ${chalk.white(`context switch ${targetName}`)}\n`));
}
