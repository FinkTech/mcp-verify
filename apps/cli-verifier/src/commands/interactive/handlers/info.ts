/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Info Command Handlers (Help & About)
 *
 * Extracted from interactive.ts - Section 13
 */

import chalk from 'chalk';
import { t } from '@mcp-verify/shared';

// Version hardcoded for bundle compatibility
const packageJson = { version: '1.0.0' };

export function showHelp(): void {
  const H = (s: string) => chalk.bold.cyan(s);

  console.log(chalk.bold.white(`\n  ${t('interactive_available_commands')}:\n`));

  console.log(H('  Security Tools:'));
  helpRow('validate, v',    '<target> [--output dir]',  t('cmd_validate_desc'));
  helpRow('fuzz, f',        '<target> [--tool name]',   t('cmd_fuzz_desc'));
  helpRow('doctor, d',      '<target>',                 t('cmd_doctor_desc'));
  helpRow('fingerprint',    '<target>',                 t('cmd_fingerprint_desc'));
  helpRow('inspect, ls',    '<target>',                 t('cmd_inspect_desc'));
  helpRow('stress, s',      '<target> [--users N]',     t('cmd_stress_desc'));
  helpRow('dashboard',      '<target> [--port N]',      t('cmd_dashboard_desc'));
  helpRow('play',           '<target> [--port N]',      t('cmd_playground_desc'));
  helpRow('proxy',          '<target> [--port N]',      t('cmd_proxy_desc'));
  helpRow('mock, m',        '[--port N]',               t('cmd_mock_desc'));
  helpRow('init',           '[--dir path]',             t('cmd_init_desc'));
  helpRow('examples, ex',   '',                         t('cmd_examples_desc'));

  console.log(H('\n  Session & Config:'));
  helpRow('target',         '<command|url>',            t('cmd_target_desc'));
  helpRow('set',            'target|lang <value>',      t('interactive_set_target_desc'));
  helpRow('lang, language', '[en|es]',                  t('change_language_cambiar_idioma'));
  helpRow('config, cfg',    '',                         t('interactive_show_config_desc'));
  helpRow('history',        '[--last N] [--clear]',     t('interactive_show_history_desc'));

  console.log(H('\n  Workspace & Profiles:'));
  helpRow('profile',        'set | save | list | show',              t('cmd_profile_desc'));
  helpRow('context',        'list | switch | create | clone | delete', t('cmd_context_desc'));
  helpRow('status',         '',                                       t('cmd_status_desc'));

  console.log(H('\n  Shell:'));
  helpRow('clear, cls',     '',                         t('cmd_clear'));
  helpRow('help, h',        '',                         t('cmd_help'));
  helpRow('exit, q, quit',  '',                         t('cmd_exit'));

  console.log(chalk.bold.white('\n  Output Redirection:\n'));
  console.log(chalk.dim('    cmd [args] > file.txt   ') + chalk.gray('overwrite'));
  console.log(chalk.dim('    cmd [args] >> file.txt  ') + chalk.gray('append'));
  console.log(chalk.dim('    validate > report.txt   ') + chalk.gray('redirect validate output'));

  console.log(chalk.bold.white('\n  Examples:\n'));
  const ex = (s: string) => console.log('    ' + chalk.dim('mcp-verify > ') + chalk.cyan(s));
  ex('target node server.js');
  ex('profile set aggressive');
  ex('validate');
  ex('fuzz "node server.js" --tool "Echo Tool" > fuzz.txt');
  ex('context create staging --copy');
  ex('context switch staging');
  ex('stress http://localhost:3000 --users 20 --duration 60 >> stress.log');
  ex('history --last 10');
  ex('lang es\n');
}

export function helpRow(cmd: string, args: string, desc: string): void {
  const C = 20, A = 40;
  console.log(`    ${chalk.cyan(cmd.padEnd(C))}${chalk.dim(args.padEnd(A))}${desc}`);
}

export function showAbout(): void {
  console.log(chalk.bold.white(`\n  ${t('interactive_about_title')}\n`));
  console.log(`  ${chalk.gray('Version:')}        ${chalk.cyan(packageJson.version)}`);
  console.log(`  ${chalk.gray('License:')}        ${chalk.cyan('AGPL-3.0')}`);
  console.log(`  ${chalk.gray('Maintained by:')}  ${chalk.cyan('Fink')}`);
  console.log(chalk.bold.white(`\n  ${t('md_description')}:\n`));
  console.log(chalk.gray(`  ${t('interactive_about_desc')}`));
  console.log(chalk.bold.white(`\n  ${t('interactive_features')}:\n`));
  [
    t('about_feature_owasp'), t('about_feature_llm'), t('about_feature_protocol'),
    t('about_feature_reports'), t('about_feature_i18n'),
  ].forEach(f => console.log(`    ${chalk.cyan('✓')} ${chalk.gray(f)}`));
  console.log(chalk.bold.white(`\n  ${t('interactive_links')}:\n`));
  console.log(`    ${chalk.gray('GitHub:')}   ${chalk.cyan('github.com/FinkTech/mcp-verify')}`);
  console.log(`    ${chalk.gray('Docs:')}     ${chalk.cyan('github.com/FinkTech/mcp-verify#readme')}`);
  console.log(`    ${chalk.gray('Security:')} ${chalk.cyan('github.com/FinkTech/mcp-verify/blob/main/SECURITY.md')}`);
  console.log(`    ${chalk.gray('Issues:')}   ${chalk.cyan('github.com/FinkTech/mcp-verify/issues')}`);
  console.log(chalk.yellow(`\n  ⚠️  ${t('cli_disclaimer_independent')}\n`));
}
