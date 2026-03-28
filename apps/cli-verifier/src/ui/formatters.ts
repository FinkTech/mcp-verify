/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Output Formatters
 *
 * Functions for formatting validation reports, errors, and status messages
 */

import chalk from 'chalk';
import { t } from '@mcp-verify/shared';
import { Report } from '@mcp-verify/core';

/**
 * Display validation report summary in the terminal
 */
export function displayReportSummary(
  report: Report,
  reportPath: string,
  mdReportPath: string,
  htmlReportPath?: string
): void {
  // Status indicator
  if (report.status === 'valid') {
    console.log(chalk.bgGreen.white.bold(`  ✅ ${t('status_valid').toUpperCase()}  `));
  } else {
    console.log(chalk.bgRed.white.bold(`  ❌ ${t('status_invalid').toUpperCase()}  `));
  }

  // Fuzzing results
  if (report.fuzzing) {
    console.log(chalk.bold(`\n${t('fuzzing_label')}:`));
    console.log(`  ${t('tests_label')}: ${report.fuzzing.totalTests}`);
    if (report.fuzzing.crashes > 0) {
      console.log(chalk.bgRed.white.bold(`  ${t('crashes_detected')}: ${report.fuzzing.crashes}  `));
    } else if (report.fuzzing.failedTests > 0) {
      console.log(chalk.yellow(`  ${t('failures_label')}: ${report.fuzzing.failedTests}`));
    } else {
      console.log(chalk.green(`  ${t('all_tests_passed_label')}`));
    }
  }

  console.log(`${t('duration_ms')}: ${report.duration_ms}ms`);

  // Security Audit
  console.log(chalk.bold('\n' + t('security_audit') + ':'));
  let scoreColor = chalk.green;
  if (report.security.score < 70) scoreColor = chalk.red;
  else if (report.security.score < 90) scoreColor = chalk.yellow;

  console.log(`${t('score')}: ${scoreColor(report.security.score + '/100')} (${scoreColor(report.security.level)})`);

  if (report.badges) {
    console.log(`${t('badge')}: ${chalk.blue(report.badges.url)}`);
  }

  if (report.security.findings.length > 0) {
    report.security.findings.forEach(finding => {
      let severityColor = chalk.white;
      if (finding.severity === 'critical') severityColor = chalk.red.bold;
      if (finding.severity === 'high') severityColor = chalk.red;
      if (finding.severity === 'medium') severityColor = chalk.yellow;
      console.log(`  • [${severityColor(finding.severity.toUpperCase())}] ${finding.message}`);
    });
  }

  console.log(chalk.gray('─'.repeat(50)));
  console.log(`${t('json_label')}: ${chalk.cyan(reportPath)}`);
  console.log(`${chalk.bold(t('markdown_label'))}: ${chalk.magenta(mdReportPath)}`);
  if (htmlReportPath) console.log(`${t('html_label')}: ${chalk.blue(htmlReportPath)}`);
  console.log('');
}

/**
 * Display validation error with helpful suggestions
 */
export function displayValidationError(error: unknown, target: string): void {
  console.log('');
  console.error(chalk.red.bold('❌ ' + t('validation_failed') + '\n'));
  console.error(chalk.red(t('error') + ': ') + (error instanceof Error ? error.message : String(error)));
  console.log('');
  console.log(chalk.yellow.bold('💡 ' + t('common_solutions') + ':\n'));

  const errorMsg = String(error instanceof Error ? error.message : error).toLowerCase();

  if (errorMsg.includes('econnrefused') || errorMsg.includes('connection refused')) {
    console.log(chalk.gray('• ') + t('server_not_running'));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_check_process')));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_verify_port') + '\n'));
  } else if (errorMsg.includes('timeout')) {
    console.log(chalk.gray('• ') + t('server_slow'));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_increase_timeout')));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_check_logs') + '\n'));
  } else if (errorMsg.includes('enotfound') || errorMsg.includes('dns')) {
    console.log(chalk.gray('• ') + t('dns_error'));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_check_spelling')));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_ping_hostname') + '\n'));
  } else if (errorMsg.includes('parse') || errorMsg.includes('json')) {
    console.log(chalk.gray('• ') + t('invalid_json'));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_check_implementation')));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_use_verbose_raw') + '\n'));
  } else {
    console.log(chalk.gray('• ') + t('unexpected_error'));
    console.log(chalk.dim('  ' + t('try_prefix') + ' ' + t('tip_verbose')));
    console.log(chalk.dim('  ' + t('try_prefix') + ' mcp-verify doctor ' + target + '\n'));
  }

  console.log(chalk.bold('🔍 ' + t('need_help') + ''));
  console.log(chalk.gray('   ' + t('label_run') + ' ') + chalk.cyan('mcp-verify doctor ' + target));
  console.log(chalk.gray('   ' + t('label_docs') + ' ') + chalk.cyan('mcp-verify examples'));
  console.log(chalk.gray('   ' + t('label_issues') + ' ') + chalk.cyan('https://github.com/FinkTech/mcp-verify/issues\n'));
}

/**
 * Get color for severity level
 */
export function getSeverityColor(severity: string): typeof chalk {
  if (severity === 'critical') return chalk.red.bold;
  if (severity === 'high') return chalk.red;
  if (severity === 'medium') return chalk.yellow;
  return chalk.white;
}

/**
 * Get color for security score
 */
export function getScoreColor(score: number): typeof chalk {
  if (score < 70) return chalk.red;
  if (score < 90) return chalk.yellow;
  return chalk.green;
}
