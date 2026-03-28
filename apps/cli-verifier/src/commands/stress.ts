/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Stress Test Command
 *
 * Load testing for MCP servers with concurrent requests
 */

import ora from 'ora';
import chalk from 'chalk';
import { StressTester } from '@mcp-verify/core/use-cases/stress-tester/stress-tester';
import { t, getCurrentLanguage } from '@mcp-verify/shared';
import { drawAsciiChart } from '../ui/charts';
import { detectTransportType } from '../utils/transport-factory';
import { configureLogging } from '../utils/logging-helper';
import { registerCleanup } from '../utils/cleanup-handlers';

export async function runStressAction(target: string, options: Record<string, unknown>) {
  // Check disclaimer before proceeding
  const { checkDisclaimer } = await import('../utils/disclaimer-manager.js');
  const accepted = await checkDisclaimer('stress');

  if (!accepted) {
    console.log(chalk.yellow(t('disclaimer_aborted')));
    process.exit(0);
  }

  const spinner = ora(t('starting_stress_test')).start();
  let stressTester: StressTester | null = null;

  // Configure logging based on verbose flag
  configureLogging(Boolean(options.verbose));

  try {
    // Determine transport type
    const transportType = (options.transport as 'http' | 'stdio' | undefined) || detectTransportType(target);

    stressTester = new StressTester(target, transportType as 'stdio' | 'http', getCurrentLanguage());

    // Register cleanup handler
    registerCleanup(async () => {
      // StressTester closes transports automatically in finally blocks
      if (stressTester) {
        // No cleanup needed - transports are closed automatically
      }
    });

    spinner.text = `${t('simulating_load')}: ${options.users} ${t('clients_for')} ${options.duration}s...`;

    const result = await stressTester.run({
      concurrentClients: parseInt(String(options.users || '5')),
      durationSeconds: parseInt(String(options.duration || '10')),
      endpoints: ['initialize', 'tools/list', 'resources/list']
    });

    spinner.succeed(t('stress_test_complete'));

    // --- CLI Report ---
    console.log('\n' + chalk.bold(t('performance_report') + ':'));
    console.log(chalk.gray('─'.repeat(50)));
    console.log(`${t('total_requests')}: ${chalk.cyan(result.summary.totalRequests)}`);
    console.log(`${t('success_rate')}:   ${result.summary.successfulRequests === result.summary.totalRequests ? chalk.green('100%') : chalk.yellow(((result.summary.successfulRequests / result.summary.totalRequests) * 100).toFixed(1) + '%')}`);
    console.log(`${t('throughput')}:     ${chalk.bold(result.summary.requestsPerSecond)} ${t('req_sec')}`);
    console.log(`${t('latency_avg')}:  ${result.summary.avgLatencyMs} ms`);
    console.log(`${t('latency_p95')}:  ${result.summary.p95LatencyMs} ms`);
    console.log(`${t('latency_max')}:  ${result.summary.maxLatencyMs} ms`);

    // ASCII Chart
    if (result.metrics && result.metrics.length > 0) {
      const latencies = result.metrics.map(m => m.durationMs);
      console.log(drawAsciiChart(latencies, t('latency_distribution')));
    }

    // Resource warnings
    if (result.resourceWarnings && result.resourceWarnings.length > 0) {
      console.log(chalk.bold.yellow(`\n⚠️  ${t('resource_warnings_label') || 'Resource Warnings'}:`));
      result.resourceWarnings.forEach(warning => {
        console.log(chalk.yellow(`  • ${warning}`));
      });
    }

    // Errors
    if (result.errors.length > 0) {
      console.log(chalk.bold('\n' + t('errors_encountered') + ':'));
      result.errors.forEach(e => {
        console.log(chalk.red(`  • ${e.message} (x${e.count})`));
      });
    }
    console.log(chalk.gray('─'.repeat(50)));
    console.log('');

  } catch (error) {
    spinner.fail(t('stress_test_failed_msg'));
    console.log('');
    console.error(chalk.red.bold('❌ ' + t('stress_test_error') + '\n'));
    console.error(chalk.red(t('error') + ': ') + (error instanceof Error ? error.message : String(error)));
    console.log('');
    console.log(chalk.yellow.bold('💡 ' + t('suggestions') + ':\n'));
    console.log(chalk.gray('• ') + t('reduce_users'));
    console.log(chalk.gray('• ') + t('shorten_duration'));
    console.log(chalk.gray('• ') + t('check_server_load'));
    console.log(chalk.gray('• ') + t('run_basic_validation') + ': mcp-verify validate ' + target);
    console.log('');
  }
}
