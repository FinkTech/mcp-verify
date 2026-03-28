/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Disclaimer Manager
 *
 * Contextual disclaimers for dangerous commands with persistent preferences.
 * First-time warnings for fuzz, stress, and other potentially abusive operations.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { t } from '@mcp-verify/shared';

export type DisclaimerType = 'fuzz' | 'stress' | 'proxy' | 'validate';

interface DisclaimerPreferences {
  dismissed: Set<DisclaimerType>;
  version: string;
}

interface DisclaimerConfig {
  type: DisclaimerType;
  title: string;
  message: string[];
  severity: 'warning' | 'critical';
  allowNever?: boolean; // If false, always show (for critical disclaimers)
}

const DISCLAIMERS: Record<DisclaimerType, DisclaimerConfig> = {
  fuzz: {
    type: 'fuzz',
    title: t('disclaimer_fuzz_title'),
    message: [
      t('disclaimer_fuzz_line1'),
      '',
      t('disclaimer_fuzz_line2'),
      t('disclaimer_fuzz_line3'),
      `  ${t('disclaimer_fuzz_point1')}`,
      `  ${t('disclaimer_fuzz_point2')}`,
      `  ${t('disclaimer_fuzz_point3')}`,
      '',
      chalk.bold.yellow(t('disclaimer_fuzz_warning')),
      '',
      t('disclaimer_fuzz_legal'),
      '',
      chalk.bold.red(t('disclaimer_fuzz_responsibility')),
    ],
    severity: 'critical',
    allowNever: true,
  },

  stress: {
    type: 'stress',
    title: t('disclaimer_stress_title'),
    message: [
      t('disclaimer_stress_line1'),
      '',
      t('disclaimer_stress_line2'),
      t('disclaimer_stress_line3'),
      `  ${t('disclaimer_stress_point1')}`,
      `  ${t('disclaimer_stress_point2')}`,
      `  ${t('disclaimer_stress_point3')}`,
      '',
      chalk.bold.yellow(t('disclaimer_stress_warning')),
      '',
      t('disclaimer_stress_legal'),
      '',
      chalk.bold.red(t('disclaimer_stress_responsibility')),
    ],
    severity: 'critical',
    allowNever: true,
  },

  proxy: {
    type: 'proxy',
    title: t('disclaimer_proxy_title'),
    message: [
      t('disclaimer_proxy_line1'),
      '',
      t('disclaimer_proxy_line2'),
      t('disclaimer_proxy_line3'),
      `  ${t('disclaimer_proxy_point1')}`,
      `  ${t('disclaimer_proxy_point2')}`,
      `  ${t('disclaimer_proxy_point3')}`,
      '',
      chalk.bold.yellow(t('disclaimer_proxy_warning')),
      '',
      t('disclaimer_proxy_legal'),
      '',
      chalk.bold.red(t('disclaimer_proxy_responsibility')),
    ],
    severity: 'warning',
    allowNever: true,
  },

  validate: {
    type: 'validate',
    title: t('disclaimer_validate_title'),
    message: [
      t('disclaimer_validate_line1'),
      '',
      t('disclaimer_validate_line2'),
      t('disclaimer_validate_line3'),
      `  ${t('disclaimer_validate_point1')}`,
      `  ${t('disclaimer_validate_point2')}`,
      `  ${t('disclaimer_validate_point3')}`,
      '',
      chalk.bold.yellow(t('disclaimer_validate_warning')),
      '',
      t('disclaimer_validate_legal'),
      '',
      chalk.bold.red(t('disclaimer_validate_responsibility')),
    ],
    severity: 'warning',
    allowNever: true,
  },
};

async function promptKeypress(message: string, allowNever: boolean): Promise<'yes' | 'no' | 'never'> {
  return new Promise((resolve) => {
    const hint = allowNever ? '(y/n/d=don\'t ask again)' : '(y/n)';
    process.stdout.write(`\n  ? ${chalk.white(message)} ${chalk.dim(hint)} `);

    const prevRawMode = process.stdin.isRaw ?? false;
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    const cleanup = () => {
      process.stdin.removeListener('data', handler);
      process.stdin.setRawMode(prevRawMode);
      process.stdin.pause();
      process.stdout.write('\n');
    };

    const handler = (key: string) => {
      if (key === '\u0003' || key === '\u0004' || key === '\x1b') {
        cleanup();
        resolve('no');
        return;
      }
      
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'y') {
        cleanup();
        resolve('yes');
      } else if (lowerKey === 'n') {
        cleanup();
        resolve('no');
      } else if (allowNever && lowerKey === 'd') {
        cleanup();
        resolve('never');
      } else if (key === '\r' || key === '\n') {
        cleanup();
        resolve('no');
      }
    };
    
    process.stdin.on('data', handler);
  });
}

export class DisclaimerManager {
  private static instance: DisclaimerManager;
  private preferencesPath: string;
  private preferences: DisclaimerPreferences;

  private constructor() {
    const configDir = path.join(os.homedir(), '.mcp-verify');
    this.preferencesPath = path.join(configDir, 'disclaimers.json');

    // Ensure config directory exists
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    this.preferences = this.loadPreferences();
  }

  static getInstance(): DisclaimerManager {
    if (!DisclaimerManager.instance) {
      DisclaimerManager.instance = new DisclaimerManager();
    }
    return DisclaimerManager.instance;
  }

  /**
   * Show disclaimer if not previously dismissed
   * Returns true if user confirmed, false if cancelled
   */
  async showIfNeeded(type: DisclaimerType): Promise<boolean> {
    const config = DISCLAIMERS[type];

    if (!config) {
      throw new Error(`Unknown disclaimer type: ${type}`);
    }

    // SECURITY FIX: Skip prompts in test environments to avoid blocking CI/CD or integration tests
    if (process.env.NODE_ENV === 'test' || process.env.CI) {
      return true;
    }

    // Check if user has dismissed this disclaimer
    if (this.preferences.dismissed.has(type) && config.allowNever !== false) {
      return true; // Already dismissed, proceed
    }

    // Show disclaimer
    console.log('\n' + this.formatDisclaimer(config));

    // Prompt for confirmation
    const { action } = await inquirer.prompt<{ action: 'yes' | 'no' | 'never' }>([
      {
        type: 'expand',
        name: 'action',
        message: t('disclaimer_question'),
        choices: [
          { key: 'y', name: chalk.green(t('disclaimer_action_yes')), value: 'yes' },
          { key: 'n', name: chalk.red(t('disclaimer_action_no')), value: 'no' },
          ...(config.allowNever !== false
            ? [{ key: 'd', name: chalk.gray(t('disclaimer_action_never')), value: 'never' }]
            : []),
        ],
        default: 1, // 'no' is the default and safe option
      },
    ]);

    if (action === 'never') {
      this.dismissPermanently(type);
      return true;
    }

    return action === 'yes';
  }

  /**
   * Force show disclaimer (ignore preferences)
   * Useful for critical operations
   */
  async forceShow(type: DisclaimerType): Promise<boolean> {
    const config = DISCLAIMERS[type];
    console.log('\n' + this.formatDisclaimer(config));

    const { confirmed } = await inquirer.prompt<{ confirmed: boolean }>([
      {
        type: 'confirm',
        name: 'confirmed',
        message: 'Do you understand and accept the risks?',
        default: false,
      },
    ]);

    return confirmed;
  }

  /**
   * Dismiss disclaimer permanently
   */
  dismissPermanently(type: DisclaimerType): void {
    this.preferences.dismissed.add(type);
    this.savePreferences();

    console.log(chalk.gray(`\n✓ ${t('disclaimer_dismissed')}`));
  }

  /**
   * Reset specific disclaimer
   */
  reset(type?: DisclaimerType): void {
    if (type) {
      this.preferences.dismissed.delete(type);
      console.log(chalk.green(`✓ ${t('disclaimer_status_reset_one', { type })}`));
    } else {
      this.preferences.dismissed.clear();
      console.log(chalk.green(`✓ ${t('disclaimer_status_reset_all')}`));
    }
    this.savePreferences();
  }

  /**
   * Show current disclaimer status
   */
  status(): void {
    console.log(chalk.bold(`\n${t('disclaimer_status_title')}:\n`));

    const allTypes: DisclaimerType[] = ['fuzz', 'stress', 'proxy', 'validate'];

    // Header
    console.log(chalk.gray(`  ${t('disclaimer_status_header_type').padEnd(10)} ${t('disclaimer_status_header_status')}`));
    console.log(chalk.gray('  ' + '─'.repeat(40)));

    for (const type of allTypes) {
      const isDismissed = this.preferences.dismissed.has(type);
      const status = isDismissed
        ? chalk.gray(t('disclaimer_status_dismissed'))
        : chalk.green(t('disclaimer_status_active'));
      console.log(`  ${type.padEnd(10)} ${status}`);
    }

    if (this.preferences.dismissed.size === 0) {
      console.log(chalk.gray(`\n${t('disclaimer_status_none')}`));
    } else {
      console.log(chalk.gray(`\n${t('disclaimer_status_footer_one', { type: '<type>' })}`));
      console.log(chalk.gray(t('disclaimer_status_footer_all') + '\n'));
    }
  }

  /**
   * Format disclaimer for display
   */
  private formatDisclaimer(config: DisclaimerConfig): string {
    const borderColor = config.severity === 'critical' ? chalk.red : chalk.yellow;
    const border = borderColor('═'.repeat(70));

    const lines = [
      border,
      borderColor(`║ ${chalk.bold(config.title.toUpperCase()).padEnd(68)} ║`),
      border,
      '',
      ...config.message,
      '',
      border,
    ];

    return lines.join('\n');
  }

  /**
   * Load preferences from disk
   */
  private loadPreferences(): DisclaimerPreferences {
    try {
      if (fs.existsSync(this.preferencesPath)) {
        const data = fs.readFileSync(this.preferencesPath, 'utf-8');
        const parsed = JSON.parse(data);

        return {
          dismissed: new Set(parsed.dismissed || []),
          version: parsed.version || '1.0.0',
        };
      }
    } catch (error) {
      // Ignore errors, use defaults
    }

    return {
      dismissed: new Set(),
      version: '1.0.0',
    };
  }

  /**
   * Save preferences to disk (atomic)
   */
  private savePreferences(): void {
    const tmpPath = this.preferencesPath + '.tmp';

    try {
      const data = {
        dismissed: Array.from(this.preferences.dismissed),
        version: this.preferences.version,
      };

      fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf-8');
      fs.renameSync(tmpPath, this.preferencesPath); // Atomic
    } catch (error) {
      // Cleanup on error
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
      console.error(chalk.red('Failed to save disclaimer preferences:'), error);
    }
  }
}

/**
 * Convenience function for commands
 */
export async function checkDisclaimer(type: DisclaimerType): Promise<boolean> {
  const manager = DisclaimerManager.getInstance();
  return manager.showIfNeeded(type);
}

/**
 * Non-interactive mode: check if disclaimer was previously accepted
 */
export function isDisclaimerAccepted(type: DisclaimerType): boolean {
  const manager = DisclaimerManager.getInstance();
  const preferences = (manager as any).preferences as DisclaimerPreferences;
  return preferences.dismissed.has(type);
}
