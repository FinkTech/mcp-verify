/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Prompt Utilities
 *
 * Helpers for interactive user input using readline
 */

import readline from 'readline';
import { t } from '@mcp-verify/shared';

/**
 * Ask a question and get user input
 * @param question Question to display
 * @returns Promise resolving to user's answer
 */
export function askQuestion(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Ask a yes/no question
 * @param question Question to display
 * @returns Promise resolving to true for yes, false for no
 */
export async function askYesNo(question: string): Promise<boolean> {
  const answer = await askQuestion(`${question} (y/n): `);
  return answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';
}

/**
 * Select from multiple options
 * @param question Question to display
 * @param options Array of options
 * @returns Promise resolving to selected option (1-indexed)
 */
export async function selectOption(question: string, options: string[]): Promise<number> {
  console.log(question);
  options.forEach((option, index) => {
    console.log(`  ${index + 1}. ${option}`);
  });

  const answer = await askQuestion(t('select_option'));
  const selection = parseInt(answer, 10);

  if (isNaN(selection) || selection < 1 || selection > options.length) {
    throw new Error(t('invalid_selection'));
  }

  return selection;
}
