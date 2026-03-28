/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Spinner Utilities
 *
 * Centralized spinner configurations and helpers using ora
 */

import ora, { Ora } from 'ora';
import { t } from '@mcp-verify/shared';

/**
 * Create a spinner for validation operations
 */
export function createValidationSpinner(target: string): Ora {
  return ora({
    text: `${t('connecting_server')} ${target}`,
    color: 'cyan'
  }).start();
}

/**
 * Create a spinner for stress testing operations
 */
export function createStressTestSpinner(): Ora {
  return ora({
    text: t('running_security_scan'),
    color: 'yellow'
  }).start();
}

/**
 * Create a spinner for generic loading
 */
export function createLoadingSpinner(text: string): Ora {
  return ora({
    text,
    color: 'cyan'
  }).start();
}

/**
 * Create a spinner for connection attempts
 */
export function createConnectionSpinner(target: string): Ora {
  return ora({
    text: `${t('connecting_to_server')} ${target}`,
    color: 'blue'
  }).start();
}

/**
 * Create a spinner for report generation
 */
export function createReportSpinner(): Ora {
  return ora({
    text: t('generating_report'),
    color: 'magenta'
  }).start();
}
