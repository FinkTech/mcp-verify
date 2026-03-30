/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */

import chalk from 'chalk';
import { t }  from '@mcp-verify/shared';
import {
  HELP_COMMANDS,
  CATEGORY_TITLE_KEYS,
  HelpCategory,
  HelpCommand,
} from './help-data';
import type { ShellSession } from './session';

const CATEGORY_ORDER: HelpCategory[] = ['security', 'infra', 'workspace', 'utils'];

const CATEGORY_ALIASES: Record<string, HelpCategory> = {
  security:  'security', sec: 'security', s: 'security',
  infra:     'infra',    inf: 'infra',    i: 'infra',
  workspace: 'workspace',ws:  'workspace',w: 'workspace',
  utils:     'utils',    util:'utils',    u: 'utils',
};

const BOX_W = 60;

// Utilidad robusta para calcular longitud visual sin romper por ANSI
function vlen(s: string): number {
  return s.replace(/\x1b\[[0-9;]*m/g, '').length;
}

function printHeader(session: ShellSession): string[] {
  const lines: string[] = [];
  const ctx         = session.getActiveContext();
  const profile     = ctx.profile?.name ?? 'default';
  const lang        = session.state.lang ?? 'en';
  const contextName = session.state.activeContextName ?? 'default';
  const targetRaw   = ctx.target;
  const targetStr   = targetRaw
    ? (targetRaw.length > 38 ? '…' + targetRaw.slice(-36) : targetRaw)
    : t('interactive_not_set');

  const hbar = '─'.repeat(BOX_W);
  const labelWidth = 14;

  function row(labelKey: string, coloredValue: string, rawValue: string): string {
    const labelText = t(labelKey as Parameters<typeof t>[0]).replace(/:$/, '');
    const coloredLabel = chalk.dim(labelText);

    const visibleLabel = vlen(labelText);
    const labelPad = Math.max(0, labelWidth - visibleLabel);
    const paddedLabel = coloredLabel + ' '.repeat(labelPad);

    const content = `  ${paddedLabel} ${coloredValue}`;
    const visibleContent = 2 + labelWidth + 1 + vlen(rawValue);
    const rightPad = Math.max(0, BOX_W - visibleContent);

    return chalk.dim.cyan('│') + content + ' '.repeat(rightPad) + chalk.dim.cyan('│');
  }

  lines.push('');
  lines.push(chalk.dim.cyan(`╭${hbar}╮`));

  const titleContent = chalk.bold.cyan(t('interactive_shell')) + chalk.dim('  ·  ') + chalk.dim(t('interactive_available_commands'));
  const titleVisible = vlen(t('interactive_shell')) + 5 + vlen(t('interactive_available_commands'));
  const titlePad = Math.max(0, BOX_W - 2 - titleVisible);
  lines.push(chalk.dim.cyan('│') + `  ${titleContent}` + ' '.repeat(titlePad) + chalk.dim.cyan('│'));

  lines.push(chalk.dim.cyan(`├${hbar}┤`));
  lines.push(row('interactive_target', chalk.white(targetStr), targetStr));
  lines.push(row('interactive_using_profile', chalk.cyan(profile), profile));
  lines.push(row('interactive_language', chalk.white(lang), lang));
  lines.push(row('interactive_workspace', chalk.white(contextName), contextName));
  lines.push(chalk.dim.cyan(`╰${hbar}╯`));
  lines.push('');

  return lines;
}

function printCommand(cmd: HelpCommand): string[] {
  const lines: string[] = [];
  const bar  = chalk.bold.cyan('  ▌ ');
  const pipe = chalk.dim.cyan('  │   ');
  const cap  = chalk.dim.cyan('  │');

  const aliases = cmd.aliases.length ? chalk.dim('  ·  ') + chalk.dim(cmd.aliases.join('  ·  ')) : '';

  lines.push(bar + chalk.bold.cyan(cmd.name) + aliases);
  lines.push(pipe + chalk.hex('#94a3b8')(t(cmd.descKey as Parameters<typeof t>[0])));

  if (cmd.flags?.length) {
    lines.push(pipe + chalk.dim('flags  ') + chalk.hex('#2a5a6a')(cmd.flags.join('  ')));
  }

  if (cmd.example) {
    lines.push(pipe + chalk.dim('$ ') + chalk.green(cmd.example));
  }

  lines.push(cap);
  lines.push('');
  return lines;
}

function renderView(session: ShellSession, activeIndex: number): string[] {
  const lines: string[] = [];
  lines.push(...printHeader(session));

  // TAB BAR INTERACTIVO
  const tabs = CATEGORY_ORDER.map((cat, idx) => {
    const title = t(CATEGORY_TITLE_KEYS[cat] as Parameters<typeof t>[0]).replace(/:$/, '').toUpperCase();
    if (idx === activeIndex) {
      return chalk.bgCyan.black(` ${title} `);
    } else {
      return chalk.dim(` ${title} `);
    }
  });
  lines.push('  ' + tabs.join('  '));
  lines.push('');

  // COMMANDS DE LA PESTAÑA ACTIVA
  const activeCat = CATEGORY_ORDER[activeIndex];
  const commands = HELP_COMMANDS.filter(c => c.category === activeCat);

  for (const cmd of commands) {
    lines.push(...printCommand(cmd));
  }

  // FOOTER DE CONTROLES
  lines.push(chalk.dim('  ' + '─'.repeat(BOX_W)));
  lines.push(
    chalk.dim('  ←/→ ') + chalk.dim(t('interactive_help_change_tab') + '  ·  ') +
    chalk.dim('Esc/Enter/Q ') + chalk.dim(t('interactive_help_close'))
  );
  lines.push('');

  return lines;
}

const A = {
  hideCursor: '\x1b[?25l',
  showCursor: '\x1b[?25h',
  clearToEnd: '\x1b[J',
  up: (n: number) => `\x1b[${n}A`,
};
const write = (s: string) => process.stdout.write(s);

export async function showInteractiveHelp(session: ShellSession, categoryFilter?: string): Promise<void> {
  return new Promise((resolve) => {
    let activeIndex = 0;
    if (categoryFilter) {
      const resolved = CATEGORY_ALIASES[categoryFilter.toLowerCase()];
      if (resolved) {
        activeIndex = CATEGORY_ORDER.indexOf(resolved);
      }
    }

    const prevRawMode = process.stdin.isRaw ?? false;
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    write(A.hideCursor);

    let lineCount = 0;

    const redraw = () => {
      if (lineCount > 0) {
        write(A.up(lineCount));
        write(A.clearToEnd);
      }
      const lines = renderView(session, activeIndex);
      lines.forEach(l => write(l + '\n'));
      lineCount = lines.length;
    };

    const handler = (key: string) => {
      if (
        key === '\u0003' || 
        key === '\u0004' || 
        key === '\x1b' || 
        key.toLowerCase() === 'q' || 
        key === '\r' || 
        key === '\n'
      ) {
        process.stdin.removeListener('data', handler);
        process.stdin.setRawMode(prevRawMode);
        write(A.showCursor);
        resolve();
        return;
      }

      if (key === '\x1b[C') { 
        activeIndex = (activeIndex + 1) % CATEGORY_ORDER.length;
        redraw();
      } else if (key === '\x1b[D') { 
        activeIndex = (activeIndex - 1 + CATEGORY_ORDER.length) % CATEGORY_ORDER.length;
        redraw();
      }
    };

    process.stdin.on('data', handler);
    redraw();
  });
}
