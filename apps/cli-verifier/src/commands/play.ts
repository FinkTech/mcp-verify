/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Playground Command
 *
 * Interactive tool/prompt executor for testing MCP servers
 */

import ora from 'ora';
import chalk from 'chalk';
import readline from 'readline';
import { ToolExecutor } from '@mcp-verify/core/use-cases/playground/tool-executor';
import { JsonObject, McpTool, McpPrompt } from '@mcp-verify/core/domain/shared/common.types';
import { ExternalEditor, t, getCurrentLanguage } from '@mcp-verify/shared';
import { createTransport, detectTransportType } from '../utils/transport-factory';
import { registerCleanup } from '../utils/cleanup-handlers';

interface PlayCommandOptions {
  transport?: string;
  [key: string]: unknown;
}

// Type guards for safe casting
function isValidInputSchema(schema: unknown): schema is { properties?: Record<string, unknown> } {
  return typeof schema === 'object' && schema !== null;
}

function isValidPromptArgument(arg: unknown): arg is { name: string; required?: boolean; description?: string } {
  return typeof arg === 'object' && arg !== null && 'name' in arg && typeof (arg as any).name === 'string';
}

export async function runPlaygroundAction(target: string, options: PlayCommandOptions) {
  let executor: ToolExecutor | null = null;
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const ask = (q: string): Promise<string> => new Promise(r => rl.question(q, r));

  try {
    // Determine transport type and create transport using factory
    const transportType = options.transport || detectTransportType(target);

    const spinner = ora(t('connecting_server')).start();
    const transport = createTransport(target, {
      transportType: transportType as 'stdio' | 'http' | 'sse',
      lang: getCurrentLanguage()
    });

    executor = new ToolExecutor(transport);
    await executor.connect();
    spinner.succeed(t('connected'));

    // Register cleanup handlers
    registerCleanup(async () => {
      if (executor) await executor.close();
      rl.close();
    });

    // Fetch tools and prompts
    spinner.start(t('fetching_capabilities'));
    const [tools, prompts] = await Promise.all([
      executor.listTools(),
      executor.listPrompts().catch(() => []) // Fallback if prompts not supported
    ]);
    spinner.stop();

    if (tools.length === 0 && prompts.length === 0) {
      console.log(chalk.yellow(t('no_tools_prompts')));
      return;
    }

    const allItems = [
      ...tools.map(t => ({ type: 'tool', data: t })),
      ...prompts.map(p => ({ type: 'prompt', data: p }))
    ];

    console.log(chalk.bold('\n' + t('available_capabilities') + ':'));
    allItems.forEach((item, i) => {
      const typeLabel = item.type === 'tool' ? chalk.cyan('[' + t('tool_label') + ']') : chalk.magenta('[' + t('prompt_label') + ']');
      console.log(`  ${chalk.white(i + 1)}. ${typeLabel} ${chalk.bold(item.data.name)} - ${chalk.gray(item.data.description || t('no_description'))}`);
    });
    console.log('');

    // Exit if list-only is requested
    if (options.listOnly) {
      rl.close();
      return;
    }

    while (true) {
      const selection = await ask(chalk.green(t('select_item_or_exit') + ': '));
      if (selection.toLowerCase() === 'exit') break;

      const index = parseInt(selection) - 1;
      if (isNaN(index) || index < 0 || index >= allItems.length) {
        console.log(chalk.red(t('invalid_selection')));
        continue;
      }

      const item = allItems[index];
      const isTool = item.type === 'tool';
      const name = item.data.name;

      console.log(chalk.bold(`\n${t('selected')} ${isTool ? t('tool_label') : t('prompt_label')}: ${name}`));

      // Show Schema / Arguments
      let schema: unknown;

      if (isTool) {
        const toolData = item.data as McpTool;
        schema = toolData.inputSchema;
      } else {
        const promptData = item.data as McpPrompt;
        const args = promptData.arguments || [];
        schema = {
          properties: args
            .filter(isValidPromptArgument)
            .reduce((acc: Record<string, unknown>, arg) => ({ ...acc, [arg.name]: arg }), {})
        };
      }

      console.log(chalk.gray(t('schema_args') + ':'), JSON.stringify(schema, null, 2));

      console.log(chalk.yellow('\n' + t('enter_arguments_json')));
      console.log(chalk.gray('  - ' + t('type_simple_json')));
      console.log(chalk.gray('  - ' + t('type_editor')));

      const argsInput = await ask('> ');

      let argsStr = argsInput.trim();

      if (argsStr === '.editor') {
        rl.pause();
        console.log(chalk.blue(t('opening_editor')));
        try {
          let templateObj: Record<string, string> = {};
          // Basic template gen
          if (isTool) {
            const toolData = item.data as McpTool;
            if (toolData.inputSchema && isValidInputSchema(toolData.inputSchema) && toolData.inputSchema.properties) {
              const props = toolData.inputSchema.properties;
              for (const key in props) templateObj[key] = "";
            }
          } else {
            const promptData = item.data as McpPrompt;
            if (promptData.arguments) {
              promptData.arguments
                .filter(isValidPromptArgument)
                .forEach((a) => templateObj[a.name] = "");
            }
          }

          const template = JSON.stringify(templateObj, null, 2);
          argsStr = await ExternalEditor.edit(template, '.json');
          console.log(chalk.blue(t('input_received')));
        } catch (err) {
          console.log(chalk.red(t('editor_error') + ': ' + err));
          argsStr = "{}";
        }
        rl.resume();
      }

      let args: JsonObject = {};
      try {
        args = argsStr.trim() ? JSON.parse(argsStr) : {};
      } catch (e) {
        console.log(chalk.red(t('playground_invalid_json')));
        continue;
      }

      spinner.start(isTool ? t('executing_tool') : t('getting_prompt'));

      let result;
      if (isTool) {
        result = await executor.executeTool(name, args);
      } else {
        result = await executor.getPrompt(name, args);
      }

      spinner.stop();

      if (result.success) {
        console.log(chalk.green('✓ ' + t('success_label')) + ` (${result.durationMs}ms)`);
        console.log(chalk.bold(t('result_label') + ':'));
        console.log(JSON.stringify(result.result, null, 2));
      } else {
        console.log(chalk.red('✗ ' + t('failed_label')));
        console.log(chalk.red(t('error') + ':'), result.error);
      }
      console.log(chalk.gray('─'.repeat(50)));
    }

  } catch (error) {
    console.error(chalk.red(t('error') + ':'), error instanceof Error ? error.message : String(error));
  } finally {
    if (executor) await executor.close();
    rl.close();
  }
}
