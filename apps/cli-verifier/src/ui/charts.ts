/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ASCII Charts Utilities
 *
 * Functions for creating terminal-based charts and visualizations
 */

import chalk from "chalk";
import { t } from "@mcp-verify/shared";

/**
 * Draw an ASCII histogram chart for response time distribution
 * @param data Array of response times in milliseconds
 * @param label Label for the chart (e.g., "Response Time")
 * @returns Formatted ASCII chart string
 */
export function drawAsciiChart(data: number[], label: string): string {
  if (data.length === 0) return "";

  // Create buckets
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const bucketCount = 10;
  const buckets = new Array(bucketCount).fill(0);
  const bucketSize = range / bucketCount;

  data.forEach((val) => {
    const bucketIndex = Math.min(
      Math.floor((val - min) / bucketSize),
      bucketCount - 1,
    );
    buckets[bucketIndex]++;
  });

  const maxCount = Math.max(...buckets);
  const chartLines: string[] = [];

  chartLines.push(chalk.bold(`\n${label} ${t("chart_distribution")}:`));

  buckets.forEach((count, i) => {
    const bucketStart = Math.floor(min + i * bucketSize);
    const bucketEnd = Math.floor(min + (i + 1) * bucketSize);
    const barLength = Math.floor((count / maxCount) * 20); // Max width 20 chars
    const bar = "█".repeat(barLength);
    const percentage = Math.round((count / data.length) * 100);

    // Use padStart for alignment
    const rangeLabel = `${bucketStart}-${bucketEnd} ms`.padStart(15);
    chartLines.push(
      `${chalk.gray(rangeLabel)} ▏ ${chalk.cyan(bar)} ${chalk.gray(`(${percentage}%)`)}`,
    );
  });

  return chartLines.join("\n");
}
