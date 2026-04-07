#!/usr/bin/env node
/**
 * Script to update license headers from Apache-2.0 to AGPL-3.0
 *
 * Usage: node tools/scripts/update-license-headers.js
 */

const fs = require("fs");
const path = require("path");

const NEW_HEADER = `/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */`;

// Directories to process
const DIRS_TO_PROCESS = ["apps", "libs", "tests", "tools", "examples"];

// Extensions to process
const EXTENSIONS = [".ts", ".js", ".tsx", ".jsx"];

// Files/dirs to exclude
const EXCLUDE_PATTERNS = [
  "node_modules",
  "dist",
  "build",
  ".git",
  "coverage",
  "__test-reports__",
  ".d.ts.map",
];

/**
 * Check if path should be excluded
 */
function shouldExclude(filePath) {
  return EXCLUDE_PATTERNS.some((pattern) => filePath.includes(pattern));
}

/**
 * Extract old Apache 2.0 header from content
 */
function extractOldHeader(content) {
  const lines = content.split("\n");
  let headerEnd = -1;
  let inHeader = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (line.includes("Copyright (c) 2026 FinkTech") && line.startsWith("*")) {
      inHeader = true;
    }

    if (inHeader && line.includes("limitations under the License")) {
      // Find the closing */
      for (let j = i; j < Math.min(i + 3, lines.length); j++) {
        if (lines[j].trim() === "*/") {
          headerEnd = j;
          break;
        }
      }
      break;
    }
  }

  return headerEnd;
}

/**
 * Update license header in file content
 */
function updateHeader(content, filePath) {
  const lines = content.split("\n");

  // Check for shebang
  let hasShebang = false;
  let startIndex = 0;

  if (lines[0] && lines[0].startsWith("#!")) {
    hasShebang = true;
    startIndex = 1;
  }

  // Find the end of the old header
  const headerEndLine = extractOldHeader(content);

  if (headerEndLine === -1) {
    // No Apache header found, check if AGPL header already exists
    if (content.includes("GNU Affero General Public License")) {
      return { updated: false, reason: "already-agpl" };
    }

    // Check if file has any copyright header
    if (!content.includes("Copyright")) {
      return { updated: false, reason: "no-header" };
    }

    return { updated: false, reason: "no-apache-header" };
  }

  // Build new content
  let newLines = [];

  // Add shebang if it existed
  if (hasShebang) {
    newLines.push(lines[0]);
  }

  // Add new AGPL header
  newLines.push(NEW_HEADER);

  // Add rest of the file (skip old header)
  const remainingLines = lines.slice(headerEndLine + 1);

  // Remove leading empty lines after header
  while (remainingLines.length > 0 && remainingLines[0].trim() === "") {
    remainingLines.shift();
  }

  const result = newLines.join("\n") + "\n" + remainingLines.join("\n");

  return { updated: true, content: result };
}

/**
 * Process a single file
 */
function processFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const result = updateHeader(content, filePath);

    if (result.updated) {
      fs.writeFileSync(filePath, result.content, "utf8");
      return "updated";
    }

    return result.reason;
  } catch (error) {
    console.error(`❌ Error processing ${filePath}:`, error.message);
    return "error";
  }
}

/**
 * Recursively walk directory
 */
function walkDir(dir, fileList = []) {
  const files = fs.readdirSync(dir);

  for (const file of files) {
    const filePath = path.join(dir, file);

    if (shouldExclude(filePath)) {
      continue;
    }

    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      walkDir(filePath, fileList);
    } else {
      const ext = path.extname(filePath);
      if (EXTENSIONS.includes(ext)) {
        fileList.push(filePath);
      }
    }
  }

  return fileList;
}

/**
 * Main execution
 */
function main() {
  console.log("🔄 Updating license headers from Apache-2.0 to AGPL-3.0...\n");

  const rootDir = path.resolve(__dirname, "../..");
  const stats = {
    updated: 0,
    "already-agpl": 0,
    "no-header": 0,
    "no-apache-header": 0,
    error: 0,
  };

  // Collect all files
  let allFiles = [];
  for (const dir of DIRS_TO_PROCESS) {
    const dirPath = path.join(rootDir, dir);
    if (fs.existsSync(dirPath)) {
      const files = walkDir(dirPath);
      allFiles = allFiles.concat(files);
    }
  }

  console.log(`📁 Found ${allFiles.length} files to process\n`);

  // Process each file
  for (const file of allFiles) {
    const relativePath = path.relative(rootDir, file);
    const result = processFile(file);

    stats[result]++;

    if (result === "updated") {
      console.log(`✅ ${relativePath}`);
    } else if (result === "already-agpl") {
      // Silent skip
    } else if (result === "no-apache-header") {
      console.log(`⚠️  ${relativePath} (no Apache header found)`);
    }
  }

  console.log("\n📊 Summary:");
  console.log(`   Total files scanned: ${allFiles.length}`);
  console.log(`   ✅ Updated: ${stats.updated}`);
  console.log(`   ⏭️  Already AGPL: ${stats["already-agpl"]}`);
  console.log(`   ℹ️  No header: ${stats["no-header"]}`);
  console.log(`   ⚠️  No Apache header: ${stats["no-apache-header"]}`);
  console.log(`   ❌ Errors: ${stats.error}`);
  console.log("\n✨ Done!");
}

// Run the script
try {
  main();
} catch (error) {
  console.error("Fatal error:", error);
  process.exit(1);
}
