/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Mock for chalk to avoid ESM import issues in Jest
 * Provides minimal implementation for tests
 */

// Simple identity functions that return the input string
const createChalkMock = (str) => String(str);

// Add color methods as chainable properties
const colors = [
  "red",
  "green",
  "yellow",
  "blue",
  "cyan",
  "magenta",
  "white",
  "gray",
  "grey",
];
const modifiers = [
  "bold",
  "dim",
  "italic",
  "underline",
  "inverse",
  "strikethrough",
];

colors.forEach((color) => {
  createChalkMock[color] = createChalkMock;
});

modifiers.forEach((modifier) => {
  createChalkMock[modifier] = createChalkMock;
});

// Support chaining: chalk.red.bold('text')
const handler = {
  get(target, prop) {
    if (
      typeof prop === "string" &&
      (colors.includes(prop) || modifiers.includes(prop))
    ) {
      return new Proxy(createChalkMock, handler);
    }
    return target[prop];
  },
  apply(target, thisArg, args) {
    return String(args[0] || "");
  },
};

const chalk = new Proxy(createChalkMock, handler);

// Default export
module.exports = chalk;

// Named exports
module.exports.default = chalk;
