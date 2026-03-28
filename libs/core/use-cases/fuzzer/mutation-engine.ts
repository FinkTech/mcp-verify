/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Mutation Engine
 *
 * Generates variations of attack payloads using mutation strategies
 * to increase fuzzing coverage and bypass detection/sanitization.
 *
 * Mutation strategies:
 * - Case variations (upper/lower/mixed)
 * - Encoding (URL, double-URL, HTML entities, Unicode)
 * - Whitespace manipulation
 * - Comment insertion
 * - Concatenation tricks
 * - Null byte injection
 *
 * @module libs/core/use-cases/fuzzer/mutation-engine
 */

import { AttackPayload } from './payloads';

export interface MutatedPayload extends AttackPayload {
  original: string;
  mutationType: string;
}

export class MutationEngine {
  /**
   * Generate mutations for a single payload
   */
  mutate(payload: AttackPayload, mutationCount: number = 5): MutatedPayload[] {
    const mutations: MutatedPayload[] = [];
    const strategies = this.getAllStrategies();

    // Select random strategies
    const selectedStrategies = this.selectRandomStrategies(strategies, mutationCount);

    for (const strategy of selectedStrategies) {
      const mutated = strategy.mutate(payload.value);

      mutations.push({
        ...payload,
        value: mutated,
        original: payload.value,
        mutationType: strategy.name,
        description: `${payload.description} (${strategy.name})`
      });
    }

    return mutations;
  }

  /**
   * Generate all possible mutations for a payload
   */
  mutateAll(payload: AttackPayload): MutatedPayload[] {
    const mutations: MutatedPayload[] = [];
    const strategies = this.getAllStrategies();

    for (const strategy of strategies) {
      const mutated = strategy.mutate(payload.value);

      mutations.push({
        ...payload,
        value: mutated,
        original: payload.value,
        mutationType: strategy.name,
        description: `${payload.description} (${strategy.name})`
      });
    }

    return mutations;
  }

  /**
   * Get all mutation strategies
   */
  private getAllStrategies(): MutationStrategy[] {
    return [
      // Encoding mutations
      new UrlEncodingStrategy(),
      new DoubleUrlEncodingStrategy(),
      new HtmlEntityEncodingStrategy(),
      new UnicodeEncodingStrategy(),

      // Case mutations
      new UpperCaseStrategy(),
      new LowerCaseStrategy(),
      new AlternatingCaseStrategy(),

      // Whitespace mutations
      new SpaceToTabStrategy(),
      new ExtraSpacesStrategy(),
      new NewlineInsertionStrategy(),

      // Special character mutations
      new NullByteInjectionStrategy(),
      new CommentInsertionStrategy(),

      // Obfuscation mutations
      new CharacterConcatenationStrategy(),
      new HexEncodingStrategy()
    ];
  }

  /**
   * Select random strategies
   */
  private selectRandomStrategies(strategies: MutationStrategy[], count: number): MutationStrategy[] {
    const shuffled = [...strategies].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, Math.min(count, strategies.length));
  }
}

/**
 * Base mutation strategy interface
 */
abstract class MutationStrategy {
  abstract name: string;
  abstract mutate(value: string): string;
}

/**
 * URL Encoding
 */
class UrlEncodingStrategy extends MutationStrategy {
  name = 'URL Encoding';

  mutate(value: string): string {
    return encodeURIComponent(value);
  }
}

/**
 * Double URL Encoding
 */
class DoubleUrlEncodingStrategy extends MutationStrategy {
  name = 'Double URL Encoding';

  mutate(value: string): string {
    return encodeURIComponent(encodeURIComponent(value));
  }
}

/**
 * HTML Entity Encoding
 */
class HtmlEntityEncodingStrategy extends MutationStrategy {
  name = 'HTML Entity Encoding';

  mutate(value: string): string {
    return value
      .split('')
      .map(char => {
        const code = char.charCodeAt(0);
        // Encode special characters
        if (code > 127 || ['<', '>', '"', "'", '&'].includes(char)) {
          return `&#${code};`;
        }
        return char;
      })
      .join('');
  }
}

/**
 * Unicode Encoding
 */
class UnicodeEncodingStrategy extends MutationStrategy {
  name = 'Unicode Encoding';

  mutate(value: string): string {
    return value
      .split('')
      .map(char => {
        const code = char.charCodeAt(0);
        if (code > 127 || ['<', '>', '"', "'"].includes(char)) {
          return `\\u${code.toString(16).padStart(4, '0')}`;
        }
        return char;
      })
      .join('');
  }
}

/**
 * Uppercase
 */
class UpperCaseStrategy extends MutationStrategy {
  name = 'Uppercase';

  mutate(value: string): string {
    return value.toUpperCase();
  }
}

/**
 * Lowercase
 */
class LowerCaseStrategy extends MutationStrategy {
  name = 'Lowercase';

  mutate(value: string): string {
    return value.toLowerCase();
  }
}

/**
 * Alternating Case (CaMeLcAsE)
 */
class AlternatingCaseStrategy extends MutationStrategy {
  name = 'Alternating Case';

  mutate(value: string): string {
    return value
      .split('')
      .map((char, i) => i % 2 === 0 ? char.toLowerCase() : char.toUpperCase())
      .join('');
  }
}

/**
 * Replace spaces with tabs
 */
class SpaceToTabStrategy extends MutationStrategy {
  name = 'Space to Tab';

  mutate(value: string): string {
    return value.replace(/ /g, '\t');
  }
}

/**
 * Add extra spaces
 */
class ExtraSpacesStrategy extends MutationStrategy {
  name = 'Extra Spaces';

  mutate(value: string): string {
    return value.replace(/ /g, '  ').replace(/([;|&])/g, '$1 ');
  }
}

/**
 * Insert newlines
 */
class NewlineInsertionStrategy extends MutationStrategy {
  name = 'Newline Insertion';

  mutate(value: string): string {
    // Insert newlines before special characters
    return value.replace(/([;|&])/g, '\n$1');
  }
}

/**
 * Null byte injection
 */
class NullByteInjectionStrategy extends MutationStrategy {
  name = 'Null Byte Injection';

  mutate(value: string): string {
    // Add null byte before extension or at end
    return value.includes('.')
      ? value.replace(/\./, '\x00.')
      : value + '\x00';
  }
}

/**
 * Comment insertion (SQL/shell)
 */
class CommentInsertionStrategy extends MutationStrategy {
  name = 'Comment Insertion';

  mutate(value: string): string {
    // Insert SQL/shell comments
    if (value.includes("'")) {
      return value.replace(/'/, "'/**/");
    }
    if (value.includes(';')) {
      return value.replace(/;/, ';#');
    }
    return value + '/**/';
  }
}

/**
 * Character concatenation (SQL)
 */
class CharacterConcatenationStrategy extends MutationStrategy {
  name = 'Character Concatenation';

  mutate(value: string): string {
    // Convert "admin" to CHAR(97,100,109,105,110) or similar
    if (value.length > 10) return value; // Skip long strings

    // For SQL: 'admin' -> CONCAT(CHAR(97),CHAR(100),...)
    const chars = value.split('').map(c => c.charCodeAt(0));
    return `CONCAT(${chars.map(c => `CHAR(${c})`).join(',')})`;
  }
}

/**
 * Hex encoding
 */
class HexEncodingStrategy extends MutationStrategy {
  name = 'Hex Encoding';

  mutate(value: string): string {
    return value
      .split('')
      .map(char => {
        const hex = char.charCodeAt(0).toString(16).padStart(2, '0');
        return `\\x${hex}`;
      })
      .join('');
  }
}

/**
 * Batch mutation utilities
 */
export class BatchMutator {
  private engine: MutationEngine;

  constructor() {
    this.engine = new MutationEngine();
  }

  /**
   * Generate mutations for multiple payloads
   */
  mutateBatch(payloads: AttackPayload[], mutationsPerPayload: number = 3): MutatedPayload[] {
    const allMutations: MutatedPayload[] = [];

    for (const payload of payloads) {
      const mutations = this.engine.mutate(payload, mutationsPerPayload);
      allMutations.push(...mutations);
    }

    return allMutations;
  }

  /**
   * Generate targeted mutations for specific attack types
   */
  mutateForType(payloads: AttackPayload[], type: string, mutationsPerPayload: number = 5): MutatedPayload[] {
    const filtered = payloads.filter(p => p.type === type);
    return this.mutateBatch(filtered, mutationsPerPayload);
  }

  /**
   * Generate all possible mutations (use with caution - can be large)
   */
  mutateExhaustive(payloads: AttackPayload[]): MutatedPayload[] {
    const allMutations: MutatedPayload[] = [];

    for (const payload of payloads) {
      const mutations = this.engine.mutateAll(payload);
      allMutations.push(...mutations);
    }

    return allMutations;
  }
}
