/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

/**
 * Acorn AST node types for type safety
 */
interface AcornNode {
  type: string;
  loc?: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
}

interface CallExpressionNode extends AcornNode {
  type: 'CallExpression';
  callee: AcornNode & { type: string; name?: string };
}

interface NewExpressionNode extends AcornNode {
  type: 'NewExpression';
  callee: AcornNode & { type: string; name?: string };
}

interface MemberExpressionNode extends AcornNode {
  type: 'MemberExpression';
  property: AcornNode & { type: string; name?: string; value?: string };
}

export interface StaticAnalysisResult {
  isSafe: boolean;
  violations: string[];
}

export class SafeJSStaticAnalyzer {
  /**
   * Analiza código JavaScript estáticamente para detectar construcciones peligrosas.
   * @param code Código fuente a analizar
   */
  public analyze(code: string): StaticAnalysisResult {
    const violations: string[] = [];

    try {
      // Parsear a AST (ECMAScript moderno)
      const ast = acorn.parse(code, {
        ecmaVersion: 2022,
        sourceType: 'module', // Permitir import/export
        locations: true
      });

      // Recorrer AST
      walk.simple(ast, {
        // Detectar llamadas a funciones prohibidas
        CallExpression(node: unknown) {
          const callNode = node as CallExpressionNode;
          if (callNode.callee.type === 'Identifier' && callNode.callee.name === 'eval') {
            violations.push(`Prohibited usage of 'eval' at line ${callNode.loc?.start.line}`);
          }
          if (callNode.callee.type === 'Identifier' && callNode.callee.name === 'Function') {
             // Function('...') call
            violations.push(`Prohibited usage of 'Function' constructor call at line ${callNode.loc?.start.line}`);
          }
        },

        // Detectar 'new Function(...)'
        NewExpression(node: unknown) {
          const newNode = node as NewExpressionNode;
          if (newNode.callee.type === 'Identifier' && newNode.callee.name === 'Function') {
            violations.push(`Prohibited usage of 'new Function' at line ${newNode.loc?.start.line}`);
          }
        },

        // Detectar acceso a propiedades peligrosas (__proto__, prototype, constructor)
        MemberExpression(node: unknown) {
          const memberNode = node as MemberExpressionNode;
          const propName = memberNode.property.type === 'Identifier' ? memberNode.property.name : memberNode.property.value;

          if (propName && ['__proto__', 'prototype', 'constructor'].includes(propName)) {
            // Permitir 'constructor' solo si es definición de clase (MethodDefinition maneja eso, aquí es acceso)
            // Acceder a .constructor a veces es legítimo, pero modificarlo es peligroso.
            // Por seguridad estricta inicial, flaggeamos __proto__ y prototype.
            if (propName === '__proto__' || propName === 'prototype') {
               violations.push(`Prohibited access to '${propName}' at line ${memberNode.loc?.start.line}`);
            }
          }
        },
        
        // Detectar identificadores globales prohibidos si no están protegidos por scope
        // Nota: Deno sandbox ya protege, pero esto añade capa extra.
        // Identifier(node: unknown) {
        //   if (node.name === 'process') {
        //     violations.push(`Prohibited usage of Node.js 'process' global`);
        //   }
        // }
      });

    } catch (err: unknown) {
      // Si falla el parsing, es inseguro o inválido
      const errorMessage = err instanceof Error ? err.message : String(err);
      return {
        isSafe: false,
        violations: [`Syntax Error: ${errorMessage}`]
      };
    }

    return {
      isSafe: violations.length === 0,
      violations
    };
  }
}
