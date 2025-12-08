import { parse } from '@babel/parser';
import type { Node } from '@babel/types';

export interface ParseResult {
  ast: Node;
  success: boolean;
  error?: string;
}

export async function parseJSFile(filePath: string, source: string): Promise<ParseResult> {
  try {
    const ast = parse(source, {
      sourceType: 'module',
      plugins: [
        'jsx',
        'typescript',
        'decorators-legacy',
        'classProperties',
        'objectRestSpread',
        'asyncGenerators',
        'dynamicImport',
      ],
      errorRecovery: true,
    });

    return {
      ast,
      success: true,
    };
  } catch (error) {
    return {
      ast: null as any,
      success: false,
      error: error instanceof Error ? error.message : 'Unknown parse error',
    };
  }
}

export function parseJsonSafe(content: string): Record<string, any> | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

