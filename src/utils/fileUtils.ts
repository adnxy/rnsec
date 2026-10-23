import { readFile } from 'fs/promises';
import { resolve } from 'path';
import type { RnsecConfig } from '../types/ruleTypes.js';
import { parseJsonc } from './jsonc.js';

export async function readFileContent(filePath: string): Promise<string> {
  try {
    const content = await readFile(resolve(filePath), 'utf-8');
    return content;
  } catch (error) {
    throw new Error(`Failed to read file ${filePath}: ${error}`);
  }
}

export async function readRnsecConfig(rootDir: string): Promise<RnsecConfig | null> {
  const configPaths = ['.rnsec.json', '.rnsec.jsonc', '.rnsec.config.json'];

  for (const configPath of configPaths) {
    const fullPath = resolve(rootDir, configPath);
    let content: string;
    try {
      content = await readFile(fullPath, 'utf-8');
    } catch {
      continue; // file does not exist: try the next candidate
    }

    try {
      return parseJsonc<RnsecConfig>(content);
    } catch (error) {
      // Surface the problem instead of silently scanning without the user's config
      console.warn(
        `⚠️  Could not parse ${configPath}: ${error instanceof Error ? error.message : String(error)}. The file is being ignored.`
      );
    }
  }

  return null;
}

export function getFileExtension(filePath: string): string {
  const lastDot = filePath.lastIndexOf('.');
  return lastDot === -1 ? '' : filePath.slice(lastDot);
}

export function isJavaScriptFile(filePath: string): boolean {
  const ext = getFileExtension(filePath);
  return ['.js', '.jsx', '.ts', '.tsx'].includes(ext);
}

export function isJsonFile(filePath: string): boolean {
  return getFileExtension(filePath) === '.json';
}

export function isXmlFile(filePath: string): boolean {
  return getFileExtension(filePath) === '.xml';
}

export function isPlistFile(filePath: string): boolean {
  return getFileExtension(filePath) === '.plist';
}

