import { readFile } from 'fs/promises';
import { resolve } from 'path';

export async function readFileContent(filePath: string): Promise<string> {
  try {
    const content = await readFile(resolve(filePath), 'utf-8');
    return content;
  } catch (error) {
    throw new Error(`Failed to read file ${filePath}: ${error}`);
  }
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

