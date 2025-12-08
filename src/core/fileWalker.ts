import fg from 'fast-glob';
import { resolve } from 'path';

export interface FileGroup {
  jsFiles: string[];
  jsonFiles: string[];
  xmlFiles: string[];
  plistFiles: string[];
}

export async function walkProjectFiles(rootDir: string): Promise<FileGroup> {
  const resolvedRoot = resolve(rootDir);

  const patterns = {
    js: ['**/*.{js,jsx,ts,tsx}'],
    json: ['**/app.json', '**/app.config.json', '**/package.json'],
    xml: ['**/AndroidManifest.xml'],
    plist: ['**/Info.plist'],
  };

  const ignore = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.expo/**',
    '**/android/build/**',
    '**/ios/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.test.js',
    '**/*.test.ts',
    '**/*.test.jsx',
    '**/*.test.tsx',
    '**/*.spec.js',
    '**/*.spec.ts',
    '**/*.spec.jsx',
    '**/*.spec.tsx',
    '**/__tests__/**',
    '**/__mocks__/**',
    '**/e2e/**',
    '**/tests/**',
    '**/test/**',
    '**/*.e2e.js',
    '**/*.e2e.ts',
  ];

  const [jsFiles, jsonFiles, xmlFiles, plistFiles] = await Promise.all([
    fg(patterns.js, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.json, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.xml, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.plist, { cwd: resolvedRoot, ignore, absolute: true }),
  ]);

  return {
    jsFiles,
    jsonFiles,
    xmlFiles,
    plistFiles,
  };
}

