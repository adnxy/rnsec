import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { walkProjectFiles } from '../fileWalker.js';
import { mkdir, writeFile, rm } from 'fs/promises';
import { join } from 'path';

describe('fileWalker', () => {
  const testDir = '/tmp/rnsec-filewalker-test';

  beforeAll(async () => {
    // Create test directory structure
    await mkdir(testDir, { recursive: true });
    await mkdir(join(testDir, 'src'), { recursive: true });
    await mkdir(join(testDir, 'src', 'components'), { recursive: true });
    await mkdir(join(testDir, 'android'), { recursive: true });
    await mkdir(join(testDir, 'ios'), { recursive: true });
    await mkdir(join(testDir, 'node_modules', 'some-package'), { recursive: true });
    await mkdir(join(testDir, '__tests__'), { recursive: true });

    // Create test files
    await writeFile(join(testDir, 'App.tsx'), 'export default function App() {}');
    await writeFile(join(testDir, 'src', 'index.ts'), 'export * from "./components";');
    await writeFile(join(testDir, 'src', 'utils.js'), 'export const helper = () => {};');
    await writeFile(join(testDir, 'src', 'components', 'Button.tsx'), 'export const Button = () => null;');
    await writeFile(join(testDir, 'src', 'components', 'Input.jsx'), 'export const Input = () => null;');
    await writeFile(join(testDir, 'app.json'), '{"expo": {"name": "test"}}');
    await writeFile(join(testDir, 'package.json'), '{"name": "test-app"}');
    await writeFile(join(testDir, 'android', 'AndroidManifest.xml'), '<manifest />');
    await writeFile(join(testDir, 'ios', 'Info.plist'), '<plist></plist>');
    
    // Create files that should be ignored
    await writeFile(join(testDir, 'node_modules', 'some-package', 'index.js'), 'module.exports = {};');
    await writeFile(join(testDir, '__tests__', 'App.test.tsx'), 'test("works", () => {});');
    await writeFile(join(testDir, 'src', 'utils.test.ts'), 'test("helper", () => {});');
    await writeFile(join(testDir, 'src', 'utils.spec.ts'), 'describe("utils", () => {});');
  });

  afterAll(async () => {
    // Clean up test directory
    await rm(testDir, { recursive: true, force: true });
  });

  describe('walkProjectFiles', () => {
    it('should find JavaScript and TypeScript files', async () => {
      const result = await walkProjectFiles(testDir);
      
      expect(result.jsFiles.length).toBeGreaterThan(0);
      
      // Should find main source files
      expect(result.jsFiles.some(f => f.includes('App.tsx'))).toBe(true);
      expect(result.jsFiles.some(f => f.includes('index.ts'))).toBe(true);
      expect(result.jsFiles.some(f => f.includes('utils.js'))).toBe(true);
      expect(result.jsFiles.some(f => f.includes('Button.tsx'))).toBe(true);
      expect(result.jsFiles.some(f => f.includes('Input.jsx'))).toBe(true);
    });

    it('should find JSON config files', async () => {
      const result = await walkProjectFiles(testDir);
      
      expect(result.jsonFiles.length).toBeGreaterThan(0);
      expect(result.jsonFiles.some(f => f.includes('app.json'))).toBe(true);
      expect(result.jsonFiles.some(f => f.includes('package.json'))).toBe(true);
    });

    it('should find Android manifest files', async () => {
      const result = await walkProjectFiles(testDir);
      
      expect(result.xmlFiles.length).toBeGreaterThan(0);
      expect(result.xmlFiles.some(f => f.includes('AndroidManifest.xml'))).toBe(true);
    });

    it('should find iOS plist files', async () => {
      const result = await walkProjectFiles(testDir);
      
      expect(result.plistFiles.length).toBeGreaterThan(0);
      expect(result.plistFiles.some(f => f.includes('Info.plist'))).toBe(true);
    });

    it('should exclude node_modules by default', async () => {
      const result = await walkProjectFiles(testDir);
      
      const allFiles = [
        ...result.jsFiles,
        ...result.jsonFiles,
        ...result.xmlFiles,
        ...result.plistFiles,
      ];
      
      expect(allFiles.every(f => !f.includes('node_modules'))).toBe(true);
    });

    it('should exclude test files by default', async () => {
      const result = await walkProjectFiles(testDir);
      
      // Should not include test files
      expect(result.jsFiles.every(f => !f.includes('.test.'))).toBe(true);
      expect(result.jsFiles.every(f => !f.includes('.spec.'))).toBe(true);
      expect(result.jsFiles.every(f => !f.includes('__tests__'))).toBe(true);
    });

    it('should return absolute paths', async () => {
      const result = await walkProjectFiles(testDir);
      
      const allFiles = [
        ...result.jsFiles,
        ...result.jsonFiles,
        ...result.xmlFiles,
        ...result.plistFiles,
      ];
      
      // All paths should be absolute (start with /)
      expect(allFiles.every(f => f.startsWith('/'))).toBe(true);
    });

    it('should accept additional ignore patterns', async () => {
      const result = await walkProjectFiles(testDir, ['**/components/**']);
      
      // Should not include files from components directory
      expect(result.jsFiles.every(f => !f.includes('/components/'))).toBe(true);
    });

    it('should handle empty directories gracefully', async () => {
      const emptyDir = join(testDir, 'empty');
      await mkdir(emptyDir, { recursive: true });
      
      const result = await walkProjectFiles(emptyDir);
      
      expect(result.jsFiles).toEqual([]);
      expect(result.jsonFiles).toEqual([]);
      expect(result.xmlFiles).toEqual([]);
      expect(result.plistFiles).toEqual([]);
    });

    it('should handle non-existent directories', async () => {
      const result = await walkProjectFiles('/nonexistent/path');
      
      expect(result.jsFiles).toEqual([]);
      expect(result.jsonFiles).toEqual([]);
      expect(result.xmlFiles).toEqual([]);
      expect(result.plistFiles).toEqual([]);
    });
  });

  describe('file grouping', () => {
    it('should correctly categorize files by extension', async () => {
      const result = await walkProjectFiles(testDir);
      
      // JS files should have correct extensions
      result.jsFiles.forEach(f => {
        expect(f).toMatch(/\.(js|jsx|ts|tsx)$/);
      });
      
      // JSON files should end in .json
      result.jsonFiles.forEach(f => {
        expect(f).toMatch(/\.json$/);
      });
      
      // XML files should end in .xml
      result.xmlFiles.forEach(f => {
        expect(f).toMatch(/\.xml$/);
      });
      
      // Plist files should end in .plist
      result.plistFiles.forEach(f => {
        expect(f).toMatch(/\.plist$/);
      });
    });
  });
});
