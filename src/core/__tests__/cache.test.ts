import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ScanCache, DEFAULT_CACHE_FILE } from '../cache.js';
import { Severity, type Finding } from '../../types/findings.js';
import { mkdir, rm, readFile, writeFile } from 'fs/promises';
import { join } from 'path';

describe('ScanCache', () => {
  const testDir = '/tmp/rnsec-cache-test';
  const testVersion = '1.0.0';
  let cache: ScanCache;

  beforeEach(async () => {
    await mkdir(testDir, { recursive: true });
    cache = new ScanCache(testDir, testVersion);
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  describe('constructor', () => {
    it('should create cache with default file name', () => {
      const newCache = new ScanCache(testDir, testVersion);
      expect(newCache).toBeDefined();
    });

    it('should accept custom cache file name', () => {
      const newCache = new ScanCache(testDir, testVersion, 'custom-cache.json');
      expect(newCache).toBeDefined();
    });
  });

  describe('getContentHash', () => {
    it('should return consistent hash for same content', () => {
      const content = 'const x = 1;';
      const hash1 = cache.getContentHash(content);
      const hash2 = cache.getContentHash(content);
      
      expect(hash1).toBe(hash2);
    });

    it('should return different hash for different content', () => {
      const hash1 = cache.getContentHash('const x = 1;');
      const hash2 = cache.getContentHash('const x = 2;');
      
      expect(hash1).not.toBe(hash2);
    });

    it('should return 64-character hex string (SHA-256)', () => {
      const hash = cache.getContentHash('test content');
      
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('isValid', () => {
    it('should return false for non-existent entry', () => {
      const hash = cache.getContentHash('content');
      expect(cache.isValid('/nonexistent/file.js', hash)).toBe(false);
    });

    it('should return true for valid cached entry', () => {
      const filePath = '/test/file.js';
      const content = 'const x = 1;';
      const hash = cache.getContentHash(content);
      
      cache.set(filePath, hash, []);
      
      expect(cache.isValid(filePath, hash)).toBe(true);
    });

    it('should return false when hash changes', () => {
      const filePath = '/test/file.js';
      const oldHash = cache.getContentHash('old content');
      const newHash = cache.getContentHash('new content');
      
      cache.set(filePath, oldHash, []);
      
      expect(cache.isValid(filePath, newHash)).toBe(false);
    });

    it('should return false when disabled', () => {
      const filePath = '/test/file.js';
      const hash = cache.getContentHash('content');
      
      cache.set(filePath, hash, []);
      cache.setEnabled(false);
      
      expect(cache.isValid(filePath, hash)).toBe(false);
    });
  });

  describe('set and getFindings', () => {
    it('should store and retrieve findings', () => {
      const filePath = '/test/file.js';
      const hash = cache.getContentHash('content');
      const findings: Finding[] = [
        {
          ruleId: 'TEST_RULE',
          description: 'Test finding',
          severity: Severity.HIGH,
          filePath,
          line: 10,
        },
      ];
      
      cache.set(filePath, hash, findings);
      const retrieved = cache.getFindings(filePath);
      
      expect(retrieved).toEqual(findings);
    });

    it('should return null for non-existent entry', () => {
      expect(cache.getFindings('/nonexistent/file.js')).toBeNull();
    });

    it('should return null when disabled', () => {
      const filePath = '/test/file.js';
      const hash = cache.getContentHash('content');
      
      cache.set(filePath, hash, []);
      cache.setEnabled(false);
      
      expect(cache.getFindings(filePath)).toBeNull();
    });
  });

  describe('remove', () => {
    it('should remove cached entry', () => {
      const filePath = '/test/file.js';
      const hash = cache.getContentHash('content');
      
      cache.set(filePath, hash, []);
      expect(cache.isValid(filePath, hash)).toBe(true);
      
      cache.remove(filePath);
      expect(cache.isValid(filePath, hash)).toBe(false);
    });

    it('should handle removing non-existent entry', () => {
      expect(() => cache.remove('/nonexistent/file.js')).not.toThrow();
    });
  });

  describe('clear', () => {
    it('should clear all entries', () => {
      const hash = cache.getContentHash('content');
      
      cache.set('/file1.js', hash, []);
      cache.set('/file2.js', hash, []);
      
      cache.clear();
      
      expect(cache.getStats().entries).toBe(0);
    });
  });

  describe('load and save', () => {
    it('should persist cache to disk', async () => {
      const filePath = '/test/file.js';
      const hash = cache.getContentHash('content');
      const findings: Finding[] = [
        {
          ruleId: 'TEST_RULE',
          description: 'Test finding',
          severity: Severity.HIGH,
          filePath,
        },
      ];
      
      cache.set(filePath, hash, findings);
      await cache.save();
      
      // Create new cache instance and load
      const newCache = new ScanCache(testDir, testVersion);
      await newCache.load();
      
      expect(newCache.isValid(filePath, hash)).toBe(true);
      expect(newCache.getFindings(filePath)).toEqual(findings);
    });

    it('should handle loading non-existent cache file', async () => {
      const newCache = new ScanCache('/nonexistent/path', testVersion);
      await expect(newCache.load()).resolves.not.toThrow();
    });

    it('should handle loading invalid JSON', async () => {
      await writeFile(join(testDir, DEFAULT_CACHE_FILE), 'invalid json');
      
      const newCache = new ScanCache(testDir, testVersion);
      await expect(newCache.load()).resolves.not.toThrow();
    });
  });

  describe('version invalidation', () => {
    it('should invalidate cache when version changes', async () => {
      const filePath = '/test/file.js';
      const hash = cache.getContentHash('content');
      
      cache.set(filePath, hash, []);
      await cache.save();
      
      // Create new cache with different version
      const newCache = new ScanCache(testDir, '2.0.0');
      await newCache.load();
      
      expect(newCache.isValid(filePath, hash)).toBe(false);
    });
  });

  describe('getStats', () => {
    it('should return correct entry count', () => {
      const hash = cache.getContentHash('content');
      
      expect(cache.getStats().entries).toBe(0);
      
      cache.set('/file1.js', hash, []);
      cache.set('/file2.js', hash, []);
      cache.set('/file3.js', hash, []);
      
      expect(cache.getStats().entries).toBe(3);
    });
  });

  describe('setEnabled/isEnabled', () => {
    it('should enable and disable cache', () => {
      expect(cache.isEnabled()).toBe(true);
      
      cache.setEnabled(false);
      expect(cache.isEnabled()).toBe(false);
      
      cache.setEnabled(true);
      expect(cache.isEnabled()).toBe(true);
    });
  });

  describe('prune', () => {
    it('should remove entries for non-existent files', () => {
      const hash = cache.getContentHash('content');
      
      cache.set('/existing.js', hash, []);
      cache.set('/deleted.js', hash, []);
      
      const existingFiles = new Set(['/existing.js']);
      const pruned = cache.prune(existingFiles);
      
      expect(pruned).toBe(1);
      expect(cache.getStats().entries).toBe(1);
      expect(cache.isValid('/existing.js', hash)).toBe(true);
      expect(cache.isValid('/deleted.js', hash)).toBe(false);
    });

    it('should remove old entries', async () => {
      const hash = cache.getContentHash('content');
      
      cache.set('/file.js', hash, []);
      
      // Wait a tiny bit so the entry has some age
      await new Promise(resolve => setTimeout(resolve, 10));
      
      // Prune with very short max age (1ms)
      const existingFiles = new Set(['/file.js']);
      const pruned = cache.prune(existingFiles, 1);
      
      expect(pruned).toBe(1);
    });
  });
});
