import { createHash } from 'crypto';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { dirname, join } from 'path';
import type { Finding } from '../types/findings.js';

/**
 * Cache entry for a scanned file
 */
export interface CacheEntry {
  /** SHA-256 hash of file content */
  hash: string;
  /** Findings from the last scan */
  findings: Finding[];
  /** Timestamp of when the file was scanned */
  timestamp: number;
  /** Version of rnsec that created this entry */
  version: string;
}

/**
 * Cache data structure
 */
export interface CacheData {
  /** Map of file paths to cache entries */
  files: Record<string, CacheEntry>;
  /** Cache creation timestamp */
  createdAt: number;
  /** Cache last updated timestamp */
  updatedAt: number;
}

/**
 * Default cache file name
 */
export const DEFAULT_CACHE_FILE = '.rnsec-cache.json';

/**
 * Cache manager for incremental scanning
 * Stores file hashes and findings to skip unchanged files
 */
export class ScanCache {
  private cacheFile: string;
  private cache: CacheData;
  private version: string;
  private isDirty: boolean = false;
  private enabled: boolean = true;

  constructor(projectDir: string, version: string, cacheFileName: string = DEFAULT_CACHE_FILE) {
    this.cacheFile = join(projectDir, cacheFileName);
    this.version = version;
    this.cache = this.createEmptyCache();
  }

  /**
   * Create an empty cache data structure
   */
  private createEmptyCache(): CacheData {
    return {
      files: {},
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
  }

  /**
   * Load cache from disk
   */
  async load(): Promise<void> {
    if (!this.enabled) return;

    try {
      const content = await readFile(this.cacheFile, 'utf-8');
      const data = JSON.parse(content) as CacheData;
      
      // Validate cache structure
      if (data && typeof data.files === 'object') {
        this.cache = data;
      }
    } catch (error) {
      // Cache doesn't exist or is invalid, start fresh
      this.cache = this.createEmptyCache();
    }
  }

  /**
   * Save cache to disk
   */
  async save(): Promise<void> {
    if (!this.enabled || !this.isDirty) return;

    try {
      this.cache.updatedAt = Date.now();
      
      // Ensure directory exists
      await mkdir(dirname(this.cacheFile), { recursive: true });
      
      await writeFile(this.cacheFile, JSON.stringify(this.cache, null, 2), 'utf-8');
      this.isDirty = false;
    } catch (error) {
      // Silently fail - cache is optional
      if (process.env.RNSEC_VERBOSE) {
        console.warn(`Warning: Could not save cache: ${error}`);
      }
    }
  }

  /**
   * Calculate SHA-256 hash of content
   */
  getContentHash(content: string): string {
    return createHash('sha256').update(content).digest('hex');
  }

  /**
   * Check if a file has a valid cache entry
   * @param filePath - Path to the file
   * @param contentHash - Hash of the current file content
   * @returns true if cache is valid, false otherwise
   */
  isValid(filePath: string, contentHash: string): boolean {
    if (!this.enabled) return false;

    const entry = this.cache.files[filePath];
    if (!entry) return false;

    // Check if hash matches
    if (entry.hash !== contentHash) return false;

    // Check if cached with same version
    if (entry.version !== this.version) return false;

    return true;
  }

  /**
   * Get cached findings for a file
   * @param filePath - Path to the file
   * @returns Cached findings or null if not found/invalid
   */
  getFindings(filePath: string): Finding[] | null {
    if (!this.enabled) return null;

    const entry = this.cache.files[filePath];
    if (!entry) return null;

    return entry.findings;
  }

  /**
   * Set cache entry for a file
   * @param filePath - Path to the file
   * @param contentHash - Hash of the file content
   * @param findings - Findings from scanning the file
   */
  set(filePath: string, contentHash: string, findings: Finding[]): void {
    if (!this.enabled) return;

    this.cache.files[filePath] = {
      hash: contentHash,
      findings,
      timestamp: Date.now(),
      version: this.version,
    };
    this.isDirty = true;
  }

  /**
   * Remove a file from the cache
   * @param filePath - Path to the file
   */
  remove(filePath: string): void {
    if (this.cache.files[filePath]) {
      delete this.cache.files[filePath];
      this.isDirty = true;
    }
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    this.cache = this.createEmptyCache();
    this.isDirty = true;
  }

  /**
   * Get cache statistics
   */
  getStats(): { entries: number; hitRate?: number } {
    return {
      entries: Object.keys(this.cache.files).length,
    };
  }

  /**
   * Enable or disable caching
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Check if caching is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Prune stale entries (files that no longer exist or are too old)
   * @param maxAgeMs - Maximum age of entries in milliseconds (default: 7 days)
   */
  prune(existingFiles: Set<string>, maxAgeMs: number = 7 * 24 * 60 * 60 * 1000): number {
    let pruned = 0;
    const cutoffTime = Date.now() - maxAgeMs;

    for (const filePath of Object.keys(this.cache.files)) {
      const entry = this.cache.files[filePath];
      
      // Remove if file doesn't exist or entry is too old
      if (!existingFiles.has(filePath) || entry.timestamp < cutoffTime) {
        delete this.cache.files[filePath];
        pruned++;
        this.isDirty = true;
      }
    }

    return pruned;
  }
}
