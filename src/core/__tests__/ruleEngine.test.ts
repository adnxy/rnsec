import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { RuleEngine } from '../ruleEngine.js';
import type { Rule, RuleGroup, RuleContext } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { mkdir, rm } from 'fs/promises';

// Mock rule for testing
const createMockRule = (id: string, severity: Severity = Severity.HIGH): Rule => ({
  id,
  description: `Test rule ${id}`,
  severity,
  fileTypes: ['.js', '.ts'],
  apply: vi.fn().mockResolvedValue([]),
});

// Mock rule that returns findings - update filePath to avoid debug context filtering
const createFindingRule = (id: string, baseFindings: Finding[]): Rule => ({
  id,
  description: `Finding rule ${id}`,
  severity: Severity.HIGH,
  fileTypes: ['.js', '.ts'],
  apply: vi.fn().mockImplementation((context: RuleContext) => {
    // Return findings with the actual file path from context
    return baseFindings.map(f => ({
      ...f,
      filePath: context.filePath,
    }));
  }),
});

describe('RuleEngine', () => {
  let engine: RuleEngine;
  const testDir = '/tmp/rnsec-engine-test';

  beforeEach(async () => {
    engine = new RuleEngine();
    await mkdir(testDir, { recursive: true });
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true }).catch(() => {});
  });

  describe('registerRuleGroup', () => {
    it('should register a rule group', () => {
      const rule = createMockRule('TEST_RULE');
      const group: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [rule],
      };

      engine.registerRuleGroup(group);
      const rules = engine.getAllRules();

      expect(rules).toHaveLength(1);
      expect(rules[0].id).toBe('TEST_RULE');
    });

    it('should register multiple rule groups', () => {
      const group1: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [createMockRule('RULE_1')],
      };
      const group2: RuleGroup = {
        category: RuleCategory.NETWORK,
        rules: [createMockRule('RULE_2'), createMockRule('RULE_3')],
      };

      engine.registerRuleGroup(group1);
      engine.registerRuleGroup(group2);

      expect(engine.getAllRules()).toHaveLength(3);
    });
  });

  describe('setIgnoredRules', () => {
    it('should filter out ignored rules', () => {
      const group: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [
          createMockRule('RULE_1'),
          createMockRule('RULE_2'),
          createMockRule('RULE_3'),
        ],
      };

      engine.registerRuleGroup(group);
      engine.setIgnoredRules(['RULE_2']);

      const rules = engine.getAllRules();
      expect(rules).toHaveLength(2);
      expect(rules.map(r => r.id)).not.toContain('RULE_2');
    });

    it('should return ignored rules via getIgnoredRules', () => {
      engine.setIgnoredRules(['RULE_1', 'RULE_2']);
      expect(engine.getIgnoredRules()).toEqual(['RULE_1', 'RULE_2']);
    });
  });

  describe('setExcludedPaths', () => {
    it('should set and get excluded paths', () => {
      const paths = ['**/test/**', '**/node_modules/**'];
      engine.setExcludedPaths(paths);
      expect(engine.getExcludedPaths()).toEqual(paths);
    });
  });

  describe('getAllRules', () => {
    it('should return all rules from all groups', () => {
      const group1: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [createMockRule('RULE_1'), createMockRule('RULE_2')],
      };
      const group2: RuleGroup = {
        category: RuleCategory.NETWORK,
        rules: [createMockRule('RULE_3')],
      };

      engine.registerRuleGroup(group1);
      engine.registerRuleGroup(group2);

      const rules = engine.getAllRules();
      expect(rules).toHaveLength(3);
      expect(rules.map(r => r.id)).toEqual(['RULE_1', 'RULE_2', 'RULE_3']);
    });

    it('should return empty array when no rules registered', () => {
      expect(engine.getAllRules()).toEqual([]);
    });
  });

  describe('runRulesOnFiles', () => {
    it('should return findings from rules', async () => {
      // Use a path that won't be filtered as debug context
      const testFile = `${testDir}/src/App.js`;
      
      const mockFinding: Finding = {
        ruleId: 'TEST_RULE',
        description: 'Test finding',
        severity: Severity.HIGH,
        filePath: testFile,
        line: 10,
      };

      const rule = createFindingRule('TEST_RULE', [mockFinding]);
      const group: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [rule],
      };

      engine.registerRuleGroup(group);

      const { writeFile, mkdir: mkdirFs } = await import('fs/promises');
      
      await mkdirFs(`${testDir}/src`, { recursive: true });
      await writeFile(testFile, 'const x = 1;');
      
      const result = await engine.runRulesOnFiles([testFile]);
      
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].ruleId).toBe('TEST_RULE');
      expect(result.scannedFiles).toBe(1);
    });

    it('should call progress callback', async () => {
      const progressCallback = vi.fn();
      const rule = createMockRule('TEST_RULE');
      const group: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [rule],
      };

      engine.registerRuleGroup(group);

      const { writeFile, mkdir: mkdirFs } = await import('fs/promises');
      const testFile = `${testDir}/src/progress.js`;
      
      await mkdirFs(`${testDir}/src`, { recursive: true });
      await writeFile(testFile, 'const x = 1;');
      
      await engine.runRulesOnFiles([testFile], progressCallback);
      
      expect(progressCallback).toHaveBeenCalledWith({ current: 1, total: 1 });
    });

    it('should handle file read errors gracefully', async () => {
      const rule = createMockRule('TEST_RULE');
      const group: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [rule],
      };

      engine.registerRuleGroup(group);

      const result = await engine.runRulesOnFiles(['/nonexistent/file.js']);
      
      expect(result.findings).toHaveLength(0);
      expect(result.skippedFiles).toBe(1);
    });
  });

  describe('rule severity filtering', () => {
    it('should preserve severity levels in findings', async () => {
      const testFile = `${testDir}/src/severity.js`;
      
      const highFinding: Finding = {
        ruleId: 'HIGH_RULE',
        description: 'High severity',
        severity: Severity.HIGH,
        filePath: testFile,
      };
      const lowFinding: Finding = {
        ruleId: 'LOW_RULE',
        description: 'Low severity',
        severity: Severity.LOW,
        filePath: testFile,
      };

      const group: RuleGroup = {
        category: RuleCategory.STORAGE,
        rules: [
          createFindingRule('HIGH_RULE', [highFinding]),
          createFindingRule('LOW_RULE', [lowFinding]),
        ],
      };

      engine.registerRuleGroup(group);

      const { writeFile, mkdir: mkdirFs } = await import('fs/promises');
      
      await mkdirFs(`${testDir}/src`, { recursive: true });
      await writeFile(testFile, 'const x = 1;');
      
      const result = await engine.runRulesOnFiles([testFile]);
      
      expect(result.findings).toHaveLength(2);
      expect(result.findings.find(f => f.severity === Severity.HIGH)).toBeDefined();
      expect(result.findings.find(f => f.severity === Severity.LOW)).toBeDefined();
    });
  });
});
