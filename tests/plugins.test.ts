import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PluginManager, AnalyzerPlugin, AnalyzerContext, AnalyzerResult } from '../src/analyzer/plugins.js';

describe('Plugin System Architecture Unit Tests', () => {
  let manager: PluginManager;
  let mockContext: AnalyzerContext;

  beforeEach(() => {
    manager = PluginManager.getInstance();
    mockContext = {
      binaryData: new Uint8Array([0x7f, 0x45, 0x4c, 0x46]), // ELF magic
      sections: [],
      symbols: [],
      instructions: []
    };
  });

  afterEach(async () => {
    await manager.clear();
  });

  it('should register and unregister plugins correctly', async () => {
    const initSpy = vi.fn();
    const destroySpy = vi.fn();

    const plugin: AnalyzerPlugin = {
      metadata: {
        id: 'test-plugin',
        name: 'Test Plugin',
        description: 'A mock plugin for testing',
        version: '1.0.0',
        author: 'Antigravity'
      },
      init: initSpy,
      destroy: destroySpy,
      analyze: (ctx) => {
        return {
          pluginId: 'test-plugin',
          success: true,
          findings: []
        };
      }
    };

    await manager.register(plugin);
    expect(manager.getPlugin('test-plugin')).toBe(plugin);
    expect(manager.getPlugins()).toContain(plugin);
    expect(initSpy).toHaveBeenCalledTimes(1);

    const unregistered = await manager.unregister('test-plugin');
    expect(unregistered).toBe(true);
    expect(manager.getPlugin('test-plugin')).toBeUndefined();
    expect(destroySpy).toHaveBeenCalledTimes(1);
  });

  it('should fail to register duplicate plugin IDs', async () => {
    const plugin1: AnalyzerPlugin = {
      metadata: {
        id: 'dup-plugin',
        name: 'Plugin 1',
        description: 'First instance',
        version: '1.0.0',
        author: 'Antigravity'
      },
      analyze: () => ({ pluginId: 'dup-plugin', success: true, findings: [] })
    };

    const plugin2: AnalyzerPlugin = {
      metadata: {
        id: 'dup-plugin',
        name: 'Plugin 2',
        description: 'Second instance',
        version: '1.0.0',
        author: 'Antigravity'
      },
      analyze: () => ({ pluginId: 'dup-plugin', success: true, findings: [] })
    };

    await manager.register(plugin1);
    await expect(manager.register(plugin2)).rejects.toThrow('Plugin with ID "dup-plugin" is already registered.');
  });

  it('should run supports check and skip plugins that are not supported', async () => {
    const supportedPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'supported-plugin',
        name: 'Supported',
        description: 'Should run',
        version: '1.0.0',
        author: 'Antigravity'
      },
      supports: () => true,
      analyze: () => ({ pluginId: 'supported-plugin', success: true, findings: [] })
    };

    const unsupportedPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'unsupported-plugin',
        name: 'Unsupported',
        description: 'Should not run',
        version: '1.0.0',
        author: 'Antigravity'
      },
      supports: () => false,
      analyze: () => ({ pluginId: 'unsupported-plugin', success: true, findings: [] })
    };

    await manager.register(supportedPlugin);
    await manager.register(unsupportedPlugin);

    const results = await manager.runAll(mockContext);
    expect(results).toHaveLength(1);
    expect(results[0].pluginId).toBe('supported-plugin');
  });

  it('should execute analysis and capture findings', async () => {
    const mockFinding = {
      category: 'security',
      severity: 'high' as const,
      description: 'Found ELF signature',
      evidence: '7F 45 4C 46'
    };

    const plugin: AnalyzerPlugin = {
      metadata: {
        id: 'elf-detector',
        name: 'ELF Detector',
        description: 'Detects ELF headers',
        version: '1.0.0',
        author: 'Antigravity'
      },
      analyze: (ctx) => {
        const isElf = ctx.binaryData[0] === 0x7f && ctx.binaryData[1] === 0x45;
        return {
          pluginId: 'elf-detector',
          success: true,
          findings: isElf ? [mockFinding] : []
        };
      }
    };

    await manager.register(plugin);
    const results = await manager.runAll(mockContext);

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].findings).toContainEqual(mockFinding);
  });

  it('should capture plugin execution errors gracefully', async () => {
    const errorPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'error-plugin',
        name: 'Error Plugin',
        description: 'Throws an error',
        version: '1.0.0',
        author: 'Antigravity'
      },
      analyze: () => {
        throw new Error('Analysis failed unexpectedly');
      }
    };

    await manager.register(errorPlugin);
    const results = await manager.runAll(mockContext);

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    expect(results[0].errors).toContain('Analysis failed unexpectedly');
    expect(results[0].findings).toHaveLength(0);
  });
});
