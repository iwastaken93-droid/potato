import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  PluginManager,
  AnalyzerPlugin,
  AnalyzerContext,
  AnalyzerResult,
} from '../src/analyzer/plugins.js';

describe('Plugin System Architecture Unit Tests', () => {
  let manager: PluginManager;
  let mockContext: AnalyzerContext;

  beforeEach(() => {
    manager = PluginManager.getInstance();
    mockContext = {
      binaryData: new Uint8Array([0x7f, 0x45, 0x4c, 0x46]), // ELF magic
      sections: [],
      symbols: [],
      instructions: [],
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
        author: 'Antigravity',
      },
      init: initSpy,
      destroy: destroySpy,
      analyze: (ctx) => {
        return {
          pluginId: 'test-plugin',
          success: true,
          findings: [],
        };
      },
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
        author: 'Antigravity',
      },
      analyze: () => ({ pluginId: 'dup-plugin', success: true, findings: [] }),
    };

    const plugin2: AnalyzerPlugin = {
      metadata: {
        id: 'dup-plugin',
        name: 'Plugin 2',
        description: 'Second instance',
        version: '1.0.0',
        author: 'Antigravity',
      },
      analyze: () => ({ pluginId: 'dup-plugin', success: true, findings: [] }),
    };

    await manager.register(plugin1);
    await expect(manager.register(plugin2)).rejects.toThrow(
      'Plugin with ID "dup-plugin" is already registered.'
    );
  });

  it('should run supports check and skip plugins that are not supported', async () => {
    const supportedPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'supported-plugin',
        name: 'Supported',
        description: 'Should run',
        version: '1.0.0',
        author: 'Antigravity',
      },
      supports: () => true,
      analyze: () => ({
        pluginId: 'supported-plugin',
        success: true,
        findings: [],
      }),
    };

    const unsupportedPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'unsupported-plugin',
        name: 'Unsupported',
        description: 'Should not run',
        version: '1.0.0',
        author: 'Antigravity',
      },
      supports: () => false,
      analyze: () => ({
        pluginId: 'unsupported-plugin',
        success: true,
        findings: [],
      }),
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
      evidence: '7F 45 4C 46',
    };

    const plugin: AnalyzerPlugin = {
      metadata: {
        id: 'elf-detector',
        name: 'ELF Detector',
        description: 'Detects ELF headers',
        version: '1.0.0',
        author: 'Antigravity',
      },
      analyze: (ctx) => {
        const isElf = ctx.binaryData[0] === 0x7f && ctx.binaryData[1] === 0x45;
        return {
          pluginId: 'elf-detector',
          success: true,
          findings: isElf ? [mockFinding] : [],
        };
      },
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
        author: 'Antigravity',
      },
      analyze: () => {
        throw new Error('Analysis failed unexpectedly');
      },
    };

    await manager.register(errorPlugin);
    const results = await manager.runAll(mockContext);

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    expect(results[0].errors).toContain('Analysis failed unexpectedly');
    expect(results[0].findings).toHaveLength(0);
  });

  it('should support discoverable plugins and toggle status', async () => {
    const discoverable = manager.getDiscoverablePlugins();
    expect(discoverable.length).toBeGreaterThan(0);
    const elfPlugin = discoverable.find(
      (p) => p.metadata.id === 'elf-hardening'
    );
    expect(elfPlugin).toBeDefined();

    // Verify it is not registered initially
    expect(manager.getPlugin('elf-hardening')).toBeUndefined();

    // Install
    await manager.installPlugin('elf-hardening');
    const installed = manager.getPlugin('elf-hardening');
    expect(installed).toBeDefined();
    expect(installed?.enabled).toBe(true);

    // Toggle
    await manager.togglePlugin('elf-hardening', false);
    expect(installed?.enabled).toBe(false);

    // Skip running if disabled
    const results = await manager.runAll(mockContext);
    const elfResult = results.find((r) => r.pluginId === 'elf-hardening');
    expect(elfResult).toBeUndefined();

    // Toggle back
    await manager.togglePlugin('elf-hardening', true);
    expect(installed?.enabled).toBe(true);
  });

  it('should trigger custom lifecycle hooks (onBeforeAnalyze, onAfterAnalyze, onEnable, onDisable)', async () => {
    const beforeSpy = vi.fn();
    const afterSpy = vi.fn();
    const enableSpy = vi.fn();
    const disableSpy = vi.fn();

    const hookPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'hook-plugin',
        name: 'Hook Plugin',
        description: 'Test hooks',
        version: '1.0.0',
        author: 'Antigravity',
      },
      onBeforeAnalyze: beforeSpy,
      onAfterAnalyze: afterSpy,
      onEnable: enableSpy,
      onDisable: disableSpy,
      analyze: () => ({ pluginId: 'hook-plugin', success: true, findings: [] }),
    };

    await manager.register(hookPlugin);
    expect(enableSpy).toHaveBeenCalledTimes(1);

    await manager.runAll(mockContext);
    expect(beforeSpy).toHaveBeenCalledTimes(1);
    expect(afterSpy).toHaveBeenCalledTimes(1);

    await manager.togglePlugin('hook-plugin', false);
    expect(disableSpy).toHaveBeenCalledTimes(1);
  });

  it('should get and set plugin configuration options dynamically', async () => {
    await manager.installPlugin('elf-hardening');
    const installed = manager.getPlugin('elf-hardening')!;

    expect(installed.config?.checkCanary).toBe(true);

    manager.setPluginConfig('elf-hardening', { checkCanary: false });
    expect(installed.config?.checkCanary).toBe(false);
  });

  it('should validate API version incompatibility', async () => {
    const invalidPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'invalid-version-plugin',
        name: 'Invalid Version',
        description: 'Testing API version validation',
        version: '1.0.0',
        author: 'Antigravity',
        apiVersion: '3.0.0',
      },
      analyze: () => ({ pluginId: 'invalid-version-plugin', success: true, findings: [] }),
    };

    await expect(manager.register(invalidPlugin)).rejects.toThrow(
      'Incompatible plugin API version: "3.0.0". Supported versions: v1, v2.'
    );
  });

  it('should sort execution order topologically and detect cycles', async () => {
    const pluginA: AnalyzerPlugin = {
      metadata: {
        id: 'plugin-a',
        name: 'A',
        description: 'Depends on B',
        version: '1.0.0',
        author: 'Antigravity',
        dependencies: ['plugin-b'],
      },
      analyze: () => ({ pluginId: 'plugin-a', success: true, findings: [] }),
    };

    const pluginB: AnalyzerPlugin = {
      metadata: {
        id: 'plugin-b',
        name: 'B',
        description: 'No deps',
        version: '1.0.0',
        author: 'Antigravity',
      },
      analyze: () => ({ pluginId: 'plugin-b', success: true, findings: [] }),
    };

    await manager.register(pluginB);
    await manager.register(pluginA);

    const order = manager.resolveExecutionOrder();
    expect(order.map(p => p.metadata.id)).toEqual(['plugin-b', 'plugin-a']);

    // Now introduce circular dep
    await manager.clear();

    const cyclicA: AnalyzerPlugin = {
      metadata: {
        id: 'cyclic-a',
        name: 'Cyclic A',
        description: 'Depends on B',
        version: '1.0.0',
        author: 'Antigravity',
        dependencies: ['cyclic-b'],
      },
      analyze: () => ({ pluginId: 'cyclic-a', success: true, findings: [] }),
    };

    const cyclicB: AnalyzerPlugin = {
      metadata: {
        id: 'cyclic-b',
        name: 'Cyclic B',
        description: 'Depends on A',
        version: '1.0.0',
        author: 'Antigravity',
        dependencies: ['cyclic-a'],
      },
      analyze: () => ({ pluginId: 'cyclic-b', success: true, findings: [] }),
    };

    await manager.register(cyclicA);
    await manager.register(cyclicB);

    expect(() => manager.resolveExecutionOrder()).toThrow(
      'Circular dependency detected'
    );
  });

  it('should support dynamic typed hooks', async () => {
    const registeredSpy = vi.fn();
    const unregisteredSpy = vi.fn();
    const beforeSpy = vi.fn();
    const afterSpy = vi.fn();
    const findingSpy = vi.fn();

    manager.hooks.on('plugin:registered', registeredSpy);
    manager.hooks.on('plugin:unregistered', unregisteredSpy);
    manager.hooks.on('analyze:before', beforeSpy);
    manager.hooks.on('analyze:after', afterSpy);
    manager.hooks.on('finding:detected', findingSpy);

    const testPlugin: AnalyzerPlugin = {
      metadata: {
        id: 'hook-test',
        name: 'Hook Test',
        description: 'Test typed hooks',
        version: '1.0.0',
        author: 'Antigravity',
        apiVersion: '2.0.0',
      },
      analyze: () => ({
        pluginId: 'hook-test',
        success: true,
        findings: [
          {
            category: 'test',
            severity: 'low',
            description: 'Test finding',
          },
        ],
      }),
    };

    await manager.register(testPlugin);
    expect(registeredSpy).toHaveBeenCalledWith({ pluginId: 'hook-test' });

    await manager.runAll(mockContext);
    expect(beforeSpy).toHaveBeenCalled();
    expect(afterSpy).toHaveBeenCalled();
    expect(findingSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        pluginId: 'hook-test',
        finding: expect.objectContaining({
          category: 'test',
          description: 'Test finding',
        }),
      })
    );

    await manager.unregister('hook-test');
    expect(unregisteredSpy).toHaveBeenCalledWith({ pluginId: 'hook-test' });
  });
});
