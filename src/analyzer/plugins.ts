import { Section, Symbol, Instruction } from '../disassembler/types.js';

/**
 * Context provided to analyzer plugins during the analysis phase.
 */
export interface AnalyzerContext {
  /** The raw binary buffer of the executable/file */
  binaryData: Uint8Array;
  /** List of parsed sections (e.g. .text, .data, etc.) */
  sections: Section[];
  /** List of extracted symbols */
  symbols: Symbol[];
  /** List of disassembled instructions, if available */
  instructions: Instruction[];
}

/**
 * Severity level of an analysis finding.
 */
export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * An individual finding or issue detected by a plugin.
 */
export interface AnalysisFinding {
  /** Broad category of the finding (e.g., 'security', 'obfuscation', 'performance') */
  category: string;
  /** Severity level */
  severity: FindingSeverity;
  /** Descriptive summary of the issue or insight */
  description: string;
  /** Target virtual or physical address where the finding is located, if applicable */
  address?: number;
  /** Specific evidence supporting the finding (e.g., code snippet, hex bytes, string value) */
  evidence?: string;
  /** Custom metadata associated with the finding */
  metadata?: Record<string, any>;
}

/**
 * Structured result returned by an analyzer plugin.
 */
export interface AnalyzerResult {
  /** The unique ID of the plugin that produced this result */
  pluginId: string;
  /** Whether the analysis finished successfully */
  success: boolean;
  /** Any errors encountered during execution */
  errors?: string[];
  /** Collection of findings discovered */
  findings: AnalysisFinding[];
  /** Summary or status message of the analysis */
  summary?: string;
}

/**
 * Definition of a configuration option for a plugin.
 */
export interface PluginConfigOption {
  type: 'boolean' | 'string' | 'number';
  default: any;
  label: string;
  description: string;
  options?: string[]; // For dropdown/select selection
}

/**
 * Metadata defining a plugin's identity, version, and authorship.
 */
export interface PluginMetadata {
  /** Unique identifier for the plugin (e.g., 'entropy-analyzer') */
  id: string;
  /** Human-readable name */
  name: string;
  /** Short description explaining what it analyzes */
  description: string;
  /** Version string in semver format */
  version: string;
  /** Name or handle of the author */
  author: string;
  /** Plugin API compatibility version (e.g., '1.0.0', '2.0.0') */
  apiVersion?: string;
  /** List of plugin IDs that this plugin depends on */
  dependencies?: string[];
}

/**
 * The core interface that all custom analyzer plugins must implement.
 */
export interface AnalyzerPlugin {
  /** Metadata describing the plugin */
  metadata: PluginMetadata;

  /** Config options schema defining variables the UI can present */
  configSchema?: Record<string, PluginConfigOption>;

  /** Active configuration values for the plugin */
  config?: Record<string, any>;

  /** Whether the plugin is currently enabled */
  enabled?: boolean;

  /**
   * Optional lifecycle hook called when the plugin is registered.
   */
  init?(): void | Promise<void>;

  /**
   * Optional lifecycle hook called when the plugin is unregistered.
   */
  destroy?(): void | Promise<void>;

  /**
   * Optional lifecycle hook called before analysis starts.
   */
  onBeforeAnalyze?(
    context: AnalyzerContext,
    options?: Record<string, any>
  ): void | Promise<void>;

  /**
   * Optional lifecycle hook called after analysis finishes.
   */
  onAfterAnalyze?(
    context: AnalyzerContext,
    result: AnalyzerResult
  ): void | Promise<void>;

  /**
   * Optional lifecycle hook called when the plugin is enabled.
   */
  onEnable?(): void | Promise<void>;

  /**
   * Optional lifecycle hook called when the plugin is disabled.
   */
  onDisable?(): void | Promise<void>;

  /**
   * Evaluates if the plugin supports the given binary context.
   * Useful for architecture-specific or format-specific analyzers.
   */
  supports?(context: AnalyzerContext): boolean;

  /**
   * Executes the analysis logic against the binary context.
   */
  analyze(
    context: AnalyzerContext,
    options?: Record<string, any>
  ): AnalyzerResult | Promise<AnalyzerResult>;
}

/**
 * Map of typed hooks and their data structures.
 */
export interface PluginHookMap {
  'analyze:before': { context: AnalyzerContext; options?: Record<string, any> };
  'analyze:after': { context: AnalyzerContext; result: AnalyzerResult };
  'finding:detected': { finding: AnalysisFinding; pluginId: string };
  'plugin:registered': { pluginId: string };
  'plugin:unregistered': { pluginId: string };
}

/**
 * Event-based registry for typed plugin hooks.
 */
export class HookRegistry {
  private handlers = new Map<keyof PluginHookMap, Set<(data: any) => void | Promise<void>>>();

  public on<K extends keyof PluginHookMap>(
    event: K,
    handler: (data: PluginHookMap[K]) => void | Promise<void>
  ): void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set());
    }
    this.handlers.get(event)!.add(handler);
  }

  public off<K extends keyof PluginHookMap>(
    event: K,
    handler: (data: PluginHookMap[K]) => void | Promise<void>
  ): void {
    const set = this.handlers.get(event);
    if (set) {
      set.delete(handler);
    }
  }

  public async trigger<K extends keyof PluginHookMap>(
    event: K,
    data: PluginHookMap[K]
  ): Promise<void> {
    const set = this.handlers.get(event);
    if (set) {
      for (const handler of set) {
        await handler(data);
      }
    }
  }
}

/**
 * Registry and coordinator for managing and running custom analyzer plugins.
 */
export class PluginManager {
  private static instance: PluginManager;
  private plugins = new Map<string, AnalyzerPlugin>();
  private discoverablePlugins: AnalyzerPlugin[] = [];
  public readonly hooks = new HookRegistry();

  private constructor() {
    this.initDiscoverablePlugins();
  }

  /**
   * Retrieve the singleton instance of the PluginManager.
   *
   * @returns The singleton PluginManager instance.
   */
  public static getInstance(): PluginManager {
    if (!PluginManager.instance) {
      PluginManager.instance = new PluginManager();
    }
    return PluginManager.instance;
  }

  /**
   * Initialize built-in plugins in the discoverable registry.
   */
  private initDiscoverablePlugins() {
    this.discoverablePlugins = [
      {
        metadata: {
          id: 'elf-hardening',
          name: 'ELF Hardening Analyzer',
          description:
            'Analyzes ELF binaries for security hardening features like Stack Canaries and NX bits.',
          version: '1.0.0',
          author: 'Dissect Core',
        },
        enabled: false,
        configSchema: {
          checkCanary: {
            type: 'boolean',
            default: true,
            label: 'Check Stack Canary',
            description:
              'Scan symbol table for compiler-inserted canary check functions (__stack_chk_fail).',
          },
          checkNX: {
            type: 'boolean',
            default: true,
            label: 'Check NX (No-Execute)',
            description:
              'Verify if any sections have both write and execute permissions set.',
          },
        },
        config: {
          checkCanary: true,
          checkNX: true,
        },
        analyze: (context) => {
          const findings: AnalysisFinding[] = [];
          const isElf =
            context.binaryData[0] === 0x7f &&
            context.binaryData[1] === 0x45 &&
            context.binaryData[2] === 0x4c &&
            context.binaryData[3] === 0x46;

          if (!isElf) {
            return {
              pluginId: 'elf-hardening',
              success: true,
              findings: [],
              summary: 'Skipped: Binary is not in ELF format.',
            };
          }

          const checkCanary =
            this.getPlugin('elf-hardening')?.config?.checkCanary ?? true;
          const checkNX =
            this.getPlugin('elf-hardening')?.config?.checkNX ?? true;

          if (checkCanary) {
            const hasCanaryFunc = context.symbols.some((s) =>
              s.name.includes('__stack_chk_fail')
            );
            if (hasCanaryFunc) {
              findings.push({
                category: 'security',
                severity: 'info',
                description:
                  'Stack Canary protections detected (__stack_chk_fail present).',
                evidence: 'Symbol table contains __stack_chk_fail',
              });
            } else {
              findings.push({
                category: 'security',
                severity: 'high',
                description:
                  'Stack Canary protection is missing or not found in symbols.',
                evidence: 'No __stack_chk_fail symbol found',
              });
            }
          }

          if (checkNX) {
            const wxSections = context.sections.filter(
              (s) => s.flags?.write && s.flags?.execute
            );
            if (wxSections.length > 0) {
              findings.push({
                category: 'security',
                severity: 'critical',
                description: `Writable & Executable section(s) detected. This violates W^X safety.`,
                evidence: wxSections
                  .map(
                    (s) =>
                      `${s.name} (Addr: 0x${s.virtualAddress.toString(16)})`
                  )
                  .join(', '),
              });
            } else {
              findings.push({
                category: 'security',
                severity: 'low',
                description:
                  'W^X (Write XOR Execute) validation passed; no writable-executable sections found.',
                evidence: 'All sections are NX compliant',
              });
            }
          }

          return {
            pluginId: 'elf-hardening',
            success: true,
            findings,
            summary: `Analyzed security hardening mitigations. Found ${findings.length} issues/notes.`,
          };
        },
      },
      {
        metadata: {
          id: 'crypto-scanner',
          name: 'Crypto Constants Detector',
          description:
            'Identifies common cryptographic constants inside the binary data.',
          version: '1.0.0',
          author: 'Dissect Core',
        },
        enabled: false,
        configSchema: {
          scanAES: {
            type: 'boolean',
            default: true,
            label: 'Scan for AES',
            description: 'Scans for AES Substitution Box (S-Box) constants.',
          },
          scanMD5: {
            type: 'boolean',
            default: true,
            label: 'Scan for MD5',
            description: 'Scans for MD5 buffer initialization constants.',
          },
        },
        config: {
          scanAES: true,
          scanMD5: true,
        },
        analyze: (context) => {
          const findings: AnalysisFinding[] = [];
          const data = context.binaryData;
          const scanAES =
            this.getPlugin('crypto-scanner')?.config?.scanAES ?? true;
          const scanMD5 =
            this.getPlugin('crypto-scanner')?.config?.scanMD5 ?? true;

          // Helper to find sub-arrays
          const findPattern = (pattern: number[]): number[] => {
            const matches: number[] = [];
            for (let i = 0; i <= data.length - pattern.length; i++) {
              let match = true;
              for (let j = 0; j < pattern.length; j++) {
                if (data[i + j] !== pattern[j]) {
                  match = false;
                  break;
                }
              }
              if (match) matches.push(i);
            }
            return matches;
          };

          if (scanAES) {
            // First 8 values of AES S-Box: 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
            const aesSbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5];
            const matches = findPattern(aesSbox);
            if (matches.length > 0) {
              findings.push({
                category: 'cryptography',
                severity: 'medium',
                description:
                  'AES S-Box constants detected. Binary likely contains AES encryption routines.',
                evidence: `AES S-Box start sequence found at offset ${matches.map((m) => '0x' + m.toString(16)).join(', ')}`,
              });
            }
          }

          if (scanMD5) {
            // MD5 buffer constants: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 (in Little Endian)
            const md5consts = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
            const matches = findPattern(md5consts);
            if (matches.length > 0) {
              findings.push({
                category: 'cryptography',
                severity: 'medium',
                description:
                  'MD5 buffer initialization constants detected. Binary may implement MD5 hashing.',
                evidence: `MD5 init sequence found at offset ${matches.map((m) => '0x' + m.toString(16)).join(', ')}`,
              });
            }
          }

          return {
            pluginId: 'crypto-scanner',
            success: true,
            findings,
            summary:
              findings.length > 0
                ? `Detected cryptographic signatures: ${findings.map((f) => f.description).join('; ')}`
                : 'No common cryptographic constants detected.',
          };
        },
      },
      {
        metadata: {
          id: 'suspicious-apis',
          name: 'Suspicious API Detector',
          description:
            'Identifies high-risk APIs in symbols or imports (e.g. dynamic allocation, networking, system execution).',
          version: '1.1.0',
          author: 'Dissect Core',
        },
        enabled: false,
        configSchema: {
          riskLevel: {
            type: 'string',
            default: 'medium',
            label: 'Min Risk Level',
            description: 'Filter findings by minimum risk level.',
            options: ['low', 'medium', 'high'],
          },
        },
        config: {
          riskLevel: 'medium',
        },
        analyze: (context) => {
          const findings: AnalysisFinding[] = [];
          const riskLevel =
            this.getPlugin('suspicious-apis')?.config?.riskLevel ?? 'medium';

          const apiMap: Record<
            string,
            { severity: FindingSeverity; desc: string }
          > = {
            system: {
              severity: 'high',
              desc: 'Allows executing arbitrary system commands.',
            },
            execve: {
              severity: 'high',
              desc: 'Replaces the current process with a new process.',
            },
            VirtualAlloc: {
              severity: 'high',
              desc: 'Allocates virtual memory. Frequently used in process injection/shellcode loading.',
            },
            WriteProcessMemory: {
              severity: 'critical',
              desc: 'Writes memory to a remote process. High risk for shellcode/malware injection.',
            },
            CreateRemoteThread: {
              severity: 'critical',
              desc: 'Creates a thread in a remote process. High indicator of code injection.',
            },
            mprotect: {
              severity: 'medium',
              desc: 'Changes memory protection flags (potentially bypasses NX).',
            },
            connect: {
              severity: 'low',
              desc: 'Establishes a network socket connection.',
            },
            socket: {
              severity: 'low',
              desc: 'Creates a network communications endpoint.',
            },
            fork: { severity: 'low', desc: 'Creates a child process.' },
          };

          const severityOrder: Record<FindingSeverity, number> = {
            info: 0,
            low: 1,
            medium: 2,
            high: 3,
            critical: 4,
          };
          const minRiskValue = severityOrder[riskLevel as FindingSeverity] ?? 2;

          context.symbols.forEach((sym) => {
            for (const api of Object.keys(apiMap)) {
              if (sym.name.includes(api)) {
                const info = apiMap[api];
                if (severityOrder[info.severity] >= minRiskValue) {
                  findings.push({
                    category: 'security',
                    severity: info.severity,
                    description: `Suspicious API "${api}" detected in symbols. ${info.desc}`,
                    evidence: `Symbol name: ${sym.name} at address 0x${sym.address.toString(16)}`,
                    address: sym.address,
                  });
                }
              }
            }
          });

          return {
            pluginId: 'suspicious-apis',
            success: true,
            findings,
            summary: `Scanned symbols for high-risk APIs. Found ${findings.length} matches.`,
          };
        },
      },
      {
        metadata: {
          id: 'packer-detector',
          name: 'Packer & Entropy Analyzer',
          description:
            'Calculates file entropy and alerts if the executable appears to be packed or encrypted.',
          version: '1.0.0',
          author: 'Dissect Core',
        },
        enabled: false,
        configSchema: {
          entropyThreshold: {
            type: 'number',
            default: 7.2,
            label: 'Entropy Threshold',
            description:
              'Entropy value (0.0 to 8.0) above which a binary is suspected to be packed.',
          },
        },
        config: {
          entropyThreshold: 7.2,
        },
        analyze: (context) => {
          const data = context.binaryData;
          if (data.length === 0) {
            return {
              pluginId: 'packer-detector',
              success: true,
              findings: [],
              summary: 'Empty binary data.',
            };
          }

          // Calculate shannon entropy
          const counts = new Array(256).fill(0);
          for (let i = 0; i < data.length; i++) {
            counts[data[i]]++;
          }
          let entropy = 0;
          for (let i = 0; i < 256; i++) {
            if (counts[i] > 0) {
              const p = counts[i] / data.length;
              entropy -= p * Math.log2(p);
            }
          }

          const threshold =
            this.getPlugin('packer-detector')?.config?.entropyThreshold ?? 7.2;
          const findings: AnalysisFinding[] = [];

          if (entropy > threshold) {
            findings.push({
              category: 'obfuscation',
              severity: 'high',
              description: `High binary entropy detected (${entropy.toFixed(3)} / 8.000). The binary is likely packed, compressed, or encrypted.`,
              evidence: `Calculated Shannon entropy: ${entropy.toFixed(4)}, Threshold: ${threshold}`,
            });
          } else {
            findings.push({
              category: 'obfuscation',
              severity: 'info',
              description: `Binary entropy is normal (${entropy.toFixed(3)} / 8.000).`,
              evidence: `Calculated Shannon entropy: ${entropy.toFixed(4)}, Threshold: ${threshold}`,
            });
          }

          return {
            pluginId: 'packer-detector',
            success: true,
            findings,
            summary: `Binary entropy: ${entropy.toFixed(3)}. Packed status: ${entropy > threshold ? 'SUSPICIOUS' : 'NORMAL'}`,
          };
        },
      },
    ];
  }

  /**
   * Returns list of discoverable/available plugins that are not registered or are available to be installed.
   *
   * @returns An array of discoverable analyzer plugins.
   */
  public getDiscoverablePlugins(): AnalyzerPlugin[] {
    return this.discoverablePlugins;
  }

  /**
   * Installs a discoverable plugin by registering it in the active plugins list.
   *
   * @param id Unique identifier of the discoverable plugin.
   * @returns A promise that resolves when the plugin is successfully installed.
   */
  public async installPlugin(id: string): Promise<void> {
    const disc = this.discoverablePlugins.find((p) => p.metadata.id === id);
    if (!disc) {
      throw new Error(
        `Plugin with ID "${id}" is not in the discoverable registry.`
      );
    }
    const cloned = { ...disc, enabled: true };
    await this.register(cloned);
  }

  /**
   * Uninstalls/unregisters a plugin.
   *
   * @param id Unique identifier of the plugin.
   * @returns A promise resolving to true if successfully uninstalled, false otherwise.
   */
  public async uninstallPlugin(id: string): Promise<boolean> {
    return this.unregister(id);
  }

  /**
   * Registers a new plugin with the manager and runs its `init` lifecycle hook if present.
   *
   * @param plugin The analyzer plugin to register.
   * @throws {Error} If the plugin is missing metadata, has no ID, or if a plugin with the same ID is already registered.
   * @returns A promise that resolves when the plugin registration and initialization are complete.
   */
  public async register(plugin: AnalyzerPlugin): Promise<void> {
    if (!plugin.metadata || !plugin.metadata.id) {
      throw new Error(
        'Cannot register plugin: Missing metadata or metadata.id'
      );
    }
    if (this.plugins.has(plugin.metadata.id)) {
      throw new Error(
        `Plugin with ID "${plugin.metadata.id}" is already registered.`
      );
    }

    const apiVer = plugin.metadata.apiVersion || '1.0.0';
    const major = apiVer.split('.')[0];
    if (major !== '1' && major !== '2') {
      throw new Error(
        `Incompatible plugin API version: "${apiVer}". Supported versions: v1, v2.`
      );
    }

    if (plugin.enabled === undefined) {
      plugin.enabled = true;
    }

    if (plugin.init) {
      await plugin.init();
    }

    this.plugins.set(plugin.metadata.id, plugin);

    // Run custom onEnable lifecycle hook if enabled by default
    if (plugin.enabled && plugin.onEnable) {
      try {
        await plugin.onEnable();
      } catch (err) {
        console.error(
          `Error in onEnable lifecycle hook for plugin "${plugin.metadata.id}":`,
          err
        );
      }
    }

    await this.hooks.trigger('plugin:registered', { pluginId: plugin.metadata.id });
  }

  /**
   * Unregisters an existing plugin by its ID and runs its `destroy` lifecycle hook if present.
   *
   * @param id The unique identifier of the plugin to unregister.
   * @returns A promise resolving to true if the plugin was successfully unregistered; false if the plugin was not found.
   */
  public async unregister(id: string): Promise<boolean> {
    const plugin = this.plugins.get(id);
    if (!plugin) {
      return false;
    }

    if (plugin.enabled && plugin.onDisable) {
      try {
        await plugin.onDisable();
      } catch (err) {
        console.error(
          `Error in onDisable lifecycle hook for plugin "${id}":`,
          err
        );
      }
    }

    if (plugin.destroy) {
      try {
        await plugin.destroy();
      } catch (err) {
        console.error(`Error destroying plugin "${id}":`, err);
      }
    }

    const removed = this.plugins.delete(id);
    if (removed) {
      await this.hooks.trigger('plugin:unregistered', { pluginId: id });
    }
    return removed;
  }

  /**
   * Enable or disable a plugin, executing relevant lifecycle hooks.
   *
   * @param id The plugin ID to modify.
   * @param enabled The new active state.
   */
  public async togglePlugin(id: string, enabled: boolean): Promise<void> {
    const plugin = this.plugins.get(id);
    if (!plugin) {
      throw new Error(`Plugin with ID "${id}" is not registered.`);
    }

    if (plugin.enabled === enabled) {
      return;
    }

    plugin.enabled = enabled;
    if (enabled && plugin.onEnable) {
      await plugin.onEnable();
    } else if (!enabled && plugin.onDisable) {
      await plugin.onDisable();
    }
  }

  /**
   * Update configuration values for a registered plugin.
   *
   * @param id The plugin ID.
   * @param config The partial or complete configuration object.
   */
  public setPluginConfig(id: string, config: Record<string, any>): void {
    const plugin = this.plugins.get(id);
    if (!plugin) {
      throw new Error(`Plugin with ID "${id}" is not registered.`);
    }
    plugin.config = {
      ...(plugin.config || {}),
      ...config,
    };
  }

  /**
   * Retrieves a registered plugin by its ID.
   *
   * @param id The unique identifier of the plugin to retrieve.
   * @returns The registered plugin, or undefined if no plugin matches the given ID.
   */
  public getPlugin(id: string): AnalyzerPlugin | undefined {
    return this.plugins.get(id);
  }

  /**
   * Returns a list of all currently registered plugins.
   *
   * @returns An array of all registered analyzer plugins.
   */
  public getPlugins(): AnalyzerPlugin[] {
    return Array.from(this.plugins.values());
  }

  /**
   * Clears all registered plugins, running their destroy methods.
   *
   * @returns A promise that resolves when all plugins have been unregistered and cleaned up.
   */
  public async clear(): Promise<void> {
    const ids = Array.from(this.plugins.keys());
    for (const id of ids) {
      await this.unregister(id);
    }
  }

  /**
   * Runs analysis using all registered and compatible plugins.
   *
   * @param context The binary and symbols context provided for analysis.
   * @param options Optional configuration parameters for plugins, keyed by plugin ID.
   * @returns A promise resolving to an array of results from each executed plugin.
   */
  /**
   * Resolves execution order of plugins using topological sorting.
   */
  public resolveExecutionOrder(): AnalyzerPlugin[] {
    const order: AnalyzerPlugin[] = [];
    const visited = new Map<string, 'visiting' | 'visited'>();

    const visit = (pluginId: string) => {
      const state = visited.get(pluginId);
      if (state === 'visiting') {
        throw new Error(`Circular dependency detected involving plugin "${pluginId}".`);
      }
      if (state === 'visited') {
        return;
      }

      visited.set(pluginId, 'visiting');

      const plugin = this.plugins.get(pluginId);
      if (plugin) {
        const deps = plugin.metadata.dependencies || [];
        for (const depId of deps) {
          visit(depId);
        }
        order.push(plugin);
      } else {
        throw new Error(`Missing dependency "${pluginId}".`);
      }

      visited.set(pluginId, 'visited');
    };

    for (const pluginId of this.plugins.keys()) {
      visit(pluginId);
    }

    return order;
  }

  /**
   * Runs analysis using all registered and compatible plugins.
   *
   * @param context The binary and symbols context provided for analysis.
   * @param options Optional configuration parameters for plugins, keyed by plugin ID.
   * @returns A promise resolving to an array of results from each executed plugin.
   */
  public async runAll(
    context: AnalyzerContext,
    options?: Record<string, any>
  ): Promise<AnalyzerResult[]> {
    const results: AnalyzerResult[] = [];
    const orderedPlugins = this.resolveExecutionOrder();

    for (const plugin of orderedPlugins) {
      if (plugin.enabled === false) {
        continue;
      }
      if (plugin.supports && !plugin.supports(context)) {
        continue;
      }

      const pluginOptions = options?.[plugin.metadata.id] || plugin.config;

      // Run onBeforeAnalyze hook
      if (plugin.onBeforeAnalyze) {
        try {
          await plugin.onBeforeAnalyze(context, pluginOptions);
        } catch (err) {
          console.error(
            `Error in onBeforeAnalyze lifecycle hook for plugin "${plugin.metadata.id}":`,
            err
          );
        }
      }
      await this.hooks.trigger('analyze:before', { context, options: pluginOptions });

      try {
        const result = await plugin.analyze(context, pluginOptions);
        results.push(result);

        if (result.findings) {
          for (const finding of result.findings) {
            await this.hooks.trigger('finding:detected', {
              finding,
              pluginId: plugin.metadata.id,
            });
          }
        }

        // Run onAfterAnalyze hook
        if (plugin.onAfterAnalyze) {
          try {
            await plugin.onAfterAnalyze(context, result);
          } catch (err) {
            console.error(
              `Error in onAfterAnalyze lifecycle hook for plugin "${plugin.metadata.id}":`,
              err
            );
          }
        }
        await this.hooks.trigger('analyze:after', { context, result });
      } catch (err: any) {
        const errResult: AnalyzerResult = {
          pluginId: plugin.metadata.id,
          success: false,
          errors: [err?.message || String(err)],
          findings: [],
        };
        results.push(errResult);

        // Run onAfterAnalyze hook even on failure
        if (plugin.onAfterAnalyze) {
          try {
            await plugin.onAfterAnalyze(context, errResult);
          } catch (err) {
            console.error(
              `Error in onAfterAnalyze lifecycle hook for plugin "${plugin.metadata.id}":`,
              err
            );
          }
        }
        await this.hooks.trigger('analyze:after', { context, result: errResult });
      }
    }

    return results;
  }
}
