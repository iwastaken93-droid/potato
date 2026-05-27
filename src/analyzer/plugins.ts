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
}

/**
 * The core interface that all custom analyzer plugins must implement.
 */
export interface AnalyzerPlugin {
  /** Metadata describing the plugin */
  metadata: PluginMetadata;

  /**
   * Optional lifecycle hook called when the plugin is registered.
   */
  init?(): void | Promise<void>;

  /**
   * Optional lifecycle hook called when the plugin is unregistered.
   */
  destroy?(): void | Promise<void>;

  /**
   * Evaluates if the plugin supports the given binary context.
   * Useful for architecture-specific or format-specific analyzers.
   */
  supports?(context: AnalyzerContext): boolean;

  /**
   * Executes the analysis logic against the binary context.
   */
  analyze(context: AnalyzerContext, options?: Record<string, any>): AnalyzerResult | Promise<AnalyzerResult>;
}

/**
 * Registry and coordinator for managing and running custom analyzer plugins.
 */
export class PluginManager {
  private static instance: PluginManager;
  private plugins = new Map<string, AnalyzerPlugin>();

  private constructor() {}

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
   * Registers a new plugin with the manager and runs its `init` lifecycle hook if present.
   * 
   * @param plugin The analyzer plugin to register.
   * @throws {Error} If the plugin is missing metadata, has no ID, or if a plugin with the same ID is already registered.
   * @returns A promise that resolves when the plugin registration and initialization are complete.
   */
  public async register(plugin: AnalyzerPlugin): Promise<void> {
    if (!plugin.metadata || !plugin.metadata.id) {
      throw new Error('Cannot register plugin: Missing metadata or metadata.id');
    }
    if (this.plugins.has(plugin.metadata.id)) {
      throw new Error(`Plugin with ID "${plugin.metadata.id}" is already registered.`);
    }

    if (plugin.init) {
      await plugin.init();
    }

    this.plugins.set(plugin.metadata.id, plugin);
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

    if (plugin.destroy) {
      try {
        await plugin.destroy();
      } catch (err) {
        console.error(`Error destroying plugin "${id}":`, err);
      }
    }

    return this.plugins.delete(id);
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
  public async runAll(context: AnalyzerContext, options?: Record<string, any>): Promise<AnalyzerResult[]> {
    const results: AnalyzerResult[] = [];

    for (const plugin of this.plugins.values()) {
      if (plugin.supports && !plugin.supports(context)) {
        continue;
      }

      try {
        const pluginOptions = options?.[plugin.metadata.id];
        const result = await plugin.analyze(context, pluginOptions);
        results.push(result);
      } catch (err: any) {
        results.push({
          pluginId: plugin.metadata.id,
          success: false,
          errors: [err?.message || String(err)],
          findings: []
        });
      }
    }

    return results;
  }
}
