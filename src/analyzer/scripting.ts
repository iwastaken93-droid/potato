import { Instruction, Section, Symbol } from '../disassembler/types.js';
import { ExtractedString } from './strings.js';

export interface ScriptingContext {
  binaryData: Uint8Array;
  entryPoint: number;
  sections: Section[];
  symbols: Symbol[];
  instructions: Instruction[];
  extractedStrings: ExtractedString[];
  dependencies?: {
    binaryName: string;
    imports: { library: string; name: string; address?: number }[];
    exports: { name: string; address?: number }[];
    locals: { name: string; address: number; calls: string[] }[];
  };
}

export class ScriptingEngine {
  private context: ScriptingContext;

  constructor(context: ScriptingContext) {
    this.context = context;
  }

  public updateContext(context: ScriptingContext) {
    this.context = context;
  }

  public execute(code: string): {
    success: boolean;
    result: any;
    logs: string[];
  } {
    const logs: string[] = [];

    // Custom console logger
    const customConsole = {
      log: (...args: any[]) => {
        logs.push(args.map((arg) => this.stringify(arg)).join(' '));
      },
      error: (...args: any[]) => {
        logs.push(
          '[ERROR] ' + args.map((arg) => this.stringify(arg)).join(' ')
        );
      },
      warn: (...args: any[]) => {
        logs.push('[WARN] ' + args.map((arg) => this.stringify(arg)).join(' '));
      },
      info: (...args: any[]) => {
        logs.push('[INFO] ' + args.map((arg) => this.stringify(arg)).join(' '));
      },
    };

    // Helper functions/objects to expose to user script
    const helpers = {
      console: customConsole,
      data: this.context.binaryData,
      entryPoint: this.context.entryPoint,
      sections: this.context.sections,
      symbols: this.context.symbols,
      instructions: this.context.instructions,
      strings: this.context.extractedStrings,
      imports: this.context.dependencies?.imports || [],
      exports: this.context.dependencies?.exports || [],

      getFunctions: () =>
        this.context.symbols.filter((s) => s.type === 'function'),

      findSymbol: (nameOrAddr: string | number) => {
        if (typeof nameOrAddr === 'number') {
          return (
            this.context.symbols.find((s) => s.address === nameOrAddr) || null
          );
        }
        return (
          this.context.symbols.find((s) =>
            s.name.toLowerCase().includes(nameOrAddr.toLowerCase())
          ) || null
        );
      },

      searchInstructions: (query: string) => {
        const q = query.toLowerCase();
        return this.context.instructions.filter(
          (inst) =>
            inst.mnemonic.toLowerCase().includes(q) ||
            inst.opStr.toLowerCase().includes(q) ||
            `0x${inst.address.toString(16)}`.includes(q)
        );
      },

      filterImports: (query: string) => {
        const q = query.toLowerCase();
        return (this.context.dependencies?.imports || []).filter(
          (imp) =>
            imp.name.toLowerCase().includes(q) ||
            imp.library.toLowerCase().includes(q)
        );
      },

      filterExports: (query: string) => {
        const q = query.toLowerCase();
        return (this.context.dependencies?.exports || []).filter((exp) =>
          exp.name.toLowerCase().includes(q)
        );
      },

      findStrings: (query: string) => {
        const q = query.toLowerCase();
        return this.context.extractedStrings.filter((s) =>
          s.value.toLowerCase().includes(q)
        );
      },

      readBytes: (address: number, length: number) => {
        let offset = address;
        const sec = this.context.sections.find(
          (s) =>
            address >= s.virtualAddress &&
            address < s.virtualAddress + s.virtualSize
        );
        if (sec) {
          offset = address - sec.virtualAddress + sec.fileOffset;
        }
        if (offset < 0 || offset >= this.context.binaryData.length) {
          throw new Error(
            `Address 0x${address.toString(16)} is out of binary bounds.`
          );
        }
        const end = Math.min(offset + length, this.context.binaryData.length);
        return this.context.binaryData.slice(offset, end);
      },

      hex: (val: number | Uint8Array) => {
        if (val instanceof Uint8Array) {
          return Array.from(val)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(' ');
        }
        return '0x' + val.toString(16).toUpperCase();
      },

      help: () => {
        customConsole.log('=== Scripting Console Help ===');
        customConsole.log('Available Variables:');
        customConsole.log(
          '  data              Uint8Array of the loaded binary'
        );
        customConsole.log('  entryPoint        Number: Entry point address');
        customConsole.log('  sections          Array of binary sections');
        customConsole.log('  symbols           Array of all parsed symbols');
        customConsole.log(
          '  instructions      Array of disassembled instructions'
        );
        customConsole.log('  strings           Array of extracted strings');
        customConsole.log(
          '  imports           Array of imported library symbols'
        );
        customConsole.log('  exports           Array of exported symbols');
        customConsole.log('\nAvailable Helper Functions:');
        customConsole.log(
          '  getFunctions()            Returns only function symbols'
        );
        customConsole.log(
          '  findSymbol(name|addr)     Finds a symbol by name (substring) or address'
        );
        customConsole.log(
          '  searchInstructions(query) Returns instructions matching mnemonic/operands/address'
        );
        customConsole.log(
          '  findStrings(query)        Returns strings matching query substring'
        );
        customConsole.log(
          '  filterImports(query)      Returns imports matching query substring'
        );
        customConsole.log(
          '  filterExports(query)      Returns exports matching query substring'
        );
        customConsole.log(
          '  readBytes(address, len)   Reads slice of binaryData at virtual address/offset'
        );
        customConsole.log(
          '  hex(number|Uint8Array)    Formats a number or buffer as a hexadecimal string'
        );
        customConsole.log(
          '  help()                    Displays this help message'
        );
        return 'Use help() for available commands and variables.';
      },
    };

    try {
      const keys = Object.keys(helpers);
      const values = Object.values(helpers);

      let codeToEval = code.trim();
      if (
        !codeToEval.includes('return') &&
        !codeToEval.includes(';') &&
        !codeToEval.includes('\n')
      ) {
        codeToEval = `return (${codeToEval});`;
      }

      const fn = new Function(
        ...keys,
        `
        try {
          ${codeToEval}
        } catch (e) {
          throw e;
        }
      `
      );

      const result = fn(...values);
      return {
        success: true,
        result,
        logs,
      };
    } catch (error: any) {
      return {
        success: false,
        result: error.message || String(error),
        logs,
      };
    }
  }

  private stringify(val: any): string {
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';
    if (typeof val === 'object') {
      if (val instanceof Uint8Array) {
        return `Uint8Array [ ${Array.from(val.slice(0, 16))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(
            ' '
          )}${val.length > 16 ? ' ...' : ''} ] (length: ${val.length})`;
      }
      try {
        return JSON.stringify(
          val,
          (key, value) => {
            if (value instanceof Uint8Array) {
              return `Uint8Array(${value.length})`;
            }
            return value;
          },
          2
        );
      } catch (e) {
        return String(val);
      }
    }
    return String(val);
  }
}
