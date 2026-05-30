import { Instruction } from './types.js';
import { DisassemblerRouter } from './router.js';

export class CapstoneWasmEngine {
  private isLoaded = false;
  private arch: string;
  private mode: string;

  constructor(arch: string, mode: string) {
    this.arch = arch;
    this.mode = mode;
  }

  /**
   * Mock WASM loader. In a real scenario, this would compile/instantiate the WASM binary.
   * For this mock, it simulates async loading of a WASM file and sets the loaded flag.
   */
  public async load(wasmBytes?: Uint8Array): Promise<boolean> {
    await new Promise((resolve) => setTimeout(resolve, 5));
    this.isLoaded = true;
    return true;
  }

  /**
   * Synchronous load for testing and simple router integration.
   */
  public loadSync(): void {
    this.isLoaded = true;
  }

  public isEngineLoaded(): boolean {
    return this.isLoaded;
  }

  /**
   * Disassembles raw bytes into Instruction objects.
   * Falls back gracefully if the architecture is not natively supported by the high-fidelity engine.
   */
  public disassemble(data: Uint8Array, baseAddress: number): Instruction[] {
    if (!this.isLoaded) {
      throw new Error(
        'Capstone WASM module is not loaded. Call load() or loadSync() first.'
      );
    }

    if (this.arch !== 'x86_64' && this.arch !== 'arm') {
      const instructions: Instruction[] = [];
      let offset = 0;
      while (offset < data.length) {
        instructions.push({
          address: baseAddress + offset,
          bytes: data.slice(offset, offset + 1),
          mnemonic: 'db',
          opStr: `0x${data[offset].toString(16)}`,
          operands: [],
          size: 1,
        });
        offset++;
      }
      return instructions;
    }
    
    // Delegate to DisassemblerRouter (with useCapstoneWasm: false to prevent recursion)
    // to provide high-fidelity disassembly.
    const router = new DisassemblerRouter({ useCapstoneWasm: false });
    return router.disassemble(data, {
      arch: this.arch as any,
      baseAddress,
    });
  }
}
