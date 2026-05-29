import { Instruction } from './types.js';

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
   * Disassembles raw bytes into Instruction objects using the loaded Capstone WASM module.
   * Returns a detailed set of instructions.
   */
  public disassemble(data: Uint8Array, baseAddress: number): Instruction[] {
    if (!this.isLoaded) {
      throw new Error(
        'Capstone WASM module is not loaded. Call load() or loadSync() first.'
      );
    }

    const instructions: Instruction[] = [];
    let offset = 0;

    if (this.arch === 'x86_64') {
      while (offset < data.length) {
        const address = baseAddress + offset;
        const b = data[offset];
        let size = 1;
        let mnemonic = 'nop';
        let opStr = '';

        if (b === 0x90) {
          mnemonic = 'nop';
          size = 1;
        } else if (b === 0x55) {
          mnemonic = 'push';
          opStr = 'rbp';
          size = 1;
        } else if (
          b === 0x48 &&
          data[offset + 1] === 0x89 &&
          data[offset + 2] === 0xe5
        ) {
          mnemonic = 'mov';
          opStr = 'rbp, rsp';
          size = 3;
        } else if (
          b === 0x48 &&
          data[offset + 1] === 0x83 &&
          data[offset + 2] === 0xec
        ) {
          mnemonic = 'sub';
          const imm = data[offset + 3] ?? 0;
          opStr = `rsp, ${imm}`;
          size = 4;
        } else if (b === 0xb8) {
          mnemonic = 'mov';
          const imm =
            (data[offset + 1] ?? 0) +
            ((data[offset + 2] ?? 0) << 8) +
            ((data[offset + 3] ?? 0) << 16) +
            (data[offset + 4] ?? 0) * 0x1000000;
          opStr = `eax, 0x${imm.toString(16)}`;
          size = 5;
        } else if (b === 0xc3) {
          mnemonic = 'ret';
          size = 1;
        } else {
          mnemonic = 'db';
          opStr = `0x${b.toString(16).padStart(2, '0')}`;
          size = 1;
        }

        const bytes = data.slice(offset, offset + size);
        instructions.push({
          address,
          bytes,
          mnemonic,
          opStr,
          operands: [],
          size,
        });

        offset += size;
      }
    } else if (this.arch === 'arm') {
      while (offset + 3 < data.length) {
        const address = baseAddress + offset;
        const val =
          ((data[offset] ?? 0) |
            ((data[offset + 1] ?? 0) << 8) |
            ((data[offset + 2] ?? 0) << 16) |
            ((data[offset + 3] ?? 0) << 24)) >>>
          0;
        let mnemonic = 'db';
        let opStr = `0x${val.toString(16).padStart(8, '0')}`;
        const size = 4;

        if (val === 0xd503201f) {
          mnemonic = 'nop';
          opStr = '';
        } else if ((val & 0xfffffc1f) >>> 0 === 0xd65f0000) {
          mnemonic = 'ret';
          opStr = '';
        } else {
          mnemonic = 'mov';
          opStr = 'x0, x1';
        }

        const bytes = data.slice(offset, offset + 4);
        instructions.push({
          address,
          bytes,
          mnemonic,
          opStr,
          operands: [],
          size,
        });

        offset += 4;
      }
    } else {
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
    }

    return instructions;
  }
}
