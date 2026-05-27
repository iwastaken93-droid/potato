/**
 * Syscall and Windows API emulation system.
 * Part of the Universal Reverse Engineering Tool.
 */

import { Emulator } from './emulator.js';
import { Memory } from './memory.js';

export interface SyscallContext {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  allocatedRegions: { address: bigint; size: number }[];
  nextAllocAddress: bigint;
}

export class SyscallHandler {
  private winHooks: Map<bigint, (emu: Emulator) => void> = new Map();
  private winHookNames: Map<string, bigint> = new Map();
  private nextHookAddress: bigint = 0x80000000n;
  
  public context: SyscallContext = {
    stdout: '',
    stderr: '',
    exitCode: null,
    allocatedRegions: [],
    nextAllocAddress: 0x90000000n,
  };

  constructor() {
    this.registerWindowsStubs();
  }

  /**
   * Register default Windows API stubs.
   */
  private registerWindowsStubs(): void {
    this.registerWindowsHook('VirtualAlloc', (emu) => {
      const args = this.getWindowsArgs(emu, 4);
      const lpAddress = args[0];
      const dwSize = Number(args[1]);
      const flAllocationType = Number(args[2]);
      const flProtect = Number(args[3]);

      let allocAddr = lpAddress;
      if (allocAddr === 0n) {
        allocAddr = this.context.nextAllocAddress;
        // Page align size
        const alignedSize = Math.ceil(dwSize / 4096) * 4096;
        this.context.nextAllocAddress += BigInt(alignedSize);
      }

      // Map memory region
      // Simplistic permission mapping: if flProtect is PAGE_EXECUTE_READWRITE (0x40) or PAGE_EXECUTE_READ (0x20)
      const execute = (flProtect & 0x60) !== 0;
      const write = (flProtect & 0x44) !== 0 || flProtect === 0x04; // PAGE_READWRITE / PAGE_EXECUTE_READWRITE
      const read = true;

      emu.memory.map(allocAddr, dwSize, 'VirtualAlloc', { read, write, execute });
      this.context.allocatedRegions.push({ address: allocAddr, size: dwSize });

      emu.cpu.write('rax', allocAddr);
    });

    this.registerWindowsHook('GetProcAddress', (emu) => {
      const args = this.getWindowsArgs(emu, 2);
      const hModule = args[0];
      const lpProcNamePtr = args[1];

      if (lpProcNamePtr === 0n) {
        emu.cpu.write('rax', 0n);
        return;
      }

      const procName = this.readNullTerminatedString(emu.memory, lpProcNamePtr);
      const addr = this.winHookNames.get(procName);
      if (addr !== undefined) {
        emu.cpu.write('rax', addr);
      } else {
        emu.cpu.write('rax', 0n);
      }
    });

    this.registerWindowsHook('GetModuleHandleA', (emu) => {
      const args = this.getWindowsArgs(emu, 1);
      const lpModuleNamePtr = args[0];
      if (lpModuleNamePtr === 0n) {
        // Return dummy handle for current module
        emu.cpu.write('rax', 0x77000000n);
      } else {
        const modName = this.readNullTerminatedString(emu.memory, lpModuleNamePtr);
        emu.cpu.write('rax', 0x77000000n);
      }
    });

    this.registerWindowsHook('LoadLibraryA', (emu) => {
      const args = this.getWindowsArgs(emu, 1);
      const lpLibFileNamePtr = args[0];
      if (lpLibFileNamePtr === 0n) {
        emu.cpu.write('rax', 0n);
        return;
      }
      const libName = this.readNullTerminatedString(emu.memory, lpLibFileNamePtr);
      emu.cpu.write('rax', 0x78000000n); // dummy library handle
    });
  }

  /**
   * Register a custom Windows API hook.
   */
  public registerWindowsHook(name: string, handler: (emu: Emulator) => void): bigint {
    if (this.winHookNames.has(name)) {
      return this.winHookNames.get(name)!;
    }
    const addr = this.nextHookAddress;
    this.winHooks.set(addr, handler);
    this.winHookNames.set(name, addr);
    this.nextHookAddress += 0x1000n; // Place stubs far apart
    return addr;
  }

  /**
   * Check if an address is a registered Windows API hook.
   */
  public hasHook(address: bigint | number): boolean {
    return this.winHooks.has(BigInt(address));
  }

  /**
   * Execute a Windows API hook and perform the 'ret' instruction.
   */
  public executeHook(address: bigint | number, emu: Emulator): void {
    const handler = this.winHooks.get(BigInt(address));
    if (!handler) {
      throw new Error(`No hook registered at address 0x${BigInt(address).toString(16)}`);
    }

    handler(emu);

    // Simulate 'ret' (return to caller)
    let rsp = emu.cpu.read('rsp');
    const returnAddr = emu.memory.read64(rsp);
    rsp += 8n;
    emu.cpu.write('rsp', rsp);
    emu.cpu.write('rip', returnAddr);
  }

  /**
   * Handle standard Linux system call (via 'syscall' instruction).
   * Syscall number is in RAX.
   * Arguments: RDI, RSI, RDX, R10, R8, R9.
   * Return value: RAX.
   */
  public handleSyscall(emu: Emulator): void {
    const syscallNum = emu.cpu.read('rax');

    switch (syscallNum) {
      case 0n: // sys_read
        this.handleSysRead(emu);
        break;
      case 1n: // sys_write
        this.handleSysWrite(emu);
        break;
      case 9n: // sys_mmap
        this.handleSysMmap(emu);
        break;
      case 60n: // sys_exit
        this.handleSysExit(emu);
        break;
      default:
        throw new Error(`Unsupported Linux syscall: ${syscallNum}`);
    }
  }

  private handleSysRead(emu: Emulator): void {
    const fd = emu.cpu.read('rdi');
    const bufPtr = emu.cpu.read('rsi');
    const count = Number(emu.cpu.read('rdx'));

    // Just return 0 (EOF) for read stub, or we could handle simulated input
    emu.cpu.write('rax', 0n);
  }

  private handleSysWrite(emu: Emulator): void {
    const fd = emu.cpu.read('rdi');
    const bufPtr = emu.cpu.read('rsi');
    const count = Number(emu.cpu.read('rdx'));

    const buffer = emu.memory.readBuffer(bufPtr, count);
    const text = new TextDecoder().decode(buffer);

    if (fd === 1n) {
      this.context.stdout += text;
    } else if (fd === 2n) {
      this.context.stderr += text;
    }

    emu.cpu.write('rax', BigInt(count));
  }

  private handleSysMmap(emu: Emulator): void {
    const addr = emu.cpu.read('rdi');
    const length = Number(emu.cpu.read('rsi'));
    const prot = Number(emu.cpu.read('rdx'));
    // r10 has flags, r8 has fd, r9 has offset

    let allocAddr = addr;
    if (allocAddr === 0n) {
      allocAddr = this.context.nextAllocAddress;
      const alignedSize = Math.ceil(length / 4096) * 4096;
      this.context.nextAllocAddress += BigInt(alignedSize);
    }

    // PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4
    const read = (prot & 1) !== 0;
    const write = (prot & 2) !== 0;
    const execute = (prot & 4) !== 0;

    emu.memory.map(allocAddr, length, 'sys_mmap', { read, write, execute });
    this.context.allocatedRegions.push({ address: allocAddr, size: length });

    emu.cpu.write('rax', allocAddr);
  }

  private handleSysExit(emu: Emulator): void {
    const status = Number(emu.cpu.read('rdi'));
    this.context.exitCode = status;
    emu.pause(); // Stop emulator run loop
    emu.cpu.write('rax', 0n);
  }

  /**
   * Helper to retrieve Windows API arguments using MS x64 calling convention.
   * RCX, RDX, R8, R9, followed by stack arguments.
   */
  private getWindowsArgs(emu: Emulator, count: number): bigint[] {
    const args: bigint[] = [];
    const gprs = ['rcx', 'rdx', 'r8', 'r9'];
    for (let i = 0; i < Math.min(count, 4); i++) {
      args.push(emu.cpu.read(gprs[i]));
    }
    if (count > 4) {
      const rsp = emu.cpu.read('rsp');
      // On entry to the hook, rsp points to the return address.
      // Shadow space is 32 bytes (4 QWORDs).
      // Fifth argument is at rsp + 40 (return address at 0, shadow space 8..39)
      for (let i = 4; i < count; i++) {
        const offset = BigInt(40 + (i - 4) * 8);
        args.push(emu.memory.read64(rsp + offset));
      }
    }
    return args;
  }

  /**
   * Helper to read a null-terminated ASCII string from emulator memory.
   */
  private readNullTerminatedString(memory: Memory, address: bigint): string {
    let str = '';
    let addr = address;
    while (true) {
      const char = memory.read8(addr);
      if (char === 0) break;
      str += String.fromCharCode(char);
      addr++;
    }
    return str;
  }
}
