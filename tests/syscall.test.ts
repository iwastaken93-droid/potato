import { describe, it, expect } from 'vitest';
import { Emulator } from '../src/emulator/emulator.js';
import { SyscallHandler } from '../src/emulator/syscall.js';
import { Instruction } from '../src/disassembler/types.js';

describe('Syscall and Windows API Emulation Tests', () => {
  it('should emulate Linux sys_write to stdout', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    // Load custom text into memory
    const message = 'Hello from Emulator!';
    const msgAddr = 0x5000n;
    const encoder = new TextEncoder();
    const msgBytes = encoder.encode(message);

    emu.memory.map(msgAddr, msgBytes.length, 'data');
    emu.memory.writeBuffer(msgAddr, msgBytes);

    // Setup registers for sys_write
    emu.cpu.write('rax', 1n); // sys_write syscall number
    emu.cpu.write('rdi', 1n); // fd = stdout
    emu.cpu.write('rsi', msgAddr); // buf ptr
    emu.cpu.write('rdx', BigInt(msgBytes.length)); // count

    // Set up syscall instruction
    const inst: Instruction = {
      address: 0x1000,
      mnemonic: 'syscall',
      opStr: '',
      size: 2,
    };
    emu.loadInstructions([inst]);
    emu.cpu.write('rip', 0x1000n);

    // Step the emulator
    const res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(BigInt(msgBytes.length));
    expect(handler.context.stdout).toBe(message);
  });

  it('should emulate Linux sys_exit and halt the emulator', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    emu.cpu.write('rax', 60n); // sys_exit syscall number
    emu.cpu.write('rdi', 123n); // exit status

    const inst: Instruction = {
      address: 0x1000,
      mnemonic: 'syscall',
      opStr: '',
      size: 2,
    };
    emu.loadInstructions([inst]);
    emu.cpu.write('rip', 0x1000n);

    const res = emu.step();
    expect(res.success).toBe(true);
    expect(res.halted).toBe(true);
    expect(handler.context.exitCode).toBe(123);
  });

  it('should emulate Linux sys_mmap to map memory', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    emu.cpu.write('rax', 9n); // sys_mmap syscall number
    emu.cpu.write('rdi', 0n); // addr = 0 (auto-allocated)
    emu.cpu.write('rsi', 4096n); // length = 4096
    emu.cpu.write('rdx', 3n); // prot = PROT_READ (1) | PROT_WRITE (2)

    const inst: Instruction = {
      address: 0x1000,
      mnemonic: 'syscall',
      opStr: '',
      size: 2,
    };
    emu.loadInstructions([inst]);
    emu.cpu.write('rip', 0x1000n);

    const res = emu.step();
    expect(res.success).toBe(true);

    const allocatedAddr = emu.cpu.read('rax');
    expect(allocatedAddr).toBeGreaterThan(0n);

    // Test writing to the newly mapped memory
    emu.memory.write32(allocatedAddr, 0xdeadbeef);
    expect(emu.memory.read32(allocatedAddr)).toBe(0xdeadbeef);
  });

  it('should hook and emulate Windows VirtualAlloc via direct calls', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    // Actually the constructor registers VirtualAlloc. Let's find its address.
    const hookAddr = (handler as any).winHookNames.get('VirtualAlloc');
    expect(hookAddr).toBeDefined();

    // Call VirtualAlloc(0, 8192, MEM_COMMIT, PAGE_READWRITE)
    // MS x64 calling convention: rcx, rdx, r8, r9
    emu.cpu.write('rcx', 0n); // lpAddress
    emu.cpu.write('rdx', 8192n); // dwSize
    emu.cpu.write('r8', 0x1000n); // flAllocationType
    emu.cpu.write('r9', 0x04n); // flProtect = PAGE_READWRITE

    // Setup stack to simulate a call instruction
    const nextRip = 0x1005n;
    let rsp = emu.cpu.read('rsp');
    rsp -= 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, nextRip);

    // Set RIP to the hook address
    emu.cpu.write('rip', hookAddr);

    // Step the emulator (it will execute the hook and simulate 'ret')
    const res = emu.step();
    expect(res.success).toBe(true);

    const allocatedAddr = emu.cpu.read('rax');
    expect(allocatedAddr).toBeGreaterThan(0n);
    expect(emu.cpu.read('rip')).toBe(nextRip); // Returned to nextRip

    // Check we can write/read the allocated memory
    emu.memory.write32(allocatedAddr, 0xcafebabe);
    expect(emu.memory.read32(allocatedAddr)).toBe(0xcafebabe);
  });

  it('should hook and emulate Windows GetProcAddress', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const gpaHookAddr = (handler as any).winHookNames.get('GetProcAddress');
    const vaHookAddr = (handler as any).winHookNames.get('VirtualAlloc');
    expect(gpaHookAddr).toBeDefined();
    expect(vaHookAddr).toBeDefined();

    // Load "VirtualAlloc" string to memory
    const procName = 'VirtualAlloc';
    const nameAddr = 0x6000n;
    const encoder = new TextEncoder();
    const nameBytes = new Uint8Array([...encoder.encode(procName), 0]); // null-terminated
    emu.memory.map(nameAddr, nameBytes.length, 'data');
    emu.memory.writeBuffer(nameAddr, nameBytes);

    // Set up args: hModule = 0 (rcx), lpProcName = 0x6000 (rdx)
    emu.cpu.write('rcx', 0n);
    emu.cpu.write('rdx', nameAddr);

    // Setup stack for return address
    const nextRip = 0x2005n;
    let rsp = emu.cpu.read('rsp');
    rsp -= 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, nextRip);

    emu.cpu.write('rip', gpaHookAddr);

    const res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(vaHookAddr);
    expect(emu.cpu.read('rip')).toBe(nextRip);
  });

  it('should handle GetModuleHandleA and LoadLibraryA', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const gmhHookAddr = (handler as any).winHookNames.get('GetModuleHandleA');
    const llHookAddr = (handler as any).winHookNames.get('LoadLibraryA');
    expect(gmhHookAddr).toBeDefined();
    expect(llHookAddr).toBeDefined();

    // 1. GMH with NULL
    emu.cpu.write('rcx', 0n);
    let rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', gmhHookAddr);
    let res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0x77000000n);

    // 2. GMH with a module name
    const modName = 'kernel32.dll';
    const modAddr = 0x6000n;
    const modBytes = new Uint8Array([...new TextEncoder().encode(modName), 0]);
    emu.memory.map(modAddr, modBytes.length, 'data');
    emu.memory.writeBuffer(modAddr, modBytes);
    emu.cpu.write('rcx', modAddr);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', gmhHookAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0x77000000n);

    // 3. LoadLibraryA with NULL
    emu.cpu.write('rcx', 0n);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', llHookAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0n);

    // 4. LoadLibraryA with library name
    emu.cpu.write('rcx', modAddr);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', llHookAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0x78000000n);
  });

  it('should hook and execute with more than 4 arguments (getWindowsArgs stack logic)', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    let argsPassed: bigint[] = [];
    const customHookAddr = handler.registerWindowsHook(
      'TestHookFiveArgs',
      (e) => {
        argsPassed = (handler as any).getWindowsArgs(e, 5);
      }
    );

    // Call reset to initialize default stack map and initial RSP first
    emu.reset(0x1000);

    // RCX, RDX, R8, R9, stack (rsp + 40)
    emu.cpu.write('rcx', 11n);
    emu.cpu.write('rdx', 22n);
    emu.cpu.write('r8', 33n);
    emu.cpu.write('r9', 44n);

    let rsp = emu.cpu.read('rsp');

    // Simulate pushing return address: decrement RSP
    rsp -= 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);

    // 5th argument goes at rsp + 40
    emu.memory.write64(rsp + 40n, 55n);

    emu.cpu.write('rip', customHookAddr);
    const res = emu.step();
    expect(res.success).toBe(true);
    expect(argsPassed).toEqual([11n, 22n, 33n, 44n, 55n]);
  });

  it('should handle Windows VirtualAlloc with custom/non-zero address and permissions mapping', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const hookAddr = (handler as any).winHookNames.get('VirtualAlloc');

    // PAGE_EXECUTE_READWRITE (0x40) at a specific address (0x40000000n)
    emu.cpu.write('rcx', 0x40000000n); // lpAddress
    emu.cpu.write('rdx', 4096n); // dwSize
    emu.cpu.write('r8', 0x1000n); // MEM_COMMIT
    emu.cpu.write('r9', 0x40n); // flProtect = PAGE_EXECUTE_READWRITE

    let rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', hookAddr);

    let res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0x40000000n);

    // Let's test the permissions of the mapped area: should have write and execute
    const region = emu.memory.getRegionAt(0x40000000n);
    expect(region).not.toBeNull();
    expect(region?.permissions.read).toBe(true);
    expect(region?.permissions.write).toBe(true);
    expect(region?.permissions.execute).toBe(true);
  });

  it('should handle GetProcAddress for invalid pointer or non-existent hooks', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const hookAddr = (handler as any).winHookNames.get('GetProcAddress');

    // NULL pointer
    emu.cpu.write('rcx', 0n);
    emu.cpu.write('rdx', 0n);
    let rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', hookAddr);
    let res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0n);

    // Non-existent hook name
    const name = 'NonExistentFunc';
    const nameAddr = 0x6000n;
    const nameBytes = new Uint8Array([...new TextEncoder().encode(name), 0]);
    emu.memory.map(nameAddr, nameBytes.length, 'data');
    emu.memory.writeBuffer(nameAddr, nameBytes);

    emu.cpu.write('rcx', 0n);
    emu.cpu.write('rdx', nameAddr);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', hookAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0n);
  });

  it('should throw error when executing non-existent hook address', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    expect(() => handler.executeHook(0xdeadbeefn, emu)).toThrow(
      'No hook registered at address'
    );
  });

  it('should register hook name only once and return existing hook address', () => {
    const handler = new SyscallHandler();
    const addr1 = handler.registerWindowsHook('MyFunc', () => {});
    const addr2 = handler.registerWindowsHook('MyFunc', () => {});
    expect(addr1).toBe(addr2);
  });

  it('should throw error for unsupported Linux syscall', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    emu.cpu.write('rax', 999n); // unsupported syscall
    expect(() => handler.handleSyscall(emu)).toThrow(
      'Unsupported Linux syscall: 999'
    );
  });

  it('should write to stderr for sys_write fd=2', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const message = 'Error message!';
    const msgAddr = 0x5000n;
    const msgBytes = new TextEncoder().encode(message);
    emu.memory.map(msgAddr, msgBytes.length, 'data');
    emu.memory.writeBuffer(msgAddr, msgBytes);

    emu.cpu.write('rax', 1n); // sys_write
    emu.cpu.write('rdi', 2n); // fd = stderr
    emu.cpu.write('rsi', msgAddr);
    emu.cpu.write('rdx', BigInt(msgBytes.length));

    handler.handleSyscall(emu);
    expect(handler.context.stderr).toBe(message);
    expect(emu.cpu.read('rax')).toBe(BigInt(msgBytes.length));
  });

  it('should return 0 EOF for sys_read', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    emu.cpu.write('rax', 0n); // sys_read
    emu.cpu.write('rdi', 0n); // fd
    emu.cpu.write('rsi', 0x5000n); // buf
    emu.cpu.write('rdx', 100n); // count

    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(0n);
  });

  it('should emulate Linux sys_mprotect and change permissions', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const addr = 0x4000n;
    emu.memory.map(addr, 4096, 'test_region', { read: true, write: true, execute: false });

    // mprotect to read/execute only (PROT_READ = 1, PROT_EXEC = 4)
    emu.cpu.write('rax', 10n); // sys_mprotect
    emu.cpu.write('rdi', addr);
    emu.cpu.write('rsi', 4096n);
    emu.cpu.write('rdx', 5n); // 1 | 4

    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(0n);

    const region = emu.memory.getRegionAt(addr);
    expect(region).not.toBeNull();
    expect(region?.permissions.read).toBe(true);
    expect(region?.permissions.write).toBe(false);
    expect(region?.permissions.execute).toBe(true);

    // Test failure for non-existent region
    emu.cpu.write('rax', 10n);
    emu.cpu.write('rdi', 0x99990000n);
    emu.cpu.write('rsi', 4096n);
    emu.cpu.write('rdx', 5n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(18446744073709551615n);
  });

  it('should emulate Linux sys_nanosleep, sys_clone, and sys_wait4', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    // 1. nanosleep
    emu.cpu.write('rax', 35n);
    emu.cpu.write('rdi', 0n);
    emu.cpu.write('rsi', 0n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(0n);

    // 2. clone
    emu.cpu.write('rax', 56n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(5678n);

    // 3. wait4
    const statusAddr = 0x6000n;
    emu.memory.map(statusAddr, 4, 'status');
    emu.cpu.write('rax', 61n);
    emu.cpu.write('rdi', -1n);
    emu.cpu.write('rsi', statusAddr);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(5678n);
    expect(emu.memory.read32(statusAddr)).toBe(0);
  });

  it('should hook and emulate Windows VirtualProtect', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const vpAddr = (handler as any).winHookNames.get('VirtualProtect');
    expect(vpAddr).toBeDefined();

    const memAddr = 0x50000000n;
    emu.memory.map(memAddr, 4096, 'vp_test', { read: true, write: true, execute: false });

    const oldProtectAddr = 0x6000n;
    emu.memory.map(oldProtectAddr, 4, 'old_protect');

    // Call VirtualProtect(memAddr, 4096, PAGE_EXECUTE_READ = 0x20, oldProtectAddr)
    emu.cpu.write('rcx', memAddr);
    emu.cpu.write('rdx', 4096n);
    emu.cpu.write('r8', 0x20n);
    emu.cpu.write('r9', oldProtectAddr);

    let rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', vpAddr);

    const res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(1n);
    expect(emu.memory.read32(oldProtectAddr)).toBe(0x04); // PAGE_READWRITE

    const region = emu.memory.getRegionAt(memAddr);
    expect(region?.permissions.read).toBe(true);
    expect(region?.permissions.write).toBe(false);
    expect(region?.permissions.execute).toBe(true);

    // Call VirtualProtect with non-existent address
    emu.cpu.write('rcx', 0x99990000n);
    emu.cpu.write('rdx', 4096n);
    emu.cpu.write('r8', 0x20n);
    emu.cpu.write('r9', 0n);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', vpAddr);
    emu.step();
    expect(emu.cpu.read('rax')).toBe(0n);
  });

  it('should hook and emulate Windows CreateFileA and CloseHandle', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const cfAddr = (handler as any).winHookNames.get('CreateFileA');
    const chAddr = (handler as any).winHookNames.get('CloseHandle');
    expect(cfAddr).toBeDefined();
    expect(chAddr).toBeDefined();

    // Setup CreateFileA with dummy name
    const fileName = 'dummy.txt';
    const nameAddr = 0x7000n;
    const nameBytes = new Uint8Array([...new TextEncoder().encode(fileName), 0]);
    emu.memory.map(nameAddr, nameBytes.length, 'filename');
    emu.memory.writeBuffer(nameAddr, nameBytes);

    emu.cpu.write('rcx', nameAddr); // lpFileName
    emu.cpu.write('rdx', 0n);
    emu.cpu.write('r8', 0n);
    emu.cpu.write('r9', 0n);

    emu.reset(0x1000);
    let rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);

    // 5th, 6th, 7th args on stack
    emu.memory.write64(rsp + 40n, 0n);
    emu.memory.write64(rsp + 48n, 0n);
    emu.memory.write64(rsp + 56n, 0n);

    emu.cpu.write('rip', cfAddr);
    let res = emu.step();
    expect(res.success).toBe(true);
    const fileHandle = emu.cpu.read('rax');
    expect(fileHandle).toBe(0x444n);

    // CloseHandle
    emu.cpu.write('rcx', fileHandle);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', chAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(1n);
  });

  it('should hook and emulate new Windows APIs: GetLastError, GetStdHandle, WriteFile, ReadFile, ExitProcess, Sleep', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    const gleAddr = (handler as any).winHookNames.get('GetLastError');
    const gshAddr = (handler as any).winHookNames.get('GetStdHandle');
    const wfAddr = (handler as any).winHookNames.get('WriteFile');
    const rfAddr = (handler as any).winHookNames.get('ReadFile');
    const epAddr = (handler as any).winHookNames.get('ExitProcess');
    const sleepAddr = (handler as any).winHookNames.get('Sleep');

    // 1. GetLastError
    emu.reset(0x1000);
    let rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', gleAddr);
    let res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0n);

    // 2. GetStdHandle
    emu.reset(0x1000);
    emu.cpu.write('rcx', 0xfffffff5n); // STD_OUTPUT_HANDLE
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', gshAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0x200n);

    // 3. WriteFile
    emu.reset(0x1000);
    const message = 'WinWrite';
    const msgAddr = 0x5000n;
    const msgBytes = new TextEncoder().encode(message);
    emu.memory.map(msgAddr, msgBytes.length, 'data');
    emu.memory.writeBuffer(msgAddr, msgBytes);

    const writtenAddr = 0x6000n;
    emu.memory.map(writtenAddr, 4, 'written');

    emu.cpu.write('rcx', 0x200n); // hFile (stdout)
    emu.cpu.write('rdx', msgAddr); // lpBuffer
    emu.cpu.write('r8', BigInt(msgBytes.length)); // nNumberOfBytesToWrite
    emu.cpu.write('r9', writtenAddr); // lpNumberOfBytesWritten

    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    // WriteFile takes 5 args, so 5th is on stack at rsp + 40
    emu.memory.write64(rsp + 40n, 0n); // lpOverlapped

    emu.cpu.write('rip', wfAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(1n);
    expect(emu.memory.read32(writtenAddr)).toBe(message.length);
    expect(handler.context.stdout).toBe(message);

    // 4. ReadFile
    emu.reset(0x1000);
    emu.cpu.write('rcx', 0x100n); // hFile
    emu.cpu.write('rdx', msgAddr); // lpBuffer
    emu.cpu.write('r8', 10n); // nNumberOfBytesToRead
    emu.cpu.write('r9', writtenAddr); // lpNumberOfBytesRead

    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.memory.write64(rsp + 40n, 0n); // lpOverlapped

    emu.cpu.write('rip', rfAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(1n);
    expect(emu.memory.read32(writtenAddr)).toBe(0);

    // 5. Sleep
    emu.reset(0x1000);
    emu.cpu.write('rcx', 100n);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', sleepAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0n);

    // 6. ExitProcess
    emu.reset(0x1000);
    emu.cpu.write('rcx', 42n);
    rsp = emu.cpu.read('rsp') - 8n;
    emu.cpu.write('rsp', rsp);
    emu.memory.write64(rsp, 0x9999n);
    emu.cpu.write('rip', epAddr);
    res = emu.step();
    expect(res.success).toBe(true);
    expect(res.halted).toBe(true);
    expect(handler.context.exitCode).toBe(42);
  });

  it('should emulate expanded Linux syscalls: sys_close, sys_brk, sys_getpid, sys_getuid, sys_getgid, sys_clock_gettime', () => {
    const emu = new Emulator();
    const handler = new SyscallHandler();
    emu.syscallHandler = handler;

    // 1. sys_close (case 3)
    emu.cpu.write('rax', 3n);
    emu.cpu.write('rdi', 10n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(0n);

    // 2. sys_brk (case 12) with 0
    emu.cpu.write('rax', 12n);
    emu.cpu.write('rdi', 0n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(0x50000000n);

    // sys_brk with non-zero
    emu.cpu.write('rax', 12n);
    emu.cpu.write('rdi', 0x60000000n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(0x60000000n);

    // 3. sys_getpid (case 39)
    emu.cpu.write('rax', 39n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(1234n);

    // 4. sys_getuid (case 102)
    emu.cpu.write('rax', 102n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(1000n);

    // 5. sys_getgid (case 104)
    emu.cpu.write('rax', 104n);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(1000n);

    // 6. sys_clock_gettime (case 228)
    const tpAddr = 0x7000n;
    emu.memory.map(tpAddr, 16, 'timespec');
    emu.cpu.write('rax', 228n);
    emu.cpu.write('rdi', 0n);
    emu.cpu.write('rsi', tpAddr);
    handler.handleSyscall(emu);
    expect(emu.cpu.read('rax')).toBe(0n);
    expect(emu.memory.read64(tpAddr)).toBe(1600000000n);
    expect(emu.memory.read64(tpAddr + 8n)).toBe(0n);
  });
});

