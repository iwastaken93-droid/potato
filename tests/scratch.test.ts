import { describe, it } from 'vitest';
import { Emulator } from '../src/emulator/emulator.js';

describe('scratch test', () => {
  it('run step', () => {
    const emu = new Emulator();
    emu.reset(0x1000);
    emu.memory.map(0x1000n, 1);
    emu.memory.writeBuffer(0x1000n, new Uint8Array([0x90]));
    console.log("Memory at 0x1000:", emu.memory.read8(0x1000n).toString(16));

    const res = emu.step();
    console.log("Step result:", JSON.stringify(res));
    console.log("RIP:", emu.cpu.read('rip').toString());
  });
});
