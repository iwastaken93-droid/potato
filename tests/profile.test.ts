import { describe, it } from 'vitest';
import { PEParser } from '../src/parser/pe.js';
import { parseElf } from '../src/parser/elf.js';
import { disassembleRiscv } from '../src/disassembler/riscv.js';
import { disassembleCil } from '../src/disassembler/dotnetIl.js';

describe('Performance Profiling Suite', () => {
  it('runs hotpath benchmarks and reports bottlenecks', () => {
    console.log('\n=== H E A D L E S S  P R O F I L I N G ===\n');

    // 1. PE parser prep
    const peBuffer = new ArrayBuffer(352);
    const peView = new DataView(peBuffer);
    const peBytes = new Uint8Array(peBuffer);
    peBytes[0] = 0x4d; // 'M'
    peBytes[1] = 0x5a; // 'Z'
    peView.setUint32(60, 64, true);
    peView.setUint32(64, 0x00004550, true);
    const coffOffset = 68;
    peView.setUint16(coffOffset, 0x14c, true);
    peView.setUint16(coffOffset + 2, 1, true);
    peView.setUint16(coffOffset + 16, 224, true);
    const optionalOffset = coffOffset + 20;
    peView.setUint16(optionalOffset, 0x10b, true);
    const winOffset = optionalOffset + 28;
    peView.setUint32(winOffset, 0x400000, true);
    peView.setUint32(winOffset + 4, 0x1000, true);
    peView.setUint32(winOffset + 8, 0x200, true);
    peView.setUint32(winOffset + 28, 0x8000, true);
    peView.setUint32(winOffset + 32, 0x400, true);

    // 2. ELF parser prep
    const elfBuffer = new ArrayBuffer(64);
    const elfView = new DataView(elfBuffer);
    const elfBytes = new Uint8Array(elfBuffer);
    elfBytes[0] = 0x7f;
    elfBytes[1] = 0x45;
    elfBytes[2] = 0x4c;
    elfBytes[3] = 0x46;
    elfBytes[4] = 2; // 64-bit
    elfBytes[5] = 1; // Little Endian
    elfView.setUint16(16, 2, true); // EXEC
    elfView.setUint16(18, 62, true); // AMD64
    elfView.setBigUint64(24, 0x1000n, true);
    elfView.setUint16(52, 64, true); // header size

    // 3. RISC-V disassembly prep
    const riscvBytes = new Uint8Array([
      0x93, 0x00, 0xa1, 0x00, // addi x1, x2, 10
      0x01, 0x00,             // c.nop
      0x95, 0x00,             // c.addi x1, 5
      0xf9, 0x51,             // c.li x3, -2
      0xc0, 0x40              // c.lw x8, 4(x9)
    ]);

    // 4. .NET IL disassembly prep
    const cilBytes = new Uint8Array([
      0x58,                   // add
      0xfe, 0x09, 0x05, 0x00, // ldarg 5
      0x2e, 0x05,             // beq.s +5
      0x1f, 0x7f              // ldc.i4.s 127
    ]);

    const runBenchmark = (name: string, fn: () => void, iterations: number) => {
      // Warm up
      for (let i = 0; i < Math.floor(iterations * 0.1); i++) {
        fn();
      }

      const start = performance.now();
      for (let i = 0; i < iterations; i++) {
        fn();
      }
      const end = performance.now();
      const duration = end - start;
      const avg = duration / iterations;
      const opsPerSec = (iterations / duration) * 1000;

      return { name, duration, avg, opsPerSec, iterations };
    };

    const results = [
      runBenchmark('PE Parser Parse Header', () => {
        const parser = new PEParser(peBuffer);
        parser.parse();
      }, 20000),
      runBenchmark('ELF Parser Parse Header', () => {
        parseElf(elfBuffer);
      }, 20000),
      runBenchmark('RISC-V Disassembler Loop', () => {
        disassembleRiscv(riscvBytes, 0x1000);
      }, 10000),
      runBenchmark('.NET IL Disassembler Loop', () => {
        disassembleCil(cilBytes, 0x1000);
      }, 10000)
    ];

    console.table(
      results.map((r) => ({
        Benchmark: r.name,
        Iterations: r.iterations,
        'Total (ms)': r.duration.toFixed(2),
        'Avg (ms)': r.avg.toFixed(4),
        'Ops/sec': Math.round(r.opsPerSec).toLocaleString()
      }))
    );

    // Identify bottleneck
    const slowest = [...results].sort((a, b) => b.avg - a.avg)[0];
    console.log(`\nBottleneck Identified: ${slowest.name} (Avg ${slowest.avg.toFixed(4)} ms per run)`);
  });
});
