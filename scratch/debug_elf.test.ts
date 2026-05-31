import { describe, it } from 'vitest';
import { parseElf } from '../src/parser/elf.js';

describe('ELF parser debug', () => {
  it('debugs', () => {
    const shOff = 64;
    const shNum = 7;
    const shentSize = 64;

    const shstrtabOffset = shOff + shNum * shentSize;
    const shstrtabSize = 64;
    const dynstrOffset = shstrtabOffset + shstrtabSize;
    const dynstrSize = 64;
    const dynsymOffset = dynstrOffset + dynstrSize;
    const dynsymSize = 2 * 24;
    const relaPltOffset = dynsymOffset + dynsymSize;
    const relaPltSize = 24;
    const pltOffset = relaPltOffset + relaPltSize;
    const pltSize = 32;
    const gotPltOffset = pltOffset + pltSize;
    const gotPltSize = 16;

    const totalSize = gotPltOffset + gotPltSize;
    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // Little Endian
    bytes[7] = 0;
    view.setUint16(16, 3, true);
    view.setUint16(18, 183, true); // AArch64
    view.setBigUint64(40, BigInt(shOff), true);
    view.setUint16(58, shentSize, true);
    view.setUint16(60, shNum, true);
    view.setUint16(62, 1, true);

    const sh1 = shOff + shentSize;
    view.setUint32(sh1, 1, true);
    view.setUint32(sh1 + 4, 3, true);
    view.setBigUint64(sh1 + 24, BigInt(shstrtabOffset), true);
    view.setBigUint64(sh1 + 32, BigInt(shstrtabSize), true);

    const sh2 = shOff + 2 * shentSize;
    view.setUint32(sh2, 11, true);
    view.setUint32(sh2 + 4, 11, true);
    view.setBigUint64(sh2 + 24, BigInt(dynsymOffset), true);
    view.setBigUint64(sh2 + 32, BigInt(dynsymSize), true);
    view.setUint32(sh2 + 40, 3, true);
    view.setBigUint64(sh2 + 56, 24n, true);

    const sh3 = shOff + 3 * shentSize;
    view.setUint32(sh3, 19, true);
    view.setUint32(sh3 + 4, 3, true);
    view.setBigUint64(sh3 + 24, BigInt(dynstrOffset), true);
    view.setBigUint64(sh3 + 32, BigInt(dynstrSize), true);

    const sh4 = shOff + 4 * shentSize;
    view.setUint32(sh4, 27, true);
    view.setUint32(sh4 + 4, 4, true); // SHT_RELA
    view.setBigUint64(sh4 + 24, BigInt(relaPltOffset), true);
    view.setBigUint64(sh4 + 32, BigInt(relaPltSize), true);
    view.setUint32(sh4 + 40, 2, true);
    view.setBigUint64(sh4 + 56, 24n, true);

    const sh5 = shOff + 5 * shentSize;
    view.setUint32(sh5, 37, true);
    view.setUint32(sh5 + 4, 1, true);
    view.setBigUint64(sh5 + 16, 0x1000n, true); // shAddr (align 4096)
    view.setBigUint64(sh5 + 24, BigInt(pltOffset), true);
    view.setBigUint64(sh5 + 32, BigInt(pltSize), true);

    const sh6 = shOff + 6 * shentSize;
    view.setUint32(sh6, 42, true);
    view.setUint32(sh6 + 4, 1, true);
    view.setBigUint64(sh6 + 16, 0x3000n, true); // shAddr
    view.setBigUint64(sh6 + 24, BigInt(gotPltOffset), true);
    view.setBigUint64(sh6 + 32, BigInt(gotPltSize), true);

    const shstrtab = new Uint8Array(buffer, shstrtabOffset, shstrtabSize);
    const writeStr = (tab, offset, str) => {
      for (let i = 0; i < str.length; i++) tab[offset + i] = str.charCodeAt(i);
      tab[offset + str.length] = 0;
    };
    writeStr(shstrtab, 1, '.shstrtab');
    writeStr(shstrtab, 11, '.dynsym');
    writeStr(shstrtab, 19, '.dynstr');
    writeStr(shstrtab, 27, '.rela.plt');
    writeStr(shstrtab, 37, '.plt');
    writeStr(shstrtab, 42, '.got.plt');

    const dynstr = new Uint8Array(buffer, dynstrOffset, dynstrSize);
    writeStr(dynstr, 1, 'baz');

    const sym1Addr = dynsymOffset + 24;
    view.setUint32(sym1Addr, 1, true);
    view.setUint8(sym1Addr + 4, (1 << 4) | 2);
    view.setUint8(sym1Addr + 5, 0);
    view.setUint16(sym1Addr + 6, 0, true);
    view.setBigUint64(sym1Addr + 8, 0n, true);
    view.setBigUint64(sym1Addr + 16, 0n, true);

    // Relocation at gotAddress 0x3008 pointing to baz
    view.setBigUint64(relaPltOffset, 0x3008n, true);
    view.setBigUint64(relaPltOffset + 8, (1n << 32n) | 1026n, true); // R_AARCH64_JUMP_SLOT (1026)
    view.setBigInt64(relaPltOffset + 16, 0n, true);

    const pltEntryOffset = pltOffset + 16;
    view.setUint32(pltEntryOffset, 0xd0000010, true);
    view.setUint32(pltEntryOffset + 4, 0xf9400611, true);

    const parsed = parseElf(buffer);
    console.log('parsed relocs:', parsed.relocations);
    console.log('parsed symbols:', parsed.symbols);
    console.log('parsed got:', parsed.gotEntries);
  });
});
