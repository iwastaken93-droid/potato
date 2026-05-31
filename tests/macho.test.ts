import { describe, it, expect } from 'vitest';
import { parseMacho } from '../src/parser/macho.js';
import { DisassemblerRouter } from '../src/disassembler/router.js';

describe('Mach-O Parser Unit Tests', () => {
  it('should successfully parse a valid 64-bit Little Endian Mach-O header', () => {
    // 64-bit header is 32 bytes
    const buffer = new ArrayBuffer(32);
    const view = new DataView(buffer);

    // magic: 0xfeedfacf (LE)
    view.setUint32(0, 0xfeedfacf, true);
    // cputype: CPU_TYPE_X86_64 = 7 | 0x01000000 = 0x01000007
    view.setInt32(4, 0x01000007, true);
    // cpusubtype: CPU_SUBTYPE_MULTIPLE = -1
    view.setInt32(8, -1, true);
    // filetype: MH_EXECUTE = 2
    view.setUint32(12, 2, true);
    // ncmds: 0
    view.setUint32(16, 0, true);
    // sizeofcmds: 0
    view.setUint32(20, 0, true);
    // flags: 0x00000085
    view.setUint32(24, 0x00000085, true);
    // reserved: 0
    view.setUint32(28, 0, true);

    const parsed = parseMacho(buffer);

    expect(parsed.is64Bit).toBe(true);
    expect(parsed.isLittleEndian).toBe(true);
    expect(parsed.header.magic).toBe(0xfeedfacf);
    expect(parsed.header.cputypeName).toBe('x86_64');
    expect(parsed.header.filetypeName).toBe('MH_EXECUTE');
    expect(parsed.loadCommands.length).toBe(0);
    expect(parsed.segments.length).toBe(0);
    expect(parsed.sections.length).toBe(0);
    expect(parsed.symbols.length).toBe(0);
  });

  it('should successfully parse a valid 32-bit Big Endian Mach-O header', () => {
    // 32-bit header is 28 bytes
    const buffer = new ArrayBuffer(28);
    const view = new DataView(buffer);

    // magic: 0xfeedface (BE)
    view.setUint32(0, 0xfeedface, false);
    // cputype: CPU_TYPE_ARM = 12
    view.setInt32(4, 12, false);
    // cpusubtype: 0
    view.setInt32(8, 0, false);
    // filetype: MH_OBJECT = 1
    view.setUint32(12, 1, false);
    // ncmds: 0
    view.setUint32(16, 0, false);
    // sizeofcmds: 0
    view.setUint32(20, 0, false);
    // flags: 0
    view.setUint32(24, 0, false);

    const parsed = parseMacho(buffer);

    expect(parsed.is64Bit).toBe(false);
    expect(parsed.isLittleEndian).toBe(false);
    expect(parsed.header.magic).toBe(0xfeedface);
    expect(parsed.header.cputypeName).toBe('ARM');
    expect(parsed.header.filetypeName).toBe('MH_OBJECT');
  });

  it('should successfully parse segments and sections', () => {
    // 64-bit header (32 bytes) + LC_SEGMENT_64 (72 bytes segment info + 80 bytes for 1 section = 152 bytes)
    const buffer = new ArrayBuffer(32 + 152);
    const view = new DataView(buffer);

    // Header
    view.setUint32(0, 0xfeedfacf, true); // magic LE 64
    view.setUint32(16, 1, true); // ncmds = 1
    view.setUint32(20, 152, true); // sizeofcmds = 152

    // LC_SEGMENT_64 Command
    const cmdOffset = 32;
    view.setUint32(cmdOffset, 0x19, true); // cmd: LC_SEGMENT_64
    view.setUint32(cmdOffset + 4, 152, true); // cmdsize: 152

    // Segment name: "__TEXT"
    const segName = '__TEXT';
    for (let i = 0; i < segName.length; i++) {
      view.setUint8(cmdOffset + 8 + i, segName.charCodeAt(i));
    }

    view.setBigUint64(cmdOffset + 24, 0x1000n, true); // vmaddr
    view.setBigUint64(cmdOffset + 32, 0x1000n, true); // vmsize
    view.setBigUint64(cmdOffset + 40, 0n, true); // fileoff
    view.setBigUint64(cmdOffset + 48, 0x1000n, true); // filesize
    view.setInt32(cmdOffset + 56, 7, true); // maxprot (rwx)
    view.setInt32(cmdOffset + 60, 5, true); // initprot (r-x)
    view.setUint32(cmdOffset + 64, 1, true); // nsects = 1
    view.setUint32(cmdOffset + 68, 0, true); // flags

    // Section 1
    const sectOffset = cmdOffset + 72;
    const sectName = '__text';
    for (let i = 0; i < sectName.length; i++) {
      view.setUint8(sectOffset + i, sectName.charCodeAt(i));
    }
    // segname again
    for (let i = 0; i < segName.length; i++) {
      view.setUint8(sectOffset + 16 + i, segName.charCodeAt(i));
    }
    view.setBigUint64(sectOffset + 32, 0x1000n, true); // addr
    view.setBigUint64(sectOffset + 40, 0x200n, true); // size
    view.setUint32(sectOffset + 48, 512, true); // offset
    view.setUint32(sectOffset + 52, 4, true); // align
    view.setUint32(sectOffset + 56, 0, true); // reloff
    view.setUint32(sectOffset + 60, 0, true); // nreloc
    view.setUint32(sectOffset + 64, 0x80000400, true); // flags (S_REGULAR | etc.)

    const parsed = parseMacho(buffer);
    expect(parsed.segments.length).toBe(1);
    expect(parsed.segments[0].segname).toBe('__TEXT');
    expect(parsed.segments[0].sections.length).toBe(1);
    expect(parsed.segments[0].sections[0].sectname).toBe('__text');
    expect(parsed.segments[0].sections[0].size).toBe(0x200n);
    expect(parsed.sections.length).toBe(1);
    expect(parsed.sections[0].sectname).toBe('__text');
  });

  it('should successfully parse symbols and resolve names', () => {
    // 64-bit header (32 bytes) + LC_SYMTAB (24 bytes) = 56 bytes
    // Symbol table offset: 56
    // 1 symbol entry: 16 bytes. String table: 16 bytes.
    // Total size: 56 + 16 + 16 = 88 bytes.
    const buffer = new ArrayBuffer(88);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // Header
    view.setUint32(0, 0xfeedfacf, true); // magic LE 64
    view.setUint32(16, 1, true); // ncmds = 1
    view.setUint32(20, 24, true); // sizeofcmds = 24

    // LC_SYMTAB Command
    const cmdOffset = 32;
    view.setUint32(cmdOffset, 0x2, true); // cmd: LC_SYMTAB
    view.setUint32(cmdOffset + 4, 24, true); // cmdsize: 24
    view.setUint32(cmdOffset + 8, 56, true); // symoff: 56
    view.setUint32(cmdOffset + 12, 1, true); // nsyms: 1
    view.setUint32(cmdOffset + 16, 72, true); // stroff: 72
    view.setUint32(cmdOffset + 20, 16, true); // strsize: 16

    // Symbol entry (at offset 56)
    view.setUint32(56, 4, true); // n_strx = 4 (starts at offset 4 in string table)
    view.setUint8(60, 0x0f); // n_type = 0x0f (N_SECT | N_EXT)
    view.setUint8(61, 1); // n_sect = 1
    view.setUint16(62, 0, true); // n_desc = 0
    view.setBigUint64(64, 0x1000n, true); // n_value = 0x1000

    // String table (at offset 72)
    // index 0: null, then string at 4: "_foo\0"
    const symName = '_foo';
    for (let i = 0; i < symName.length; i++) {
      bytes[72 + 4 + i] = symName.charCodeAt(i);
    }

    const parsed = parseMacho(buffer);
    expect(parsed.symbols.length).toBe(1);
    expect(parsed.symbols[0].name).toBe('_foo');
    expect(parsed.symbols[0].binding).toBe('global');
  });

  it('should successfully parse a fat/universal binary', () => {
    // Fat header (8 bytes) + 2 arches (40 bytes) = 48 bytes
    // First arch at offset 48, second arch at offset 80
    // Each arch is a mini Mach-O header (32 bytes)
    const buffer = new ArrayBuffer(48 + 32 + 32);
    const view = new DataView(buffer);

    // Fat magic: 0xcafebabe (Big Endian)
    view.setUint32(0, 0xcafebabe, false);
    view.setUint32(4, 2, false); // nfat_arch = 2

    // Arch 1: x86_64
    view.setInt32(8, 0x01000007, false); // cputype
    view.setInt32(12, -1, false); // cpusubtype
    view.setUint32(16, 48, false); // offset: 48
    view.setUint32(20, 32, false); // size: 32
    view.setUint32(24, 3, false); // align: 8

    // Arch 2: ARM64
    view.setInt32(28, 0x0100000c, false); // cputype
    view.setInt32(32, 0, false); // cpusubtype
    view.setUint32(36, 80, false); // offset: 80
    view.setUint32(40, 32, false); // size: 32
    view.setUint32(44, 3, false); // align: 8

    // Mach-O at offset 48: x86_64 LE magic
    view.setUint32(48, 0xfeedfacf, true);
    view.setInt32(52, 0x01000007, true); // cputype x86_64

    // Mach-O at offset 80: ARM64 LE magic
    view.setUint32(80, 0xfeedfacf, true);
    view.setInt32(84, 0x0100000c, true); // cputype arm64

    // Parse default (slice 0)
    const parsed0 = parseMacho(buffer);
    expect(parsed0.header.cputypeName).toBe('x86_64');
    expect(parsed0.fatArches?.length).toBe(2);

    // Parse slice 1
    const parsed1 = parseMacho(buffer, { fatIndex: 1 });
    expect(parsed1.header.cputypeName).toBe('ARM64');
  });

  it('should successfully parse a 64-bit fat/universal binary', () => {
    // 64-bit Fat header (8 bytes) + 2 arches (64 bytes) = 72 bytes
    // First arch at offset 72, second arch at offset 104
    // Each arch is a mini Mach-O header (32 bytes)
    const buffer = new ArrayBuffer(72 + 32 + 32);
    const view = new DataView(buffer);

    // Fat magic: 0xcafebabf (Big Endian)
    view.setUint32(0, 0xcafebabf, false);
    view.setUint32(4, 2, false); // nfat_arch = 2

    // Arch 1: x86_64
    view.setInt32(8, 0x01000007, false); // cputype
    view.setInt32(12, -1, false); // cpusubtype
    view.setBigUint64(16, 72n, false); // offset: 72
    view.setBigUint64(24, 32n, false); // size: 32
    view.setUint32(32, 3, false); // align: 8
    view.setUint32(36, 0, false); // reserved: 0

    // Arch 2: ARM64
    view.setInt32(40, 0x0100000c, false); // cputype
    view.setInt32(44, 0, false); // cpusubtype
    view.setBigUint64(48, 104n, false); // offset: 104
    view.setBigUint64(56, 32n, false); // size: 32
    view.setUint32(64, 3, false); // align: 8
    view.setUint32(68, 0, false); // reserved: 0

    // Mach-O at offset 72: x86_64 LE magic
    view.setUint32(72, 0xfeedfacf, true);
    view.setInt32(76, 0x01000007, true); // cputype x86_64

    // Mach-O at offset 104: ARM64 LE magic
    view.setUint32(104, 0xfeedfacf, true);
    view.setInt32(108, 0x0100000c, true); // cputype arm64

    // Parse default (slice 0)
    const parsed0 = parseMacho(buffer);
    expect(parsed0.header.cputypeName).toBe('x86_64');
    expect(parsed0.fatArches?.length).toBe(2);
    expect(parsed0.fatArches?.[0].offset).toBe(72);
    expect(parsed0.fatArches?.[0].size).toBe(32);

    // Parse slice 1
    const parsed1 = parseMacho(buffer, { fatIndex: 1 });
    expect(parsed1.header.cputypeName).toBe('ARM64');
  });

  it('should throw an error for invalid magic bytes', () => {
    const buffer = new ArrayBuffer(32);
    const view = new DataView(buffer);
    view.setUint32(0, 0x11223344, true);

    expect(() => parseMacho(buffer)).toThrow('Invalid Mach-O Magic');
  });

  describe('Mach-O Router Routing Tests', () => {
    it('should detect x86_64 architecture for LE Mach-O 64-bit', () => {
      const data = new Uint8Array(32);
      const view = new DataView(data.buffer);
      view.setUint32(0, 0xfeedfacf, true); // magic LE 64
      view.setInt32(4, 0x01000007, true); // cputype x86_64

      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('x86_64');
    });

    it('should detect arm architecture for BE Mach-O 32-bit', () => {
      const data = new Uint8Array(32);
      const view = new DataView(data.buffer);
      view.setUint32(0, 0xfeedface, false); // magic BE 32
      view.setInt32(4, 12, false); // cputype arm

      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('arm');
    });

    it('should detect arm architecture from fat Mach-O binary', () => {
      // Fat header (8 bytes) + 1 arch (20 bytes) = 28 bytes
      const data = new Uint8Array(28);
      const view = new DataView(data.buffer);
      view.setUint32(0, 0xcafebabe, false); // fat magic BE
      view.setUint32(4, 1, false); // 1 arch
      view.setInt32(8, 0x0100000c, false); // cputype arm64

      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('arm');
    });

    it('should detect arm architecture from 64-bit fat Mach-O binary', () => {
      // Fat header (8 bytes) + 1 arch (32 bytes) = 40 bytes
      const data = new Uint8Array(40);
      const view = new DataView(data.buffer);
      view.setUint32(0, 0xcafebabf, false); // fat magic BE 64
      view.setUint32(4, 1, false); // 1 arch
      view.setInt32(8, 0x0100000c, false); // cputype arm64

      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('arm');
    });
  });

  it('should successfully parse Mach-O chained fixups (LC_DYLD_CHAINED_FIXUPS)', () => {
    // 32-bit header (32 bytes) + LC_DYLD_CHAINED_FIXUPS (16 bytes) + Chained fixups data (200 bytes)
    const buffer = new ArrayBuffer(32 + 16 + 200);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // Header
    view.setUint32(0, 0xfeedfacf, true); // magic LE 64
    view.setUint32(16, 1, true); // ncmds = 1
    view.setUint32(20, 16, true); // sizeofcmds = 16

    // LC_DYLD_CHAINED_FIXUPS (0x80000034) Command
    const cmdOffset = 32;
    view.setUint32(cmdOffset, 0x80000034, true); // cmd
    view.setUint32(cmdOffset + 4, 16, true); // cmdsize: 16
    view.setUint32(cmdOffset + 8, 48, true); // dataoff: 48
    view.setUint32(cmdOffset + 12, 200, true); // datasize: 200

    // Chained Fixups Data at offset 48
    const dataoff = 48;
    // Header (28 bytes)
    view.setUint32(dataoff, 0, true); // fixupsVersion
    view.setUint32(dataoff + 4, 120, true); // startsOffset
    view.setUint32(dataoff + 8, 28, true); // importsOffset
    view.setUint32(dataoff + 12, 100, true); // symbolsOffset
    view.setUint32(dataoff + 16, 2, true); // importsCount
    view.setUint32(dataoff + 20, 2, true); // importsFormat: 2 (DYLD_CHAINED_IMPORT_ADDEND)
    view.setUint32(dataoff + 24, 0, true); // symbolsFormat

    // Imports Table at offset 48 + 28 = 76
    // Entry 0: libOrdinal = 1, weakImport = false, nameOffset = 0, addend = 10
    // libOrdinal (8 bits) | weakImport (1 bit << 8) | nameOffset (23 bits << 9)
    // 1 | 0 | 0 = 1
    view.setUint32(76, 1, true);
    view.setInt32(80, 10, true); // addend

    // Entry 1: libOrdinal = 2, weakImport = true, nameOffset = 5, addend = -5
    // 2 | (1 << 8) | (5 << 9) = 2 | 256 | 2560 = 2818
    view.setUint32(84, 2818, true);
    view.setInt32(88, -5, true); // addend

    // Symbols table strings at offset 48 + 100 = 148
    const sym1 = '_foo';
    const sym2 = '_bar';
    for (let i = 0; i < sym1.length; i++) {
      bytes[148 + i] = sym1.charCodeAt(i);
    }
    bytes[148 + sym1.length] = 0; // null-terminated

    for (let i = 0; i < sym2.length; i++) {
      bytes[153 + i] = sym2.charCodeAt(i);
    }
    bytes[153 + sym2.length] = 0; // null-terminated

    // Segment Starts in Image at offset 48 + 120 = 168
    // segCount = 2
    view.setUint32(168, 2, true);
    view.setUint32(172, 12, true); // seg_info_offset[0] = 12 -> segment starts at 168 + 12 = 180
    view.setUint32(176, 0, true); // seg_info_offset[1] = 0 -> no fixups

    // Segment Starts at offset 180
    view.setUint32(180, 26, true); // size
    view.setUint16(184, 4096, true); // pageSize
    view.setUint16(186, 6, true); // pointerFormat
    view.setBigUint64(188, 0x1000n, true); // segmentOffset
    view.setUint32(196, 0, true); // maxValidPointer
    view.setUint16(200, 2, true); // pageCount
    view.setUint16(202, 12, true); // pageStarts[0]
    view.setUint16(204, 0xffff, true); // pageStarts[1] (NONE)

    const parsed = parseMacho(buffer);
    expect(parsed.chainedFixups).toBeDefined();
    
    const chained = parsed.chainedFixups!;
    expect(chained.header.fixupsVersion).toBe(0);
    expect(chained.header.importsCount).toBe(2);
    expect(chained.header.importsFormat).toBe(2);

    expect(chained.imports.length).toBe(2);
    expect(chained.imports[0].name).toBe('_foo');
    expect(chained.imports[0].libOrdinal).toBe(1);
    expect(chained.imports[0].weakImport).toBe(false);
    expect(chained.imports[0].addend).toBe(10);

    expect(chained.imports[1].name).toBe('_bar');
    expect(chained.imports[1].libOrdinal).toBe(2);
    expect(chained.imports[1].weakImport).toBe(true);
    expect(chained.imports[1].addend).toBe(-5);

    expect(chained.segments.length).toBe(1);
    expect(chained.segments[0].pageSize).toBe(4096);
    expect(chained.segments[0].pointerFormat).toBe(6);
    expect(chained.segments[0].segmentOffset).toBe(0x1000n);
    expect(chained.segments[0].pageCount).toBe(2);
    expect(chained.segments[0].pageStarts).toEqual([12, 0xffff]);
  });
});
