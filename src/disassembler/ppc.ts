import { Instruction, Operand } from './types.js';

function signExtend(value: number, bits: number): number {
  const shift = 32 - bits;
  return (value << shift) >> shift;
}

/**
 * Lightweight PowerPC (PPC) 32-bit disassembler.
 */
export function disassemblePpc(data: Uint8Array, baseAddress: number): Instruction[] {
  const instructions: Instruction[] = [];
  const regs = Array.from({ length: 32 }, (_, i) => `r${i}`);
  const crs = Array.from({ length: 8 }, (_, i) => `cr${i}`);

  let i = 0;
  // PPC instructions are 4-byte aligned and 4 bytes size
  while (i + 3 < data.length) {
    const addr = baseAddress + i;
    // PPC is Big Endian by default
    const val =
      ((data[i] << 24) |
        (data[i + 1] << 16) |
        (data[i + 2] << 8) |
        data[i + 3]) >>>
      0;

    let mnemonic = 'db';
    let opStr = `0x${val.toString(16).padStart(8, '0')}`;
    let operands: Operand[] = [];
    const size = 4;

    const opcode = (val >>> 26) & 0x3f;

    // Field extraction helper
    const getRT = () => (val >>> 21) & 0x1f;
    const getRA = () => (val >>> 16) & 0x1f;
    const getRB = () => (val >>> 11) & 0x1f;
    const getXO = () => (val >>> 1) & 0x3ff; // 10-bit extended opcode (bits 1-10)
    const getSI = () => signExtend(val & 0xffff, 16);
    const getD = () => signExtend(val & 0xffff, 16);

    switch (opcode) {
      case 14: { // ADDI
        const rt = getRT();
        const ra = getRA();
        const si = getSI();
        mnemonic = 'addi';
        const rtName = regs[rt];
        const raName = ra === 0 ? '0' : regs[ra];
        opStr = `${rtName}, ${raName}, ${si}`;
        operands = [
          { type: 'reg', reg: rtName },
          { type: ra === 0 ? 'imm' : 'reg', reg: ra === 0 ? undefined : raName, imm: ra === 0 ? 0 : undefined },
          { type: 'imm', imm: si }
        ];
        break;
      }
      case 31: { // XO-type (e.g. ADD, SUBF, CMPW)
        const xo = getXO();
        const rt = getRT();
        const ra = getRA();
        const rb = getRB();
        const rtName = regs[rt];
        const raName = regs[ra];
        const rbName = regs[rb];

        if (xo === 266) { // ADD
          mnemonic = 'add';
          opStr = `${rtName}, ${raName}, ${rbName}`;
          operands = [
            { type: 'reg', reg: rtName },
            { type: 'reg', reg: raName },
            { type: 'reg', reg: rbName }
          ];
        } else if (xo === 40) { // SUBF
          mnemonic = 'subf';
          opStr = `${rtName}, ${raName}, ${rbName}`;
          operands = [
            { type: 'reg', reg: rtName },
            { type: 'reg', reg: raName },
            { type: 'reg', reg: rbName }
          ];
        } else if (xo === 0) { // CMP / CMPW
          const bf = (val >>> 23) & 0x7;
          const l = (val >>> 21) & 0x1;
          const crName = crs[bf];
          if (l === 0) { // 32-bit compare -> CMPW
            mnemonic = 'cmpw';
            if (bf === 0) {
              opStr = `${raName}, ${rbName}`;
              operands = [
                { type: 'reg', reg: raName },
                { type: 'reg', reg: rbName }
              ];
            } else {
              opStr = `${crName}, ${raName}, ${rbName}`;
              operands = [
                { type: 'reg', reg: crName },
                { type: 'reg', reg: raName },
                { type: 'reg', reg: rbName }
              ];
            }
          }
        }
        break;
      }
      case 32: { // LWZ
        const rt = getRT();
        const ra = getRA();
        const d = getD();
        mnemonic = 'lwz';
        const rtName = regs[rt];
        const raName = regs[ra];
        opStr = `${rtName}, ${d}(${raName})`;
        operands = [
          { type: 'reg', reg: rtName },
          { type: 'mem', mem: { base: raName, disp: d } }
        ];
        break;
      }
      case 36: { // STW
        const rs = getRT(); // RS field is same position as RT
        const ra = getRA();
        const d = getD();
        mnemonic = 'stw';
        const rsName = regs[rs];
        const raName = regs[ra];
        opStr = `${rsName}, ${d}(${raName})`;
        operands = [
          { type: 'reg', reg: rsName },
          { type: 'mem', mem: { base: raName, disp: d } }
        ];
        break;
      }
      case 18: { // B / BL
        const lk = val & 0x1;
        const aa = (val >>> 1) & 0x1;
        const li = signExtend(val & 0x3fffffc, 26);
        const target = aa === 1 ? li : addr + li;
        mnemonic = lk === 1 ? 'bl' : 'b';
        opStr = `0x${target.toString(16)}`;
        operands = [
          { type: 'imm', imm: target }
        ];
        break;
      }
      case 16: { // BC / BCL
        const bo = (val >>> 21) & 0x1f;
        const bi = (val >>> 16) & 0x1f;
        const lk = val & 0x1;
        const aa = (val >>> 1) & 0x1;
        const bd = signExtend(val & 0xfffc, 16);
        const target = aa === 1 ? bd : addr + bd;
        mnemonic = lk === 1 ? 'bcl' : 'bc';
        opStr = `${bo}, ${bi}, 0x${target.toString(16)}`;
        operands = [
          { type: 'imm', imm: bo },
          { type: 'imm', imm: bi },
          { type: 'imm', imm: target }
        ];
        break;
      }
    }

    instructions.push({
      address: addr,
      bytes: data.slice(i, i + 4),
      mnemonic,
      opStr,
      operands,
      size
    });

    i += 4;
  }

  // Handle remaining bytes if input is not multiple of 4
  if (i < data.length) {
    const remaining = data.slice(i);
    instructions.push({
      address: baseAddress + i,
      bytes: remaining,
      mnemonic: 'db',
      opStr: Array.from(remaining)
        .map(b => `0x${b.toString(16).padStart(2, '0')}`)
        .join(', '),
      operands: [],
      size: remaining.length
    });
  }

  return instructions;
}
