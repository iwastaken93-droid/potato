import fs from 'fs';

const opcodes = JSON.parse(fs.readFileSync('opcodes.json', 'utf8'));

const decoderTemplate = `import { Instruction, Operand } from './types.js';

export interface CilOpcode {
  op1: number;
  op2: number | null;
  mnemonic: string;
  operandType: 'none' | 'brtarget_s' | 'brtarget' | 'i1' | 'i2' | 'i4' | 'i8' | 'r4' | 'r8' | 'tok' | 'var_s' | 'var' | 'switch';
  description: string;
}

const OPCODES: CilOpcode[] = [
__OPCODE_LIST__
];

// Quick lookup maps
const singleByteOpcodes = new Map<number, CilOpcode>();
const twoByteOpcodes = new Map<number, CilOpcode>();

for (const op of OPCODES) {
  if (op.op2 === null) {
    singleByteOpcodes.set(op.op1, op);
  } else {
    twoByteOpcodes.set(op.op2, op);
  }
}

export function disassembleCil(
  data: Uint8Array,
  baseAddress: number
): Instruction[] {
  const instructions: Instruction[] = [];
  let i = 0;

  function getInt8(offset: number): number {
    const val = data[offset];
    return val >= 128 ? val - 256 : val;
  }

  function getUint8(offset: number): number {
    return data[offset];
  }

  function getUint16(offset: number): number {
    return data[offset] | (data[offset + 1] << 8);
  }

  function getInt32(offset: number): number {
    const val = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
    return val | 0;
  }

  function getUint32(offset: number): number {
    return (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
  }

  function getBigInt64(offset: number): bigint {
    const low = getUint32(offset);
    const high = getUint32(offset + 4);
    return (BigInt(high) << 32n) | BigInt(low);
  }

  function getFloat32(offset: number): number {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    for (let k = 0; k < 4; k++) {
      view.setUint8(k, data[offset + k]);
    }
    return view.getFloat32(0, true);
  }

  function getFloat64(offset: number): number {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    for (let k = 0; k < 8; k++) {
      view.setUint8(k, data[offset + k]);
    }
    return view.getFloat64(0, true);
  }

  while (i < data.length) {
    const addr = baseAddress + i;
    const startIdx = i;

    let op1 = data[i];
    let op2: number | null = null;
    let opcodeInfo: CilOpcode | undefined;

    if (op1 === 0xFE && i + 1 < data.length) {
      op2 = data[i + 1];
      opcodeInfo = twoByteOpcodes.get(op2);
    } else {
      opcodeInfo = singleByteOpcodes.get(op1);
    }

    if (!opcodeInfo) {
      // Unknown opcode, treat byte as raw data
      const rawByte = data[i];
      instructions.push({
        address: addr,
        bytes: data.slice(i, i + 1),
        mnemonic: 'db',
        opStr: \`0x\${rawByte.toString(16).padStart(2, '0')}\`,
        operands: [],
        size: 1,
      });
      i++;
      continue;
    }

    const opSize = opcodeInfo.op2 === null ? 1 : 2;
    i += opSize;

    let opStr = '';
    const operands: Operand[] = [];
    let valid = true;

    switch (opcodeInfo.operandType) {
      case 'none': {
        break;
      }
      case 'brtarget_s': {
        if (i < data.length) {
          const offset = getInt8(i);
          i += 1;
          const target = addr + opSize + 1 + offset;
          opStr = \`0x\${target.toString(16).padStart(8, '0')}\`;
          operands.push({ type: 'imm', imm: target });
        } else {
          valid = false;
        }
        break;
      }
      case 'brtarget': {
        if (i + 4 <= data.length) {
          const offset = getInt32(i);
          i += 4;
          const target = addr + opSize + 4 + offset;
          opStr = \`0x\${target.toString(16).padStart(8, '0')}\`;
          operands.push({ type: 'imm', imm: target });
        } else {
          valid = false;
        }
        break;
      }
      case 'i1': {
        if (i < data.length) {
          const val = getInt8(i);
          i += 1;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'i2': {
        if (i + 2 <= data.length) {
          const val = getUint16(i);
          i += 2;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'i4': {
        if (i + 4 <= data.length) {
          const val = getInt32(i);
          i += 4;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'i8': {
        if (i + 8 <= data.length) {
          const val = getBigInt64(i);
          i += 8;
          opStr = val.toString() + 'n';
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'r4': {
        if (i + 4 <= data.length) {
          const val = getFloat32(i);
          i += 4;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'r8': {
        if (i + 8 <= data.length) {
          const val = getFloat64(i);
          i += 8;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'tok': {
        if (i + 4 <= data.length) {
          const val = getUint32(i);
          i += 4;
          opStr = \`0x\${val.toString(16).padStart(8, '0')}\`;
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'var_s': {
        if (i < data.length) {
          const val = getUint8(i);
          i += 1;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'var': {
        if (i + 2 <= data.length) {
          const val = getUint16(i);
          i += 2;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'switch': {
        if (i + 4 <= data.length) {
          const count = getUint32(i);
          i += 4;
          if (i + count * 4 <= data.length) {
            const targets: number[] = [];
            const targetStrings: string[] = [];
            const instrAfterSwitch = addr + opSize + 4 + count * 4;
            for (let c = 0; c < count; c++) {
              const offset = getInt32(i + c * 4);
              const target = instrAfterSwitch + offset;
              targets.push(target);
              targetStrings.push(\`0x\${target.toString(16).padStart(8, '0')}\`);
              operands.push({ type: 'imm', imm: target });
            }
            i += count * 4;
            opStr = \`(\${targetStrings.join(', ')})\`;
          } else {
            valid = false;
          }
        } else {
          valid = false;
        }
        break;
      }
    }

    if (!valid) {
      // If we don't have enough bytes, roll back and treat remaining bytes as db
      i = startIdx;
      const rawByte = data[i];
      instructions.push({
        address: addr,
        bytes: data.slice(i, i + 1),
        mnemonic: 'db',
        opStr: \`0x\${rawByte.toString(16).padStart(2, '0')}\`,
        operands: [],
        size: 1,
      });
      i++;
      continue;
    }

    instructions.push({
      address: addr,
      bytes: data.slice(startIdx, i),
      mnemonic: opcodeInfo.mnemonic,
      opStr,
      operands,
      size: i - startIdx,
    });
  }

  return instructions;
}
`;

function determineOperandType(inst, op) {
  // Determine based on regex or string matches
  if (inst === 'switch' || inst.includes('switch')) {
    return 'switch';
  }

  // Branch targets
  if (inst.includes('<int8 (target)>') || inst.includes('<int8 (offset)>') || inst.endsWith('.s <int8 (target)>') || inst.endsWith('.s <int8 (offset)>')) {
    return 'brtarget_s';
  }
  if (inst.includes('<int32 (target)>') || inst.includes('<int32 (offset)>')) {
    return 'brtarget';
  }
  // Let's also check for target in description or instruction name
  if (inst.includes('target') && inst.includes('.s')) {
    return 'brtarget_s';
  }
  if (inst.includes('target')) {
    return 'brtarget';
  }

  // Variables / args indices
  if (inst.includes('<uint8') || inst.includes('<int8') && (inst.includes('loc') || inst.includes('arg') || inst.includes('var'))) {
    return 'var_s';
  }
  if (inst.includes('<uint16') || inst.includes('<int16') && (inst.includes('loc') || inst.includes('arg') || inst.includes('var'))) {
    return 'var';
  }

  // Immediates
  if (inst.includes('<int8')) {
    return 'i1';
  }
  if (inst.includes('<uint16') || inst.includes('<int16')) {
    return 'i2';
  }
  if (inst.includes('<int32') || inst.includes('<uint32')) {
    return 'i4';
  }
  if (inst.includes('<int64')) {
    return 'i8';
  }
  if (inst.includes('<float32')) {
    return 'r4';
  }
  if (inst.includes('<float64')) {
    return 'r8';
  }

  // Metadata tokens
  if (
    inst.includes('<method>') ||
    inst.includes('<field>') ||
    inst.includes('<typeTok>') ||
    inst.includes('<class>') ||
    inst.includes('<signature>') ||
    inst.includes('<token>') ||
    inst.includes('<ctor>') ||
    inst.includes('<etype>') ||
    inst.includes('<valuetype>') ||
    inst.includes('<string>') ||
    inst.includes('<callsitedescr>') ||
    inst.includes('alignment') || // e.g. unaligned. (alignment)
    inst.includes('<thisType>')
  ) {
    // wait, unaligned. alignment is 1 byte! Wait, let's verify unaligned alignment operand size.
    // Partition III says: unaligned. takes a 1-byte alignment operand (unsigned int8).
    // Let's check:
    if (inst.includes('alignment')) return 'i1';
    return 'tok';
  }

  // Special checks for specific instructions
  if (inst.startsWith('ldc.i4.s')) return 'i1';
  if (inst.startsWith('ldc.i4')) return 'i4';
  if (inst.startsWith('ldc.i8')) return 'i8';
  if (inst.startsWith('ldc.r4')) return 'r4';
  if (inst.startsWith('ldc.r8')) return 'r8';
  if (inst.startsWith('ldloc.s')) return 'var_s';
  if (inst.startsWith('stloc.s')) return 'var_s';
  if (inst.startsWith('ldloca.s')) return 'var_s';
  if (inst.startsWith('ldarg.s')) return 'var_s';
  if (inst.startsWith('starg.s')) return 'var_s';
  if (inst.startsWith('ldloc')) return 'var';
  if (inst.startsWith('stloc')) return 'var';
  if (inst.startsWith('ldloca')) return 'var';
  if (inst.startsWith('ldarg')) return 'var';
  if (inst.startsWith('starg')) return 'var';

  return 'none';
}

const listStr = opcodes.map(op => {
  const parts = op.op.split(' ');
  let op1, op2;
  if (parts.length === 2) {
    op1 = parseInt(parts[0], 16);
    op2 = parseInt(parts[1], 16);
  } else {
    op1 = parseInt(parts[0], 16);
    op2 = null;
  }
  
  // Extract mnemonic (first word of inst before space or <)
  let mnemonic = op.inst.split(/[ <\n]/)[0].trim();
  // Strip any trailing dots if it's just prefix like "constrained."
  // Wait, let's keep the dots if they are part of the instruction name, but check.
  // Actually, mnemonics like "ceq", "add", "constrained." etc. Let's keep them as parsed.
  
  const operandType = determineOperandType(op.inst, op.op);
  
  return `  {
    op1: ${op1},
    op2: ${op2},
    mnemonic: '${mnemonic}',
    operandType: '${operandType}',
    description: ${JSON.stringify(op.desc)}
  }`;
}).join(',\n');

const finalCode = decoderTemplate.replace('__OPCODE_LIST__', listStr);
fs.writeFileSync('src/disassembler/dotnetIl.ts', finalCode);
console.log('Successfully generated src/disassembler/dotnetIl.ts');
