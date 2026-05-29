/**
 * GDB/LLDB Remote Serial Protocol (RSP) packet parser, formatter, and handler.
 * Handles packet encoding/decoding, checksum validation, and basic queries
 * (reading/writing registers and memory).
 */

import { Emulator } from './emulator.js';

/**
 * GDB RSP Register Definition
 */
export interface RegisterDef {
  name: string;
  size: number; // Size in bytes
}

/**
 * Standard register layout for x86_64 GDB RSP.
 * The order and sizes must match what GDB expects for target xml / default architecture.
 */
export const X86_64_REGISTERS: RegisterDef[] = [
  { name: 'rax', size: 8 },
  { name: 'rbx', size: 8 },
  { name: 'rcx', size: 8 },
  { name: 'rdx', size: 8 },
  { name: 'rsi', size: 8 },
  { name: 'rdi', size: 8 },
  { name: 'rbp', size: 8 },
  { name: 'rsp', size: 8 },
  { name: 'r8', size: 8 },
  { name: 'r9', size: 8 },
  { name: 'r10', size: 8 },
  { name: 'r11', size: 8 },
  { name: 'r12', size: 8 },
  { name: 'r13', size: 8 },
  { name: 'r14', size: 8 },
  { name: 'r15', size: 8 },
  { name: 'rip', size: 8 },
  { name: 'rflags', size: 4 },
  { name: 'cs', size: 4 },
  { name: 'ss', size: 4 },
  { name: 'ds', size: 4 },
  { name: 'es', size: 4 },
  { name: 'fs', size: 4 },
  { name: 'gs', size: 4 },
];

/**
 * Calculate the 8-bit checksum of packet data (sum modulo 256).
 */
export function calculateChecksum(data: string): number {
  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    sum = (sum + data.charCodeAt(i)) & 0xff;
  }
  return sum;
}

/**
 * Escape GDB special characters: '$', '#', '}', and '*'.
 */
export function escapeData(data: string): string {
  let result = '';
  for (let i = 0; i < data.length; i++) {
    const char = data[i];
    if (char === '$' || char === '#' || char === '}' || char === '*') {
      result += '}' + String.fromCharCode(char.charCodeAt(0) ^ 0x20);
    } else {
      result += char;
    }
  }
  return result;
}

/**
 * Unescape GDB special characters.
 */
export function unescapeData(escaped: string): string {
  let result = '';
  for (let i = 0; i < escaped.length; i++) {
    if (escaped[i] === '}') {
      i++;
      if (i < escaped.length) {
        result += String.fromCharCode(escaped.charCodeAt(i) ^ 0x20);
      }
    } else {
      result += escaped[i];
    }
  }
  return result;
}

/**
 * Format a string/data into a GDB RSP packet.
 */
export function formatPacket(data: string): string {
  const escaped = escapeData(data);
  const checksum = calculateChecksum(escaped).toString(16).padStart(2, '0');
  return `$${escaped}#${checksum}`;
}

/**
 * Converts a BigInt into a little-endian hexadecimal string of a given byte size.
 */
export function toLittleEndianHex(val: bigint, numBytes: number): string {
  let result = '';
  let temp = val;
  for (let i = 0; i < numBytes; i++) {
    const byte = Number(temp & 0xffn);
    result += byte.toString(16).padStart(2, '0');
    temp >>= 8n;
  }
  return result;
}

/**
 * Parses a little-endian hexadecimal string into a BigInt.
 */
export function fromLittleEndianHex(hex: string): bigint {
  let val = 0n;
  for (let i = hex.length - 2; i >= 0; i -= 2) {
    const byte = BigInt(parseInt(hex.slice(i, i + 2), 16));
    val = (val << 8n) | byte;
  }
  return val;
}

/**
 * Helper to read general registers for x86_64 from CPU state into a RSP hex string.
 */
export function readGeneralRegisters(cpu: any): string {
  let response = '';
  for (const reg of X86_64_REGISTERS) {
    let val = 0n;
    try {
      if (cpu.isValidRegister(reg.name)) {
        val = cpu.read(reg.name);
      }
    } catch {
      // If not present in CPU (like cs, ss, etc.), default to 0
    }
    response += toLittleEndianHex(val, reg.size);
  }
  return response;
}

/**
 * Helper to write general registers from a RSP hex string back to CPU state.
 */
export function writeGeneralRegisters(cpu: any, hexData: string): boolean {
  let offset = 0;
  for (const reg of X86_64_REGISTERS) {
    const charsNeeded = reg.size * 2;
    if (offset + charsNeeded > hexData.length) {
      break;
    }
    const hexSlice = hexData.slice(offset, offset + charsNeeded);
    const val = fromLittleEndianHex(hexSlice);
    try {
      if (cpu.isValidRegister(reg.name)) {
        cpu.write(reg.name, val);
      }
    } catch {
      // Ignore unsupported register writes
    }
    offset += charsNeeded;
  }
  return true;
}

/**
 * Parsed GDB packet representation.
 */
export interface GDBPacket {
  type: 'packet' | 'ack' | 'nak';
  data?: string; // Decoded (unescaped) data payload
  raw?: string; // Raw payload string (escaped)
}

/**
 * Streaming parser for the GDB RSP protocol.
 */
export class GDBProtocolParser {
  private buffer: string = '';
  private state: 'idle' | 'data' | 'checksum1' | 'checksum2' = 'idle';
  private currentPacket: string = '';
  private checksumChars: string = '';
  private onPacketCallback: (packet: GDBPacket) => void;

  constructor(onPacket: (packet: GDBPacket) => void) {
    this.onPacketCallback = onPacket;
  }

  /**
   * Feed a chunk of characters/data to the parser.
   */
  public feed(chunk: string): void {
    for (let i = 0; i < chunk.length; i++) {
      const char = chunk[i];
      if (this.state === 'idle') {
        if (char === '$') {
          this.state = 'data';
          this.currentPacket = '';
        } else if (char === '+') {
          this.onPacketCallback({ type: 'ack' });
        } else if (char === '-') {
          this.onPacketCallback({ type: 'nak' });
        }
      } else if (this.state === 'data') {
        if (char === '#') {
          this.state = 'checksum1';
          this.checksumChars = '';
        } else {
          this.currentPacket += char;
        }
      } else if (this.state === 'checksum1') {
        this.checksumChars += char;
        this.state = 'checksum2';
      } else if (this.state === 'checksum2') {
        this.checksumChars += char;
        const packetEscaped = this.currentPacket;
        const expectedChecksum = calculateChecksum(packetEscaped);
        const receivedChecksum = parseInt(this.checksumChars, 16);

        if (expectedChecksum === receivedChecksum) {
          const unescaped = unescapeData(packetEscaped);
          this.onPacketCallback({
            type: 'packet',
            data: unescaped,
            raw: packetEscaped,
          });
        } else {
          // Checksum validation failed, emit invalid packet indication
          this.onPacketCallback({
            type: 'packet',
            data: undefined,
            raw: packetEscaped,
          });
        }
        this.state = 'idle';
      }
    }
  }
}

/**
 * Process a single GDB command against an Emulator instance.
 * Returns the unformatted response payload (which should be formatted using formatPacket).
 */
export function handleGDBCommand(command: string, emulator: Emulator): string {
  if (command === '?') {
    return 'S05'; // Stop reason SIGTRAP
  }

  if (command === 'g') {
    return readGeneralRegisters(emulator.cpu);
  }

  if (command.startsWith('G')) {
    const hexData = command.slice(1);
    const success = writeGeneralRegisters(emulator.cpu, hexData);
    return success ? 'OK' : 'E01';
  }

  if (command.startsWith('p')) {
    const regIdx = parseInt(command.slice(1), 16);
    if (isNaN(regIdx) || regIdx < 0 || regIdx >= X86_64_REGISTERS.length) {
      return 'E01';
    }
    const reg = X86_64_REGISTERS[regIdx];
    try {
      const val = emulator.cpu.isValidRegister(reg.name)
        ? emulator.cpu.read(reg.name)
        : 0n;
      return toLittleEndianHex(val, reg.size);
    } catch {
      return 'E01';
    }
  }

  if (command.startsWith('P')) {
    const parts = command.slice(1).split('=');
    if (parts.length !== 2) return 'E01';
    const regIdx = parseInt(parts[0], 16);
    const hexVal = parts[1];
    if (isNaN(regIdx) || regIdx < 0 || regIdx >= X86_64_REGISTERS.length) {
      return 'E01';
    }
    const reg = X86_64_REGISTERS[regIdx];
    const val = fromLittleEndianHex(hexVal);
    try {
      if (emulator.cpu.isValidRegister(reg.name)) {
        emulator.cpu.write(reg.name, val);
      }
      return 'OK';
    } catch {
      return 'E01';
    }
  }

  if (command.startsWith('m')) {
    const parts = command.slice(1).split(',');
    if (parts.length !== 2) return 'E01';
    const addr = BigInt('0x' + parts[0]);
    const length = parseInt(parts[1], 16);
    if (isNaN(length) || length < 0) return 'E01';
    try {
      const buffer = emulator.memory.readBuffer(addr, length);
      let response = '';
      for (let i = 0; i < buffer.length; i++) {
        response += buffer[i].toString(16).padStart(2, '0');
      }
      return response;
    } catch {
      return 'E03';
    }
  }

  if (command.startsWith('M')) {
    const firstPart = command.slice(1);
    const colonIndex = firstPart.indexOf(':');
    if (colonIndex === -1) return 'E01';
    const addrLengthPart = firstPart.slice(0, colonIndex);
    const hexData = firstPart.slice(colonIndex + 1);
    const parts = addrLengthPart.split(',');
    if (parts.length !== 2) return 'E01';
    const addr = BigInt('0x' + parts[0]);
    const length = parseInt(parts[1], 16);
    if (isNaN(length) || length < 0) return 'E01';

    try {
      const data = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        data[i] = parseInt(hexData.slice(i * 2, i * 2 + 2), 16);
      }
      emulator.memory.writeBuffer(addr, data);
      return 'OK';
    } catch {
      return 'E03';
    }
  }

  if (command.startsWith('s')) {
    const addrStr = command.slice(1);
    if (addrStr) {
      const addr = BigInt('0x' + addrStr);
      emulator.cpu.write('rip', addr);
    }
    const result = emulator.step();
    if (result.halted) {
      return 'W00';
    }
    return 'S05';
  }

  if (command.startsWith('c')) {
    const addrStr = command.slice(1);
    if (addrStr) {
      const addr = BigInt('0x' + addrStr);
      emulator.cpu.write('rip', addr);
    }
    let stepCount = 0;
    const maxSteps = 1000;
    while (stepCount < maxSteps) {
      const rip = Number(emulator.cpu.read('rip'));
      if (emulator.isBreakpoint(rip) && stepCount > 0) {
        return 'S05';
      }
      const result = emulator.step();
      stepCount++;
      if (result.halted || !result.success) {
        return 'W00';
      }
      if (result.hitBreakpoint) {
        return 'S05';
      }
    }
    return 'S05';
  }

  if (command === 'qSupported') {
    return 'PacketSize=1024';
  }

  // Any unrecognized command should reply with an empty response
  return '';
}
