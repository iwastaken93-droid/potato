export interface MemoryBlock {
  address: number;
  data: Uint8Array;
}

export interface ParsedHexOrSrec {
  format: 'IntelHex' | 'SRecord';
  entryPoint?: number;
  blocks: MemoryBlock[];
  header?: string;
}

export function mergeBlocks(blocks: MemoryBlock[]): MemoryBlock[] {
  if (blocks.length === 0) return [];
  // Sort by address
  blocks.sort((a, b) => a.address - b.address);
  const merged: MemoryBlock[] = [];
  let current = {
    address: blocks[0].address,
    data: new Uint8Array(blocks[0].data),
  };

  for (let i = 1; i < blocks.length; i++) {
    const b = blocks[i];
    if (current.address + current.data.length === b.address) {
      // Contiguous, merge
      const newData = new Uint8Array(current.data.length + b.data.length);
      newData.set(current.data, 0);
      newData.set(b.data, current.data.length);
      current.data = newData;
    } else {
      // Gap or overlap
      merged.push(current);
      current = {
        address: b.address,
        data: new Uint8Array(b.data),
      };
    }
  }
  merged.push(current);
  return merged;
}

export function parseIntelHex(input: string | Uint8Array): ParsedHexOrSrec {
  const content = typeof input === 'string' ? input : new TextDecoder().decode(input);
  const lines = content.split(/\r?\n/);
  
  let extendedLinearAddress = 0;
  let extendedSegmentAddress = 0;
  let entryPoint: number | undefined;
  const blocks: MemoryBlock[] = [];
  
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex].trim();
    if (line.length === 0) continue;
    if (line[0] !== ':') {
      throw new Error(`Invalid Intel HEX line prefix at line ${lineIndex + 1}: expected ':'`);
    }
    
    // Parse hex bytes
    const hexBytes: number[] = [];
    for (let i = 1; i < line.length; i += 2) {
      if (i + 1 >= line.length) {
        throw new Error(`Odd number of hex characters at line ${lineIndex + 1}`);
      }
      const byteStr = line.substring(i, i + 2);
      const val = parseInt(byteStr, 16);
      if (isNaN(val)) {
        throw new Error(`Invalid hex character in line ${lineIndex + 1}: ${byteStr}`);
      }
      hexBytes.push(val);
    }
    
    if (hexBytes.length < 5) {
      throw new Error(`Line too short at line ${lineIndex + 1}`);
    }
    
    const byteCount = hexBytes[0];
    const offsetAddress = (hexBytes[1] << 8) | hexBytes[2];
    const recordType = hexBytes[3];
    const dataBytes = hexBytes.slice(4, 4 + byteCount);
    
    // Verify checksum
    let sum = 0;
    for (let i = 0; i < hexBytes.length; i++) {
      sum = (sum + hexBytes[i]) & 0xFF;
    }
    if (sum !== 0) {
      throw new Error(`Checksum validation failed at line ${lineIndex + 1}`);
    }
    
    if (recordType === 0x00) {
      // Data Record
      const absoluteAddress = (extendedLinearAddress << 16) + (extendedSegmentAddress << 4) + offsetAddress;
      blocks.push({
        address: absoluteAddress,
        data: new Uint8Array(dataBytes),
      });
    } else if (recordType === 0x01) {
      // End of File Record
      break;
    } else if (recordType === 0x02) {
      // Extended Segment Address Record
      if (byteCount !== 2) {
        throw new Error(`Invalid byte count for record type 02 at line ${lineIndex + 1}`);
      }
      extendedSegmentAddress = (dataBytes[0] << 8) | dataBytes[1];
    } else if (recordType === 0x03) {
      // Start Segment Address Record
      if (byteCount !== 4) {
        throw new Error(`Invalid byte count for record type 03 at line ${lineIndex + 1}`);
      }
      const cs = (dataBytes[0] << 8) | dataBytes[1];
      const ip = (dataBytes[2] << 8) | dataBytes[3];
      entryPoint = (cs << 4) + ip;
    } else if (recordType === 0x04) {
      // Extended Linear Address Record
      if (byteCount !== 2) {
        throw new Error(`Invalid byte count for record type 04 at line ${lineIndex + 1}`);
      }
      extendedLinearAddress = (dataBytes[0] << 8) | dataBytes[1];
    } else if (recordType === 0x05) {
      // Start Linear Address Record
      if (byteCount !== 4) {
        throw new Error(`Invalid byte count for record type 05 at line ${lineIndex + 1}`);
      }
      entryPoint = (dataBytes[0] << 24) | (dataBytes[1] << 16) | (dataBytes[2] << 8) | dataBytes[3];
    } else {
      throw new Error(`Unknown record type ${recordType} at line ${lineIndex + 1}`);
    }
  }
  
  return {
    format: 'IntelHex',
    entryPoint,
    blocks: mergeBlocks(blocks),
  };
}

export function parseSRecord(input: string | Uint8Array): ParsedHexOrSrec {
  const content = typeof input === 'string' ? input : new TextDecoder().decode(input);
  const lines = content.split(/\r?\n/);
  
  let entryPoint: number | undefined;
  let header: string | undefined;
  const blocks: MemoryBlock[] = [];
  
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex].trim();
    if (line.length === 0) continue;
    if (line[0] !== 'S') {
      throw new Error(`Invalid S-record line prefix at line ${lineIndex + 1}: expected 'S'`);
    }
    
    const typeChar = line[1];
    if (line.length < 4) {
      throw new Error(`Line too short at line ${lineIndex + 1}`);
    }
    
    // Parse hex bytes
    const hexBytes: number[] = [];
    for (let i = 2; i < line.length; i += 2) {
      if (i + 1 >= line.length) {
        throw new Error(`Odd number of hex characters at line ${lineIndex + 1}`);
      }
      const byteStr = line.substring(i, i + 2);
      const val = parseInt(byteStr, 16);
      if (isNaN(val)) {
        throw new Error(`Invalid hex character in line ${lineIndex + 1}: ${byteStr}`);
      }
      hexBytes.push(val);
    }
    
    const byteCount = hexBytes[0];
    if (hexBytes.length !== byteCount + 1) {
      throw new Error(`Byte count mismatch at line ${lineIndex + 1}: expected ${byteCount + 1} bytes, got ${hexBytes.length}`);
    }
    
    // Verify checksum
    let sum = 0;
    for (let i = 0; i < hexBytes.length; i++) {
      sum = (sum + hexBytes[i]) & 0xFF;
    }
    if (sum !== 0xFF) {
      throw new Error(`Checksum validation failed at line ${lineIndex + 1}`);
    }
    
    // Determine address size based on type
    let addressSize = 0;
    let isData = false;
    let isEOF = false;
    let isHeader = false;
    
    switch (typeChar) {
      case '0':
        addressSize = 2;
        isHeader = true;
        break;
      case '1':
        addressSize = 2;
        isData = true;
        break;
      case '2':
        addressSize = 3;
        isData = true;
        break;
      case '3':
        addressSize = 4;
        isData = true;
        break;
      case '5':
      case '6':
        // Count record, skip
        break;
      case '7':
        addressSize = 4;
        isEOF = true;
        break;
      case '8':
        addressSize = 3;
        isEOF = true;
        break;
      case '9':
        addressSize = 2;
        isEOF = true;
        break;
      default:
        throw new Error(`Unsupported S-record type S${typeChar} at line ${lineIndex + 1}`);
    }
    
    if (addressSize > 0) {
      let address = 0;
      for (let i = 0; i < addressSize; i++) {
        address = (address << 8) | hexBytes[1 + i];
      }
      
      const dataBytes = hexBytes.slice(1 + addressSize, hexBytes.length - 1);
      
      if (isData) {
        blocks.push({
          address,
          data: new Uint8Array(dataBytes),
        });
      } else if (isEOF) {
        entryPoint = address;
      } else if (isHeader) {
        header = new TextDecoder().decode(new Uint8Array(dataBytes));
      }
    }
  }
  
  return {
    format: 'SRecord',
    entryPoint,
    blocks: mergeBlocks(blocks),
    header,
  };
}

export function detectFormat(data: Uint8Array): 'IntelHex' | 'SRecord' | null {
  let startIdx = 0;
  while (startIdx < data.length && (data[startIdx] === 0x20 || data[startIdx] === 0x09 || data[startIdx] === 0x0d || data[startIdx] === 0x0a)) {
    startIdx++;
  }
  if (startIdx >= data.length) return null;
  
  if (data[startIdx] === 0x3a) { // ':'
    return 'IntelHex';
  }
  if (data[startIdx] === 0x53) { // 'S'
    if (startIdx + 1 < data.length) {
      const nextChar = String.fromCharCode(data[startIdx + 1]);
      if (/[0-9]/.test(nextChar)) {
        return 'SRecord';
      }
    }
  }
  return null;
}
