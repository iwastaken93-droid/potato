/**
 * Mach-O Code Signature Parser
 * Parses LC_CODE_SIGNATURE data, including SuperBlobs, CodeDirectories, Entitlements,
 * and PKCS#7/CMS signature wrappers containing certificate chains.
 */

// Magic numbers
export const CSMAGIC_REQUIREMENT = 0xfade0c00;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1;
export const CSMAGIC_BLOBWRAPPER = 0xfade0c0b;
export const CSMAGIC_DER_ENTITLEMENTS = 0xfade0cc5;

export const MAGIC_NAMES: Record<number, string> = {
  [CSMAGIC_REQUIREMENT]: 'CSMAGIC_REQUIREMENT',
  [CSMAGIC_REQUIREMENTS]: 'CSMAGIC_REQUIREMENTS',
  [CSMAGIC_CODEDIRECTORY]: 'CSMAGIC_CODEDIRECTORY',
  [CSMAGIC_EMBEDDED_SIGNATURE]: 'CSMAGIC_EMBEDDED_SIGNATURE',
  [CSMAGIC_DETACHED_SIGNATURE]: 'CSMAGIC_DETACHED_SIGNATURE',
  [CSMAGIC_BLOBWRAPPER]: 'CSMAGIC_BLOBWRAPPER',
  [CSMAGIC_DER_ENTITLEMENTS]: 'CSMAGIC_DER_ENTITLEMENTS',
};

// Blob slot types
export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_INFOPLIST = 1;
export const CSSLOT_REQUIREMENTS = 2;
export const CSSLOT_RESOURCEDIR = 3;
export const CSSLOT_APPLICATION = 4;
export const CSSLOT_ENTITLEMENTS = 5;
export const CSSLOT_DER_ENTITLEMENTS = 7;
export const CSSLOT_SIGNATURESLOT = 0x10000;

export const SLOT_NAMES: Record<number, string> = {
  [CSSLOT_CODEDIRECTORY]: 'CSSLOT_CODEDIRECTORY',
  [CSSLOT_INFOPLIST]: 'CSSLOT_INFOPLIST',
  [CSSLOT_REQUIREMENTS]: 'CSSLOT_REQUIREMENTS',
  [CSSLOT_RESOURCEDIR]: 'CSSLOT_RESOURCEDIR',
  [CSSLOT_APPLICATION]: 'CSSLOT_APPLICATION',
  [CSSLOT_ENTITLEMENTS]: 'CSSLOT_ENTITLEMENTS',
  [CSSLOT_DER_ENTITLEMENTS]: 'CSSLOT_DER_ENTITLEMENTS',
  [CSSLOT_SIGNATURESLOT]: 'CSSLOT_SIGNATURESLOT',
};

// Hash Types
export const HASH_TYPE_NAMES: Record<number, string> = {
  1: 'SHA-1',
  2: 'SHA-256',
  3: 'SHA-384',
  4: 'SHA-512',
};

export interface ASN1Node {
  tag: number;
  tagClass: number; // 0=universal, 1=application, 2=context-specific, 3=private
  isConstructed: boolean;
  type: string;
  value: Uint8Array | ASN1Node[];
  raw: Uint8Array;
}

export interface ParsedCertificate {
  subject: Record<string, string>;
  subjectString: string;
  issuer: Record<string, string>;
  issuerString: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  raw: Uint8Array;
}

export interface CodeDirectoryInfo {
  version: number;
  flags: number;
  hashOffset: number;
  identOffset: number;
  nSpecialSlots: number;
  nCodeSlots: number;
  codeLimit: number;
  hashSize: number;
  hashType: number;
  hashTypeName: string;
  platform: number;
  pageSize: number;
  teamOffset?: number;
  identifier: string;
  teamIdentifier?: string;
  specialSlots: Record<number, string>; // slot index (negative) -> hex hash
  codeSlots: string[]; // index -> hex hash
}

export interface MachoSignatureBlob {
  type: number;
  typeName: string;
  offset: number;
  length: number;
  magic: number;
  magicName: string;
  payload: unknown;
}

export interface MachoSignatureInfo {
  magic: number;
  magicName: string;
  length: number;
  count: number;
  blobs: MachoSignatureBlob[];
}

/**
 * Basic ASN.1 DER Parser
 */
export function parseASN1(
  data: Uint8Array,
  offset = 0
): { node: ASN1Node; nextOffset: number } {
  const start = offset;
  if (offset >= data.length) {
    throw new Error('ASN.1: empty data');
  }
  const tagByte = data[offset++];
  const tagClass = (tagByte & 0xc0) >> 6;
  const isConstructed = (tagByte & 0x20) !== 0;
  let tagNumber = tagByte & 0x1f;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    while (offset < data.length) {
      const b = data[offset++];
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }

  if (offset >= data.length) {
    throw new Error('ASN.1: length missing');
  }
  let length = 0;
  const lenByte = data[offset++];
  if ((lenByte & 0x80) === 0) {
    length = lenByte;
  } else {
    const lenOctets = lenByte & 0x7f;
    for (let i = 0; i < lenOctets; i++) {
      if (offset >= data.length) {
        throw new Error('ASN.1: length overflow');
      }
      length = (length << 8) | data[offset++];
    }
  }

  if (offset + length > data.length) {
    throw new Error(
      `ASN.1: value out of bounds (length: ${length}, size: ${data.length - offset})`
    );
  }

  const valueBytes = data.slice(offset, offset + length);
  const nextOffset = offset + length;

  let type = `TAG_${tagNumber}`;
  if (tagClass === 0) {
    switch (tagNumber) {
      case 1:
        type = 'BOOLEAN';
        break;
      case 2:
        type = 'INTEGER';
        break;
      case 3:
        type = 'BIT STRING';
        break;
      case 4:
        type = 'OCTET STRING';
        break;
      case 5:
        type = 'NULL';
        break;
      case 6:
        type = 'OBJECT IDENTIFIER';
        break;
      case 12:
        type = 'UTF8String';
        break;
      case 16:
        type = 'SEQUENCE';
        break;
      case 17:
        type = 'SET';
        break;
      case 19:
        type = 'PrintableString';
        break;
      case 20:
        type = 'T61String';
        break;
      case 22:
        type = 'IA5String';
        break;
      case 23:
        type = 'UTCTime';
        break;
      case 24:
        type = 'GeneralizedTime';
        break;
    }
  } else if (tagClass === 2) {
    type = `CONTEXT_${tagNumber}`;
  }

  let value: Uint8Array | ASN1Node[];
  if (isConstructed) {
    const children: ASN1Node[] = [];
    let childOffset = 0;
    while (childOffset < valueBytes.length) {
      try {
        const child = parseASN1(valueBytes, childOffset);
        children.push(child.node);
        childOffset = child.nextOffset;
      } catch {
        // Fallback to raw bytes if children nested parsing fails
        return {
          node: {
            tag: tagNumber,
            tagClass,
            isConstructed: false,
            type: `${type}_RAW_FALLBACK`,
            value: valueBytes,
            raw: data.slice(start, nextOffset),
          },
          nextOffset,
        };
      }
    }
    value = children;
  } else {
    value = valueBytes;
  }

  const node: ASN1Node = {
    tag: tagNumber,
    tagClass,
    isConstructed,
    type,
    value,
    raw: data.slice(start, nextOffset),
  };

  return { node, nextOffset };
}

export function parseOID(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const first = bytes[0];
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let val = 0;
  for (let i = 1; i < bytes.length; i++) {
    const b = bytes[i];
    val = (val << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join('.');
}

export function parseASN1String(bytes: Uint8Array): string {
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return s;
  }
}

export function parseX509Name(node: ASN1Node): Record<string, string> {
  const result: Record<string, string> = {};
  if (node.type !== 'SEQUENCE' || !Array.isArray(node.value)) return result;

  const OID_MAP: Record<string, string> = {
    '2.5.4.3': 'CN',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
  };

  for (const setNode of node.value) {
    if (setNode.type === 'SET' && Array.isArray(setNode.value)) {
      for (const seq of setNode.value) {
        if (
          seq.type === 'SEQUENCE' &&
          Array.isArray(seq.value) &&
          seq.value.length >= 2
        ) {
          const oidNode = seq.value[0];
          const valNode = seq.value[1];
          if (
            oidNode.type === 'OBJECT IDENTIFIER' &&
            oidNode.value instanceof Uint8Array
          ) {
            const oid = parseOID(oidNode.value);
            const key = OID_MAP[oid] || oid;
            if (valNode.value instanceof Uint8Array) {
              result[key] = parseASN1String(valNode.value);
            }
          }
        }
      }
    }
  }
  return result;
}

export function formatX509Name(name: Record<string, string>): string {
  return Object.entries(name)
    .map(([key, val]) => `${key}=${val}`)
    .join(', ');
}

export function parseValidity(node: ASN1Node): {
  notBefore: string;
  notAfter: string;
} {
  let notBefore = '';
  let notAfter = '';
  if (
    node.type === 'SEQUENCE' &&
    Array.isArray(node.value) &&
    node.value.length >= 2
  ) {
    const nb = node.value[0];
    const na = node.value[1];
    if (nb.value instanceof Uint8Array) {
      notBefore = parseASN1String(nb.value);
    }
    if (na.value instanceof Uint8Array) {
      notAfter = parseASN1String(na.value);
    }
  }
  return { notBefore, notAfter };
}

export function parseSerialNumber(node: ASN1Node): string {
  if (node.type === 'INTEGER' && node.value instanceof Uint8Array) {
    let hex = '';
    for (let i = 0; i < node.value.length; i++) {
      hex += node.value[i].toString(16).padStart(2, '0');
    }
    return hex.toUpperCase();
  }
  return '';
}

export function parseCertificate(certNode: ASN1Node): ParsedCertificate | null {
  if (
    certNode.type !== 'SEQUENCE' ||
    !Array.isArray(certNode.value) ||
    certNode.value.length < 3
  ) {
    return null;
  }

  const tbsNode = certNode.value[0];
  if (tbsNode.type !== 'SEQUENCE' || !Array.isArray(tbsNode.value)) {
    return null;
  }

  let index = 0;
  const first = tbsNode.value[0];
  if (first.type === 'CONTEXT_0') {
    index = 1;
  }

  const serialNode = tbsNode.value[index++];
  index++; // Skip sigAlgoNode
  const issuerNode = tbsNode.value[index++];
  const validityNode = tbsNode.value[index++];
  const subjectNode = tbsNode.value[index];

  if (!serialNode || !issuerNode || !validityNode || !subjectNode) {
    return null;
  }

  const subject = parseX509Name(subjectNode);
  const issuer = parseX509Name(issuerNode);
  const validity = parseValidity(validityNode);
  const serialNumber = parseSerialNumber(serialNode);

  return {
    subject,
    subjectString: formatX509Name(subject),
    issuer,
    issuerString: formatX509Name(issuer),
    serialNumber,
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    raw: certNode.raw,
  };
}

export function extractCertificates(node: ASN1Node): ASN1Node[] {
  const certs: ASN1Node[] = [];
  function traverse(n: ASN1Node) {
    if (n.type === 'CONTEXT_0' && Array.isArray(n.value)) {
      for (const child of n.value) {
        if (child.type === 'SEQUENCE' && Array.isArray(child.value)) {
          certs.push(child);
        }
      }
    }
    if (Array.isArray(n.value)) {
      for (const child of n.value) {
        traverse(child);
      }
    }
  }
  traverse(node);
  return certs;
}

/**
 * Parses raw code signature blob wrapper and extracts CMS/PKCS7 certificate chains.
 */
export function parseSignatureSlot(bytes: Uint8Array): {
  raw: Uint8Array;
  certificates: ParsedCertificate[];
} {
  try {
    const { node } = parseASN1(bytes);
    const certNodes = extractCertificates(node);
    const certificates: ParsedCertificate[] = [];
    for (const certNode of certNodes) {
      const parsed = parseCertificate(certNode);
      if (parsed) {
        certificates.push(parsed);
      }
    }
    return {
      raw: bytes,
      certificates,
    };
  } catch {
    return {
      raw: bytes,
      certificates: [],
    };
  }
}

/**
 * Parses CodeDirectory blob structure.
 */
export function parseCodeDirectory(bytes: Uint8Array): CodeDirectoryInfo {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = view.getUint32(0, false);
  if (magic !== CSMAGIC_CODEDIRECTORY) {
    throw new Error(`Invalid CodeDirectory magic: 0x${magic.toString(16)}`);
  }

  view.getUint32(4, false);
  const version = view.getUint32(8, false);
  const flags = view.getUint32(12, false);
  const hashOffset = view.getUint32(16, false);
  const identOffset = view.getUint32(20, false);
  const nSpecialSlots = view.getUint32(24, false);
  const nCodeSlots = view.getUint32(28, false);
  const codeLimit = view.getUint32(32, false);
  const hashSize = view.getUint8(36);
  const hashType = view.getUint8(37);
  const platform = view.getUint8(38);
  const pageSize = view.getUint8(39);

  let teamOffset: number | undefined;
  if (version >= 0x20200 && bytes.length >= 44) {
    teamOffset = view.getUint32(40, false);
  }

  // Parse identifier string
  let identifier = '';
  if (identOffset > 0 && identOffset < bytes.length) {
    let offset = identOffset;
    while (offset < bytes.length && bytes[offset] !== 0) {
      identifier += String.fromCharCode(bytes[offset++]);
    }
  }

  // Parse team identifier string
  let teamIdentifier: string | undefined;
  if (teamOffset && teamOffset > 0 && teamOffset < bytes.length) {
    let offset = teamOffset;
    teamIdentifier = '';
    while (offset < bytes.length && bytes[offset] !== 0) {
      teamIdentifier += String.fromCharCode(bytes[offset++]);
    }
  }

  // Helper to convert hash bytes to hex string
  const toHex = (buf: Uint8Array) => {
    let hex = '';
    for (let i = 0; i < buf.length; i++) {
      hex += buf[i].toString(16).padStart(2, '0');
    }
    return hex;
  };

  // Parse special slots
  const specialSlots: Record<number, string> = {};
  for (let i = 1; i <= nSpecialSlots; i++) {
    const offset = hashOffset - i * hashSize;
    if (offset >= 0 && offset + hashSize <= bytes.length) {
      const hashBytes = bytes.slice(offset, offset + hashSize);
      specialSlots[-i] = toHex(hashBytes);
    }
  }

  // Parse ordinary code slots
  const codeSlots: string[] = [];
  for (let i = 0; i < nCodeSlots; i++) {
    const offset = hashOffset + i * hashSize;
    if (offset >= 0 && offset + hashSize <= bytes.length) {
      const hashBytes = bytes.slice(offset, offset + hashSize);
      codeSlots.push(toHex(hashBytes));
    }
  }

  return {
    version,
    flags,
    hashOffset,
    identOffset,
    nSpecialSlots,
    nCodeSlots,
    codeLimit,
    hashSize,
    hashType,
    hashTypeName: HASH_TYPE_NAMES[hashType] || `UNKNOWN_HASH_${hashType}`,
    platform,
    pageSize,
    teamOffset,
    identifier,
    teamIdentifier,
    specialSlots,
    codeSlots,
  };
}

/**
 * Parses Entitlements xml plist.
 */
export function parseEntitlements(bytes: Uint8Array): string {
  // Entitlements magic is 0xfade0c01 (or CSMAGIC_REQUIREMENTS, but in this slot context it contains XML plist)
  // Skip the magic (4 bytes) and length (4 bytes)
  if (bytes.length < 8) return '';
  const str = parseASN1String(bytes.slice(8));
  const nullIdx = str.indexOf('\0');
  const cleanStr = nullIdx !== -1 ? str.slice(0, nullIdx) : str;
  return cleanStr.trim();
}

/**
 * Main function to parse code signature from a binary buffer given its offset and size.
 */
export function parseMachoSignature(
  buffer: ArrayBuffer,
  dataoff: number,
  datasize: number
): MachoSignatureInfo {
  if (dataoff + datasize > buffer.byteLength) {
    throw new Error('Code signature offset and size exceed buffer bounds');
  }

  const signatureBytes = new Uint8Array(buffer, dataoff, datasize);
  const view = new DataView(buffer, dataoff, datasize);

  if (datasize < 8) {
    throw new Error('Signature data too small');
  }

  const magic = view.getUint32(0, false);
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) {
    throw new Error(`Invalid SuperBlob magic: 0x${magic.toString(16)}`);
  }

  const length = view.getUint32(4, false);
  const count = view.getUint32(8, false);

  const blobs: MachoSignatureBlob[] = [];

  for (let i = 0; i < count; i++) {
    const idxOffset = 12 + i * 8;
    if (idxOffset + 8 > datasize) break;

    const type = view.getUint32(idxOffset, false);
    const offset = view.getUint32(idxOffset + 4, false);

    if (offset >= datasize) continue;

    const typeName =
      SLOT_NAMES[type] || `CSSLOT_UNKNOWN_0x${type.toString(16)}`;

    // Read the blob header at the specified offset
    const blobMagic = view.getUint32(offset, false);
    const blobLength = view.getUint32(offset + 4, false);
    const magicName =
      MAGIC_NAMES[blobMagic] || `CSMAGIC_UNKNOWN_0x${blobMagic.toString(16)}`;

    if (offset + blobLength > datasize) continue;

    const blobBytes = signatureBytes.slice(offset, offset + blobLength);
    let payload: unknown = null;

    if (type === CSSLOT_CODEDIRECTORY) {
      try {
        payload = parseCodeDirectory(blobBytes);
      } catch (e) {
        payload = { error: (e as Error).message };
      }
    } else if (type === CSSLOT_ENTITLEMENTS) {
      payload = parseEntitlements(blobBytes);
    } else if (type === CSSLOT_SIGNATURESLOT) {
      // Signature wrapper starts with blob magic and length, CMS data is after the 8-byte header
      if (blobBytes.length > 8) {
        payload = parseSignatureSlot(blobBytes.slice(8));
      }
    } else if (type === CSSLOT_DER_ENTITLEMENTS) {
      payload = { raw: blobBytes.slice(8) };
    } else {
      payload = { raw: blobBytes.slice(8) };
    }

    blobs.push({
      type,
      typeName,
      offset,
      length: blobLength,
      magic: blobMagic,
      magicName,
      payload,
    });
  }

  return {
    magic,
    magicName: MAGIC_NAMES[magic] || 'CSMAGIC_EMBEDDED_SIGNATURE',
    length,
    count,
    blobs,
  };
}
