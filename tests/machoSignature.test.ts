import { describe, it, expect } from 'vitest';
import * as machoSig from '../src/parser/machoSignature.js';

describe('Mach-O Signature Parser - Constants', () => {
  it('should have correct magic numbers', () => {
    expect(machoSig.CSMAGIC_REQUIREMENT).toBe(0xfade0c00);
    expect(machoSig.CSMAGIC_REQUIREMENTS).toBe(0xfade0c01);
    expect(machoSig.CSMAGIC_CODEDIRECTORY).toBe(0xfade0c02);
    expect(machoSig.CSMAGIC_EMBEDDED_SIGNATURE).toBe(0xfade0cc0);
    expect(machoSig.CSMAGIC_DETACHED_SIGNATURE).toBe(0xfade0cc1);
    expect(machoSig.CSMAGIC_BLOBWRAPPER).toBe(0xfade0c0b);
    expect(machoSig.CSMAGIC_DER_ENTITLEMENTS).toBe(0xfade0cc5);
  });

  it('should map magic names correctly', () => {
    expect(machoSig.MAGIC_NAMES[machoSig.CSMAGIC_REQUIREMENT]).toBe(
      'CSMAGIC_REQUIREMENT'
    );
    expect(machoSig.MAGIC_NAMES[machoSig.CSMAGIC_DER_ENTITLEMENTS]).toBe(
      'CSMAGIC_DER_ENTITLEMENTS'
    );
  });

  it('should map slot names correctly', () => {
    expect(machoSig.SLOT_NAMES[machoSig.CSSLOT_CODEDIRECTORY]).toBe(
      'CSSLOT_CODEDIRECTORY'
    );
    expect(machoSig.SLOT_NAMES[machoSig.CSSLOT_SIGNATURESLOT]).toBe(
      'CSSLOT_SIGNATURESLOT'
    );
  });

  it('should map hash type names correctly', () => {
    expect(machoSig.HASH_TYPE_NAMES[1]).toBe('SHA-1');
    expect(machoSig.HASH_TYPE_NAMES[2]).toBe('SHA-256');
  });
});

describe('Mach-O Signature Parser - ASN1 & OID Parsing', () => {
  it('should parse simple OID correctly', () => {
    // 1.3.6.1 -> 1 * 40 + 3 = 43 (0x2b), 6 (0x06), 1 (0x01)
    const bytes = new Uint8Array([0x2b, 0x06, 0x01]);
    expect(machoSig.parseOID(bytes)).toBe('1.3.6.1');
    expect(machoSig.parseOID(new Uint8Array([]))).toBe('');
  });

  it('should parse OID with multi-byte values correctly', () => {
    // 2.5.4.3 (CN) -> 2 * 40 + 5 = 85 (0x55), 4 (0x04), 3 (0x03)
    const bytes = new Uint8Array([0x55, 0x04, 0x03]);
    expect(machoSig.parseOID(bytes)).toBe('2.5.4.3');
  });

  it('should parse ASN1 String', () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]); // Hello
    expect(machoSig.parseASN1String(bytes)).toBe('Hello');
  });

  it('should parse simple ASN.1 structures', () => {
    // NULL: 0x05, 0x00
    const nullBytes = new Uint8Array([0x05, 0x00]);
    const { node: nullNode, nextOffset: nullNext } =
      machoSig.parseASN1(nullBytes);
    expect(nullNode.type).toBe('NULL');
    expect(nullNode.tag).toBe(5);
    expect(nullNode.isConstructed).toBe(false);
    expect(nullNext).toBe(2);

    // INTEGER 42: 0x02, 0x01, 0x2a
    const intBytes = new Uint8Array([0x02, 0x01, 0x2a]);
    const { node: intNode, nextOffset: intNext } = machoSig.parseASN1(intBytes);
    expect(intNode.type).toBe('INTEGER');
    expect(intNode.tag).toBe(2);
    expect(intNode.value).toEqual(new Uint8Array([0x2a]));
    expect(intNext).toBe(3);
  });

  it('should parse constructed ASN.1 sequence', () => {
    // SEQUENCE of INTEGER 42: 0x30, 0x03, 0x02, 0x01, 0x2a
    const seqBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x2a]);
    const { node, nextOffset } = machoSig.parseASN1(seqBytes);
    expect(node.type).toBe('SEQUENCE');
    expect(node.isConstructed).toBe(true);
    expect(Array.isArray(node.value)).toBe(true);
    const children = node.value as machoSig.ASN1Node[];
    expect(children.length).toBe(1);
    expect(children[0].type).toBe('INTEGER');
    expect(children[0].value).toEqual(new Uint8Array([0x2a]));
    expect(nextOffset).toBe(5);
  });

  it('should fallback to raw on nested parsing failure', () => {
    // Sequence with invalid child structure (e.g. tag says sequence length is 5 but inner bytes are truncated)
    // 0x30 (Sequence, constructed), 0x05 (length 5), 0x02 (Integer), 0x05 (length 5 - exceeds parent!)
    const invalidSeq = new Uint8Array([
      0x30, 0x05, 0x02, 0x05, 0x11, 0x22, 0x33,
    ]);
    const { node } = machoSig.parseASN1(invalidSeq);
    expect(node.type).toBe('SEQUENCE_RAW_FALLBACK');
    expect(node.isConstructed).toBe(false);
    expect(node.value).toBeInstanceOf(Uint8Array);
  });

  it('should throw errors for invalid ASN1 structure', () => {
    expect(() => machoSig.parseASN1(new Uint8Array([]))).toThrow(
      'ASN.1: empty data'
    );
    expect(() => machoSig.parseASN1(new Uint8Array([0x02]))).toThrow(
      'ASN.1: length missing'
    );
    expect(() =>
      machoSig.parseASN1(new Uint8Array([0x02, 0x82, 0x01]))
    ).toThrow('ASN.1: length overflow');
    expect(() =>
      machoSig.parseASN1(new Uint8Array([0x02, 0x05, 0x01]))
    ).toThrow('ASN.1: value out of bounds');
  });

  it('should parse long tag numbers and long length forms', () => {
    // Long tag: tag byte starts with 0x1F, then base 128. E.g. tag 31 -> 0x1F, 0x1F.
    // Let's construct tag 31 with length 2: 0x1f, 0x1f, 0x02, 0x00, 0x00
    // Actually tag class application: 0x40. Tag number 0x1F -> 0x5F.
    // 0x5F, 0x1F, 0x02, 0x00, 0x00
    const bytes = new Uint8Array([0x5f, 0x1f, 0x02, 0x00, 0x00]);
    const { node } = machoSig.parseASN1(bytes);
    expect(node.tag).toBe(31);
    expect(node.tagClass).toBe(1);

    // Long length form (e.g. length of 128: 0x81, 0x80)
    // INTEGER with length 128: 0x02, 0x81, 0x80, ...128 zeroes
    const longLenBytes = new Uint8Array(131);
    longLenBytes[0] = 0x02; // INTEGER
    longLenBytes[1] = 0x81; // long length form, 1 octet
    longLenBytes[2] = 0x80; // 128 bytes
    const { node: longNode } = machoSig.parseASN1(longLenBytes);
    expect(longNode.type).toBe('INTEGER');
    expect((longNode.value as Uint8Array).length).toBe(128);
  });
});

describe('Mach-O Signature Parser - X509 Name & Certificate Parsing', () => {
  it('should parse X509 names correctly', () => {
    const mockNode: machoSig.ASN1Node = {
      tag: 16,
      tagClass: 0,
      isConstructed: true,
      type: 'SEQUENCE',
      raw: new Uint8Array(),
      value: [
        {
          tag: 17,
          tagClass: 0,
          isConstructed: true,
          type: 'SET',
          raw: new Uint8Array(),
          value: [
            {
              tag: 16,
              tagClass: 0,
              isConstructed: true,
              type: 'SEQUENCE',
              raw: new Uint8Array(),
              value: [
                {
                  tag: 6,
                  tagClass: 0,
                  isConstructed: false,
                  type: 'OBJECT IDENTIFIER',
                  raw: new Uint8Array(),
                  value: new Uint8Array([85, 4, 3]), // 2.5.4.3 -> CN
                },
                {
                  tag: 19,
                  tagClass: 0,
                  isConstructed: false,
                  type: 'PrintableString',
                  raw: new Uint8Array(),
                  value: new Uint8Array([65, 66, 67]), // ABC
                },
              ],
            },
            {
              tag: 16,
              tagClass: 0,
              isConstructed: true,
              type: 'SEQUENCE',
              raw: new Uint8Array(),
              value: [
                {
                  tag: 6,
                  tagClass: 0,
                  isConstructed: false,
                  type: 'OBJECT IDENTIFIER',
                  raw: new Uint8Array(),
                  value: new Uint8Array([85, 4, 10]), // 2.5.4.10 -> O
                },
                {
                  tag: 19,
                  tagClass: 0,
                  isConstructed: false,
                  type: 'PrintableString',
                  raw: new Uint8Array(),
                  value: new Uint8Array([88, 89, 90]), // XYZ
                },
              ],
            },
          ],
        },
      ],
    };

    const parsed = machoSig.parseX509Name(mockNode);
    expect(parsed.CN).toBe('ABC');
    expect(parsed.O).toBe('XYZ');
    expect(machoSig.formatX509Name(parsed)).toBe('CN=ABC, O=XYZ');
  });

  it('should parse validity dates', () => {
    const validityNode: machoSig.ASN1Node = {
      tag: 16,
      tagClass: 0,
      isConstructed: true,
      type: 'SEQUENCE',
      raw: new Uint8Array(),
      value: [
        {
          tag: 23,
          tagClass: 0,
          isConstructed: false,
          type: 'UTCTime',
          raw: new Uint8Array(),
          value: new Uint8Array([
            50, 53, 48, 53, 50, 57, 49, 48, 52, 54, 52, 52, 90,
          ]), // 250529104644Z
        },
        {
          tag: 23,
          tagClass: 0,
          isConstructed: false,
          type: 'UTCTime',
          raw: new Uint8Array(),
          value: new Uint8Array([
            51, 53, 48, 53, 50, 57, 49, 48, 52, 54, 52, 52, 90,
          ]), // 350529104644Z
        },
      ],
    };
    const validity = machoSig.parseValidity(validityNode);
    expect(validity.notBefore).toBe('250529104644Z');
    expect(validity.notAfter).toBe('350529104644Z');
  });

  it('should parse serial numbers', () => {
    const serialNode: machoSig.ASN1Node = {
      tag: 2,
      tagClass: 0,
      isConstructed: false,
      type: 'INTEGER',
      raw: new Uint8Array(),
      value: new Uint8Array([0x12, 0x34, 0x56, 0xab]),
    };
    expect(machoSig.parseSerialNumber(serialNode)).toBe('123456AB');
  });

  it('should parse mock certificate correctly', () => {
    // TBSCertificate nodes: Version, Serial, Signature Algorithm, Issuer, Validity, Subject
    const mockTBS: machoSig.ASN1Node = {
      tag: 16,
      tagClass: 0,
      isConstructed: true,
      type: 'SEQUENCE',
      raw: new Uint8Array(),
      value: [
        {
          tag: 0,
          tagClass: 2,
          isConstructed: true,
          type: 'CONTEXT_0',
          raw: new Uint8Array(),
          value: [],
        }, // Version
        {
          tag: 2,
          tagClass: 0,
          isConstructed: false,
          type: 'INTEGER',
          raw: new Uint8Array(),
          value: new Uint8Array([0x01, 0x02]),
        }, // Serial
        {
          tag: 16,
          tagClass: 0,
          isConstructed: true,
          type: 'SEQUENCE',
          raw: new Uint8Array(),
          value: [],
        }, // Signature Algorithm
        {
          tag: 16,
          tagClass: 0,
          isConstructed: true,
          type: 'SEQUENCE',
          raw: new Uint8Array(),
          value: [],
        }, // Issuer
        {
          tag: 16,
          tagClass: 0,
          isConstructed: true,
          type: 'SEQUENCE',
          raw: new Uint8Array(),
          value: [],
        }, // Validity
        {
          tag: 16,
          tagClass: 0,
          isConstructed: true,
          type: 'SEQUENCE',
          raw: new Uint8Array(),
          value: [],
        }, // Subject
      ],
    };

    const mockCertNode: machoSig.ASN1Node = {
      tag: 16,
      tagClass: 0,
      isConstructed: true,
      type: 'SEQUENCE',
      raw: new Uint8Array([1, 2, 3]),
      value: [
        mockTBS,
        {
          tag: 16,
          tagClass: 0,
          isConstructed: true,
          type: 'SEQUENCE',
          raw: new Uint8Array(),
          value: [],
        },
        {
          tag: 3,
          tagClass: 0,
          isConstructed: false,
          type: 'BIT STRING',
          raw: new Uint8Array(),
          value: new Uint8Array(),
        },
      ],
    };

    const cert = machoSig.parseCertificate(mockCertNode);
    expect(cert).not.toBeNull();
    expect(cert?.serialNumber).toBe('0102');
    expect(cert?.raw).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('should return null for invalid certificate node structures', () => {
    expect(
      machoSig.parseCertificate({
        tag: 1,
        tagClass: 0,
        isConstructed: false,
        type: 'BOOLEAN',
        raw: new Uint8Array(),
        value: new Uint8Array(),
      })
    ).toBeNull();
  });

  it('should extract certificates from context-specific tags', () => {
    const innerCert: machoSig.ASN1Node = {
      tag: 16,
      tagClass: 0,
      isConstructed: true,
      type: 'SEQUENCE',
      raw: new Uint8Array(),
      value: [],
    };
    const rootNode: machoSig.ASN1Node = {
      tag: 16,
      tagClass: 0,
      isConstructed: true,
      type: 'SEQUENCE',
      raw: new Uint8Array(),
      value: [
        {
          tag: 0,
          tagClass: 2,
          isConstructed: true,
          type: 'CONTEXT_0',
          raw: new Uint8Array(),
          value: [innerCert],
        },
      ],
    };
    const extracted = machoSig.extractCertificates(rootNode);
    expect(extracted.length).toBe(1);
    expect(extracted[0]).toBe(innerCert);
  });

  it('should handle signature slot parsing gracefully', () => {
    const result = machoSig.parseSignatureSlot(
      new Uint8Array([0x02, 0x01, 0x00])
    ); // Just an integer
    expect(result.certificates.length).toBe(0);
    expect(result.raw).toBeDefined();

    const resultInvalid = machoSig.parseSignatureSlot(new Uint8Array([]));
    expect(resultInvalid.certificates.length).toBe(0);
  });
});

describe('Mach-O Signature Parser - CodeDirectory Parsing', () => {
  it('should parse a valid CodeDirectory blob', () => {
    // Minimal valid CodeDirectory blob
    // Length: 56 bytes
    const buffer = new ArrayBuffer(56);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    view.setUint32(0, machoSig.CSMAGIC_CODEDIRECTORY, false); // magic
    view.setUint32(4, 56, false); // length
    view.setUint32(8, 0x20200, false); // version
    view.setUint32(12, 0, false); // flags
    view.setUint32(16, 52, false); // hashOffset (starts at 52)
    view.setUint32(20, 44, false); // identOffset (ident string starts at 44)
    view.setUint32(24, 0, false); // nSpecialSlots = 0
    view.setUint32(28, 1, false); // nCodeSlots = 1
    view.setUint32(32, 0, false); // codeLimit
    view.setUint8(36, 4); // hashSize = 4 bytes
    view.setUint8(37, 2); // hashType = 2 (SHA-256)
    view.setUint8(38, 0); // platform
    view.setUint8(39, 12); // pageSize = 4096 (12)
    view.setUint32(40, 0, false); // teamOffset = 0 (none)

    // Write identifier "test\0" starting at offset 44 (identOffset)
    bytes[44] = 't'.charCodeAt(0);
    bytes[45] = 'e'.charCodeAt(0);
    bytes[46] = 's'.charCodeAt(0);
    bytes[47] = 't'.charCodeAt(0);
    bytes[48] = 0; // null terminator

    // Code slot 0 is at hashOffset (52) -> 4 bytes. Write 0xaa 0xbb 0xcc 0xdd
    bytes[52] = 0xaa;
    bytes[53] = 0xbb;
    bytes[54] = 0xcc;
    bytes[55] = 0xdd;

    const parsed = machoSig.parseCodeDirectory(bytes);
    expect(parsed.identifier).toBe('test');
    expect(parsed.hashTypeName).toBe('SHA-256');
    expect(parsed.codeSlots[0]).toBe('aabbccdd');
  });

  it('should throw error for invalid CodeDirectory magic', () => {
    const bytes = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(() => machoSig.parseCodeDirectory(bytes)).toThrow(
      'Invalid CodeDirectory magic'
    );
  });
});

describe('Mach-O Signature Parser - Entitlements Parsing', () => {
  it('should parse XML plist from entitlements payload', () => {
    // Entitlements blob structure: 4 bytes magic, 4 bytes length, then XML content
    const plistText =
      '<plist><dict><key>get-task-allow</key><true/></dict></plist>';
    const header = new Uint8Array([
      0xfa,
      0xde,
      0x0c,
      0x01,
      0,
      0,
      0,
      8 + plistText.length,
    ]);
    const payload = new TextEncoder().encode(plistText);
    const bytes = new Uint8Array(header.length + payload.length);
    bytes.set(header);
    bytes.set(payload, header.length);

    expect(machoSig.parseEntitlements(bytes)).toBe(plistText);
    expect(machoSig.parseEntitlements(new Uint8Array(4))).toBe('');
  });
});

describe('Mach-O Signature Parser - parseMachoSignature', () => {
  it('should correctly parse a complete SuperBlob containing multiple blobs', () => {
    // Let's construct a valid SuperBlob header
    // 0-4: magic: CSMAGIC_EMBEDDED_SIGNATURE (0xfade0cc0)
    // 4-8: length: 97 bytes
    // 8-12: count of blobs (2 blobs: CodeDirectory and Entitlements)
    // 12-20: Blob 1 header: type (0 = CSSLOT_CODEDIRECTORY), offset (28)
    // 20-28: Blob 2 header: type (5 = CSSLOT_ENTITLEMENTS), offset (84)

    // CodeDirectory at 28 (length: 56):
    // Magic: 0xfade0c02
    // Length: 56
    // version: 0x20200
    // identOffset: 44 (within CodeDirectory blob -> absolute 28 + 44 = 72)

    // Entitlements at 84 (length: 13):
    // Magic: 0xfade0c01
    // Length: 13

    const buffer = new ArrayBuffer(97);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // SuperBlob Header
    view.setUint32(0, machoSig.CSMAGIC_EMBEDDED_SIGNATURE, false);
    view.setUint32(4, 97, false);
    view.setUint32(8, 2, false); // 2 blobs

    // Blob 1 entry: CodeDirectory
    view.setUint32(12, machoSig.CSSLOT_CODEDIRECTORY, false);
    view.setUint32(16, 28, false); // offset 28

    // Blob 2 entry: Entitlements
    view.setUint32(20, machoSig.CSSLOT_ENTITLEMENTS, false);
    view.setUint32(24, 84, false); // offset 84

    // Write CodeDirectory blob at offset 28
    view.setUint32(28, machoSig.CSMAGIC_CODEDIRECTORY, false); // magic
    view.setUint32(32, 56, false); // length
    view.setUint32(36, 0x20200, false); // version
    view.setUint32(40, 0, false); // flags
    view.setUint32(44, 40, false); // hashOffset
    view.setUint32(48, 44, false); // identOffset = 44 (28 + 44 = 72)
    view.setUint32(52, 0, false); // nSpecialSlots = 0
    view.setUint32(56, 0, false); // nCodeSlots = 0

    // Ident string "foo\0" at offset 72
    bytes[72] = 'f'.charCodeAt(0);
    bytes[73] = 'o'.charCodeAt(0);
    bytes[74] = 'o'.charCodeAt(0);
    bytes[75] = 0; // null terminator

    // Write Entitlements blob at offset 84
    view.setUint32(84, machoSig.CSMAGIC_REQUIREMENTS, false); // magic
    view.setUint32(88, 13, false); // length = 13
    // Entitlements plist text: "<xml>" (5 bytes) starting at 92 (84 + 8)
    const xmlStr = '<xml>';
    for (let i = 0; i < xmlStr.length; i++) {
      bytes[92 + i] = xmlStr.charCodeAt(i);
    }

    const parsed = machoSig.parseMachoSignature(buffer, 0, 97);
    expect(parsed.magic).toBe(machoSig.CSMAGIC_EMBEDDED_SIGNATURE);
    expect(parsed.magicName).toBe('CSMAGIC_EMBEDDED_SIGNATURE');
    expect(parsed.count).toBe(2);
    expect(parsed.blobs.length).toBe(2);

    expect(parsed.blobs[0].typeName).toBe('CSSLOT_CODEDIRECTORY');
    expect(parsed.blobs[0].payload.identifier).toBe('foo');

    expect(parsed.blobs[1].typeName).toBe('CSSLOT_ENTITLEMENTS');
    expect(parsed.blobs[1].payload).toBe('<xml>');
  });

  it('should throw errors for invalid sizes or magic in parseMachoSignature', () => {
    const emptyBuffer = new ArrayBuffer(0);
    expect(() => machoSig.parseMachoSignature(emptyBuffer, 0, 0)).toThrow(
      'Signature data too small'
    );

    const smallBuffer = new ArrayBuffer(8);
    const view = new DataView(smallBuffer);
    view.setUint32(0, 0x12345678, false);
    expect(() => machoSig.parseMachoSignature(smallBuffer, 0, 8)).toThrow(
      'Invalid SuperBlob magic'
    );
  });
});
