import { describe, it, expect } from 'vitest';
import { parseDebugLoclists } from '../src/parser/dwarfParser.js';

describe('dwarf v5 .debug_loclists tests', () => {
  it('should parse a mock DWARF v5 .debug_loclists section', () => {
    const bytes: number[] = [];

    // Header
    // 1. unit_length (4 bytes) - populated later
    bytes.push(0, 0, 0, 0);
    const startOfUnit = bytes.length;

    // 2. version (2 bytes) = 5
    bytes.push(5, 0);

    // 3. address_size (1 byte) = 8
    bytes.push(8);

    // 4. segment_selector_size (1 byte) = 0
    bytes.push(0);

    // 5. offset_entry_count (4 bytes) = 2
    bytes.push(2, 0, 0, 0);

    // Offsets table starts at 12 from start of table.
    // Offset 0: points to list 1 (offset 8 from start of offset array)
    bytes.push(8, 0, 0, 0);
    // Offset 1: points to list 2 (offset 24 from start of offset array)
    bytes.push(24, 0, 0, 0);

    // List 1 (at table offset 12 + 8 = 20)
    // Entry 1: DW_LLE_base_address (0x06)
    bytes.push(0x06);
    // Base Address = 0x1000 (8 bytes)
    bytes.push(0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    // Entry 2: DW_LLE_offset_pair (0x04)
    bytes.push(0x04);
    bytes.push(0x10); // start_offset = 0x10
    bytes.push(0x20); // end_offset = 0x20
    bytes.push(2);    // expr_len = 2
    bytes.push(0x55, 0x66); // expression

    // Entry 3: DW_LLE_end_of_list (0x00)
    bytes.push(0x00);

    // List 2 (at table offset 12 + 24 = 36)
    // Entry 1: DW_LLE_start_end (0x07)
    bytes.push(0x07);
    // Start Address = 0x5000 (8 bytes)
    bytes.push(0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    // End Address = 0x6000 (8 bytes)
    bytes.push(0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    bytes.push(1);    // expr_len = 1
    bytes.push(0x99); // expression

    // Entry 2: DW_LLE_default_location (0x05)
    bytes.push(0x05);
    bytes.push(3);    // expr_len = 3
    bytes.push(0x11, 0x22, 0x33); // expression

    // Entry 3: DW_LLE_end_of_list (0x00)
    bytes.push(0x00);

    const endOfUnit = bytes.length;
    const unitLength = endOfUnit - 4; // 32-bit DWARF unit length field itself excluded
    bytes[0] = unitLength & 0xff;
    bytes[1] = (unitLength >> 8) & 0xff;
    bytes[2] = (unitLength >> 16) & 0xff;
    bytes[3] = (unitLength >> 24) & 0xff;

    const buffer = new Uint8Array(bytes).buffer;
    const tables = parseDebugLoclists(buffer);

    expect(tables).toHaveLength(1);
    const table = tables[0];
    expect(table.version).toBe(5);
    expect(table.addressSize).toBe(8);
    expect(table.offsetEntryCount).toBe(2);
    expect(table.offsets).toEqual([8, 24]);

    // Check list 1
    const list1 = table.lists.get(20);
    expect(list1).toBeDefined();
    expect(list1).toHaveLength(3);
    expect(list1![0].typeName).toBe('DW_LLE_base_address');
    expect(list1![0].startAddress).toBe(0x1000);
    expect(list1![1].typeName).toBe('DW_LLE_offset_pair');
    expect(list1![1].offsetStart).toBe(0x10);
    expect(list1![1].offsetEnd).toBe(0x20);
    expect(Array.from(list1![1].expression)).toEqual([0x55, 0x66]);
    expect(list1![2].typeName).toBe('DW_LLE_end_of_list');

    // Check list 2
    const list2 = table.lists.get(36);
    expect(list2).toBeDefined();
    expect(list2).toHaveLength(3);
    expect(list2![0].typeName).toBe('DW_LLE_start_end');
    expect(list2![0].startAddress).toBe(0x5000);
    expect(list2![0].endAddress).toBe(0x6000);
    expect(Array.from(list2![0].expression)).toEqual([0x99]);
    expect(list2![1].typeName).toBe('DW_LLE_default_location');
    expect(Array.from(list2![1].expression)).toEqual([0x11, 0x22, 0x33]);
    expect(list2![2].typeName).toBe('DW_LLE_end_of_list');
  });
});
