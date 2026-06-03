import { Section } from '../disassembler/types.js';

export interface MemoryRegion {
  address: bigint;
  size: number;
  name: string;
  permissions: {
    read: boolean;
    write: boolean;
    execute: boolean;
  };
}

export class MemoryAccessError extends Error {
  constructor(
    public address: bigint,
    public accessType: 'read' | 'write' | 'execute',
    message: string
  ) {
    super(message);
    this.name = 'MemoryAccessError';
  }
}

export class Memory {
  private pages: Map<bigint, Uint8Array>;
  private pageSize: bigint = 4096n;
  private regions: MemoryRegion[] = [];
  public strictMode: boolean = false;

  constructor() {
    this.pages = new Map();
  }

  /**
   * Clear all memory mappings and regions.
   */
  clear(): void {
    this.pages.clear();
    this.regions = [];
  }

  /**
   * Get the page key for a given virtual address.
   */
  private getPageKey(address: bigint): bigint {
    return address / this.pageSize;
  }

  /**
   * Get the page offset for a given virtual address.
   */
  private getPageOffset(address: bigint): number {
    return Number(address % this.pageSize);
  }

  /**
   * Ensure a page exists at the given page key.
   */
  private ensurePage(pageKey: bigint): Uint8Array {
    let page = this.pages.get(pageKey);
    if (!page) {
      page = new Uint8Array(Number(this.pageSize));
      this.pages.set(pageKey, page);
    }
    return page;
  }

  /**
   * Map a range of memory (ensures pages are pre-allocated/cleared and registers a region).
   */
  map(
    address: bigint,
    size: number,
    name: string = 'anonymous',
    permissions = { read: true, write: true, execute: false }
  ): void {
    const startPage = this.getPageKey(address);
    const endPage = this.getPageKey(address + BigInt(size) - 1n);
    for (let p = startPage; p <= endPage; p++) {
      this.ensurePage(p);
    }

    // Merge or track the region
    this.regions.push({
      address,
      size,
      name,
      permissions,
    });
  }

  /**
   * Get the currently registered memory map/regions.
   */
  getMemoryMap(): MemoryRegion[] {
    return this.regions;
  }

  getPages(): Map<bigint, Uint8Array> {
    return this.pages;
  }

  clearAndLoad(regions: MemoryRegion[], pagesMap: Map<bigint, Uint8Array>): void {
    this.clear();
    this.regions = regions;
    for (const [key, val] of pagesMap.entries()) {
      this.pages.set(key, val);
    }
  }

  /**
   * Find a mapped region containing the given virtual address.
   */
  getRegionAt(address: bigint): MemoryRegion | null {
    for (const region of this.regions) {
      if (
        address >= region.address &&
        address < region.address + BigInt(region.size)
      ) {
        return region;
      }
    }
    return null;
  }

  /**
   * Load sections from a parsed binary buffer and its section list.
   */
  loadSections(binaryData: Uint8Array, sections: Section[]): void {
    for (const sec of sections) {
      const address = BigInt(sec.virtualAddress);
      const size = sec.virtualSize;
      const permissions = {
        read: sec.flags.read,
        write: sec.flags.write,
        execute: sec.flags.execute,
      };

      // Map the memory region
      this.map(address, size, sec.name, permissions);

      // Copy initialized data bypassing permissions
      if (sec.fileSize > 0 && sec.fileOffset < binaryData.length) {
        const loadSize = Math.min(
          sec.fileSize,
          binaryData.length - sec.fileOffset
        );
        const dataToCopy = binaryData.subarray(
          sec.fileOffset,
          sec.fileOffset + loadSize
        );
        this.writeBuffer(address, dataToCopy, true);
      }
    }
  }

  /**
   * Verify memory access permissions.
   */
  private checkPermission(
    address: bigint,
    accessType: 'read' | 'write' | 'execute'
  ): void {
    const region = this.getRegionAt(address);
    if (region) {
      if (!region.permissions[accessType]) {
        throw new MemoryAccessError(
          address,
          accessType,
          `Permission denied: ${accessType} access to address 0x${address.toString(16)} in region '${region.name}'`
        );
      }
    } else if (this.strictMode) {
      throw new MemoryAccessError(
        address,
        accessType,
        `Segmentation fault: ${accessType} access to unmapped address 0x${address.toString(16)}`
      );
    }
  }

  /**
   * Write a buffer to a virtual address.
   */
  writeBuffer(
    address: bigint,
    data: Uint8Array,
    bypassPermissions = false
  ): void {
    for (let i = 0; i < data.length; i++) {
      this.write8(address + BigInt(i), data[i], bypassPermissions);
    }
  }

  /**
   * Read a buffer from a virtual address.
   */
  readBuffer(address: bigint, size: number): Uint8Array {
    const result = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      result[i] = this.read8(address + BigInt(i));
    }
    return result;
  }

  /**
   * Read a single byte.
   */
  read8(address: bigint): number {
    const maskedAddr = address & 0xffffffffffffffffn;
    this.checkPermission(maskedAddr, 'read');
    const pageKey = this.getPageKey(maskedAddr);
    const offset = this.getPageOffset(maskedAddr);
    const page = this.pages.get(pageKey);
    return page ? page[offset] : 0;
  }

  /**
   * Write a single byte.
   */
  write8(address: bigint, value: number, bypassPermissions = false): void {
    const maskedAddr = address & 0xffffffffffffffffn;
    if (!bypassPermissions) {
      this.checkPermission(maskedAddr, 'write');
    }
    const pageKey = this.getPageKey(maskedAddr);
    const offset = this.getPageOffset(maskedAddr);
    const page = this.ensurePage(pageKey);
    page[offset] = value & 0xff;
  }

  /**
   * Read 16-bit word (little-endian).
   */
  read16(address: bigint): number {
    return this.read8(address) | (this.read8(address + 1n) << 8);
  }

  /**
   * Write 16-bit word (little-endian).
   */
  write16(address: bigint, value: number): void {
    this.write8(address, value & 0xff);
    this.write8(address + 1n, (value >> 8) & 0xff);
  }

  /**
   * Read 32-bit double-word (little-endian).
   */
  read32(address: bigint): number {
    return (
      (this.read8(address) |
        (this.read8(address + 1n) << 8) |
        (this.read8(address + 2n) << 16) |
        (this.read8(address + 3n) << 24)) >>>
      0
    );
  }

  /**
   * Write 32-bit double-word (little-endian).
   */
  write32(address: bigint, value: number): void {
    this.write8(address, value & 0xff);
    this.write8(address + 1n, (value >> 8) & 0xff);
    this.write8(address + 2n, (value >> 16) & 0xff);
    this.write8(address + 3n, (value >> 24) & 0xff);
  }

  /**
   * Read 64-bit quad-word (little-endian).
   */
  read64(address: bigint): bigint {
    const low = BigInt(this.read32(address));
    const high = BigInt(this.read32(address + 4n));
    return (high << 32n) | low;
  }

  /**
   * Write 64-bit quad-word (little-endian).
   */
  write64(address: bigint, value: bigint): void {
    const val = value & 0xffffffffffffffffn;
    this.write32(address, Number(val & 0xffffffffn));
    this.write32(address + 4n, Number((val >> 32n) & 0xffffffffn));
  }
}
