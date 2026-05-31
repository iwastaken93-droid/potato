import { inflateRawSync } from 'zlib';

export interface ArchiveEntry {
  path: string; // Flat path, e.g., "classes.dex" or "nested.zip/lib/armeabi-v7a/libnative.so"
  size: number; // Uncompressed size
  compressedSize: number;
  isDirectory: boolean;
  compressionMethod: number;
  executableType: 'DEX' | 'Class' | 'ELF' | 'Mach-O' | 'Unknown';
}

interface RawCentralDirectoryEntry {
  path: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  localHeaderOffset: number;
  isDirectory: boolean;
}

export class ArchiveUnpacker {
  private buffer: Uint8Array;

  constructor(buffer: ArrayBuffer | Uint8Array) {
    this.buffer =
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  }

  /**
   * Helper to parse the End of Central Directory (EOCD) to locate the central directory.
   */
  private findEOCD(): number {
    const minOffset = Math.max(0, this.buffer.length - 65535 - 22);
    for (let i = this.buffer.length - 22; i >= minOffset; i--) {
      if (
        this.buffer[i] === 0x50 &&
        this.buffer[i + 1] === 0x4b &&
        this.buffer[i + 2] === 0x05 &&
        this.buffer[i + 3] === 0x06
      ) {
        return i;
      }
    }
    throw new Error(
      'Invalid ZIP archive: End of Central Directory (EOCD) signature not found.'
    );
  }

  /**
   * Lists the direct entries inside the current zip archive.
   */
  private listLocalEntries(): RawCentralDirectoryEntry[] {
    if (this.buffer.length < 22) {
      return [];
    }

    try {
      const eocdOffset = this.findEOCD();
      const view = new DataView(
        this.buffer.buffer,
        this.buffer.byteOffset,
        this.buffer.byteLength
      );

      const cdEntriesCount = view.getUint16(eocdOffset + 10, true);
      const cdOffset = view.getUint32(eocdOffset + 16, true);

      const entries: RawCentralDirectoryEntry[] = [];
      let currentOffset = cdOffset;

      for (let i = 0; i < cdEntriesCount; i++) {
        if (currentOffset + 46 > this.buffer.length) {
          break;
        }

        // Check Central Directory signature "PK\x01\x02"
        if (
          this.buffer[currentOffset] !== 0x50 ||
          this.buffer[currentOffset + 1] !== 0x4b ||
          this.buffer[currentOffset + 2] !== 0x01 ||
          this.buffer[currentOffset + 3] !== 0x02
        ) {
          break;
        }

        const compressionMethod = view.getUint16(currentOffset + 10, true);
        const compressedSize = view.getUint32(currentOffset + 20, true);
        const uncompressedSize = view.getUint32(currentOffset + 24, true);
        const fileNameLength = view.getUint16(currentOffset + 28, true);
        const extraFieldLength = view.getUint16(currentOffset + 30, true);
        const fileCommentLength = view.getUint16(currentOffset + 32, true);
        const localHeaderOffset = view.getUint32(currentOffset + 42, true);

        if (currentOffset + 46 + fileNameLength > this.buffer.length) {
          break;
        }

        const fileNameBytes = this.buffer.subarray(
          currentOffset + 46,
          currentOffset + 46 + fileNameLength
        );
        const path = new TextDecoder().decode(fileNameBytes);
        const isDirectory = path.endsWith('/');

        entries.push({
          path,
          compressedSize,
          uncompressedSize,
          compressionMethod,
          localHeaderOffset,
          isDirectory,
        });

        currentOffset +=
          46 + fileNameLength + extraFieldLength + fileCommentLength;
      }

      return entries;
    } catch {
      // If parsing central directory fails, return empty
      return [];
    }
  }

  /**
   * Decompresses and extracts a single local entry by its RawCentralDirectoryEntry description.
   */
  private extractLocalEntry(entry: RawCentralDirectoryEntry): Uint8Array {
    if (entry.isDirectory) {
      return new Uint8Array(0);
    }

    const view = new DataView(
      this.buffer.buffer,
      this.buffer.byteOffset,
      this.buffer.byteLength
    );
    const localHeaderOffset = entry.localHeaderOffset;

    if (localHeaderOffset + 30 > this.buffer.length) {
      throw new Error(`Malformed local header offset for: ${entry.path}`);
    }

    // Verify local header signature "PK\x03\x04"
    if (
      this.buffer[localHeaderOffset] !== 0x50 ||
      this.buffer[localHeaderOffset + 1] !== 0x4b ||
      this.buffer[localHeaderOffset + 2] !== 0x03 ||
      this.buffer[localHeaderOffset + 3] !== 0x04
    ) {
      throw new Error(`Invalid local header signature for: ${entry.path}`);
    }

    const localFileNameLength = view.getUint16(localHeaderOffset + 26, true);
    const localExtraFieldLength = view.getUint16(localHeaderOffset + 28, true);
    const dataOffset =
      localHeaderOffset + 30 + localFileNameLength + localExtraFieldLength;

    if (dataOffset + entry.compressedSize > this.buffer.length) {
      throw new Error(`Truncated file data for: ${entry.path}`);
    }

    const compressedData = this.buffer.subarray(
      dataOffset,
      dataOffset + entry.compressedSize
    );

    if (entry.compressionMethod === 0) {
      return new Uint8Array(compressedData);
    } else if (entry.compressionMethod === 8) {
      try {
        return new Uint8Array(inflateRawSync(compressedData));
      } catch (err) {
        throw new Error(
          `Decompression failed for ${entry.path}: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err }
        );
      }
    } else {
      throw new Error(
        `Unsupported compression method ${entry.compressionMethod} for: ${entry.path}`
      );
    }
  }

  /**
   * Identifies the executable component type based on file magic bytes and path extension.
   */
  private detectExecutableType(
    data: Uint8Array,
    path: string
  ): ArchiveEntry['executableType'] {
    if (data.length < 4) {
      return 'Unknown';
    }

    const magic =
      ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0;

    // ELF magic: 0x7F 'E' 'L' 'F' (0x7F454C46)
    if (magic === 0x7f454c46) {
      return 'ELF';
    }

    // DEX magic: "dex\n" (0x6465780a)
    if (magic === 0x6465780a) {
      return 'DEX';
    }

    // Java Class magic: 0xCAFEBABE
    // Mach-O Fat magic: 0xCAFEBABE (or reverse 0xBEBAFECA)
    // Mach-O Thin magic: 0xFEEDFACE or 0xFEEDFACF (reverse 0xCEFAEDFE or 0xCFFAEDFE)
    if (
      magic === 0xfeedface ||
      magic === 0xfeedfacf ||
      magic === 0xcefaedfe ||
      magic === 0xcffaedfe
    ) {
      return 'Mach-O';
    }

    if (magic === 0xcafebabe || magic === 0xbebafeca) {
      // Differentiate by file extension if possible, default to Class inside jar/zip
      if (path.endsWith('.class')) {
        return 'Class';
      }
      // If it looks like a macho (thin/fat) or from layout, can be Mach-O.
      // Often ca-fe-ba-be with .class extension is Java Class.
      return 'Class';
    }

    return 'Unknown';
  }

  /**
   * Helper to check if a file extension represents an archive.
   */
  private isArchiveExtension(path: string): boolean {
    const lower = path.toLowerCase();
    return (
      lower.endsWith('.zip') ||
      lower.endsWith('.apk') ||
      lower.endsWith('.jar') ||
      lower.endsWith('.ipa')
    );
  }

  /**
   * Lists all entries recursively, including contents of nested ZIP/APK/JAR/IPA files.
   */
  public listAllEntries(): ArchiveEntry[] {
    const results: ArchiveEntry[] = [];
    const localEntries = this.listLocalEntries();

    for (const entry of localEntries) {
      if (entry.isDirectory) {
        results.push({
          path: entry.path,
          size: entry.uncompressedSize,
          compressedSize: entry.compressedSize,
          isDirectory: true,
          compressionMethod: entry.compressionMethod,
          executableType: 'Unknown',
        });
        continue;
      }

      let data: Uint8Array | null = null;
      try {
        data = this.extractLocalEntry(entry);
      } catch {
        // Skip or append with unknown if extraction fails
      }

      const executableType = data
        ? this.detectExecutableType(data, entry.path)
        : 'Unknown';

      results.push({
        path: entry.path,
        size: entry.uncompressedSize,
        compressedSize: entry.compressedSize,
        isDirectory: false,
        compressionMethod: entry.compressionMethod,
        executableType,
      });

      // If it's a nested archive, recurse into it
      if (this.isArchiveExtension(entry.path) && data) {
        try {
          const subUnpacker = new ArchiveUnpacker(data);
          const subEntries = subUnpacker.listAllEntries();
          for (const subEntry of subEntries) {
            results.push({
              path: `${entry.path}/${subEntry.path}`,
              size: subEntry.size,
              compressedSize: subEntry.compressedSize,
              isDirectory: subEntry.isDirectory,
              compressionMethod: subEntry.compressionMethod,
              executableType: subEntry.executableType,
            });
          }
        } catch {
          // If sub-parsing fails, just continue
        }
      }
    }

    return results;
  }

  /**
   * Extracts a specific entry by path. Supports nested paths separated by forward slashes,
   * e.g., "nested.zip/classes.dex".
   */
  public extractEntry(targetPath: string): Uint8Array {
    const normalizedTarget = targetPath.replace(/\\/g, '/');
    const localEntries = this.listLocalEntries();

    // Try exact local match first
    const exactMatch = localEntries.find((e) => e.path === normalizedTarget);
    if (exactMatch) {
      return this.extractLocalEntry(exactMatch);
    }

    // Try nested match: e.g. targetPath = "lib.jar/com/test/Foo.class"
    // We look for a local entry that is a prefix archive.
    for (const entry of localEntries) {
      if (
        this.isArchiveExtension(entry.path) &&
        normalizedTarget.startsWith(entry.path + '/')
      ) {
        const remainingPath = normalizedTarget.substring(entry.path.length + 1);
        const subArchiveData = this.extractLocalEntry(entry);
        const subUnpacker = new ArchiveUnpacker(subArchiveData);
        return subUnpacker.extractEntry(remainingPath);
      }
    }

    throw new Error(`Entry not found: ${targetPath}`);
  }
}
