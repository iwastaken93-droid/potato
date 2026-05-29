# 🧬 Binary Parsers (ELF, PE, Mach-O, DEX, WASM)

DISSECT implements zero-dependency parsers for five major executable and bytecode file formats. Each parser reads a binary `Uint8Array` buffer sequentially using helper readers to reconstruct native headers and metadata structures.

---

## 🛠️ Parser List & File Locations

| Format     | Module File                                                                              | Description                                     | Magic Numbers                |
| :--------- | :--------------------------------------------------------------------------------------- | :---------------------------------------------- | :--------------------------- |
| **ELF**    | [elf.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/elf.ts)     | Executable and Linkable Format (Linux/BSD/Unix) | `7f 45 4c 46` (`\x7fELF`)    |
| **PE**     | [pe.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/pe.ts)       | Portable Executable (Windows PE32/PE32+)        | `4d 5a` (`MZ` header)        |
| **Mach-O** | [macho.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/macho.ts) | Mach Object (macOS/iOS/Darwin Executable)       | `fe ed fa ce`, `fe ed fa cf` |
| **DEX**    | [dex.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dex.ts)     | Dalvik Executable (Android bytecode)            | `64 65 78 0a` (`dex\n`)      |
| **WASM**   | [wasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/wasm.ts)   | WebAssembly Binary Module                       | `00 61 73 6d` (`\x00asm`)    |

---

## 🔍 Detailed Parsing Mechanisms

### 🐧 1. ELF (Executable and Linkable Format)

The ELF parser supports both 32-bit and 64-bit offsets, Little Endian and Big Endian byte layouts.

- **Header Decoding**: Parses the `e_ident` array to identify bitness (`class`), byte order (`endianness`), OS ABI, file type (REL, EXEC, DYN, CORE), and target machine architecture (x86, ARM, AMD64).
- **Program Headers**: Loops through program headers (segments) representing runtime memory layout. Decodes flags to resolve R, W, and X permissions.
- **Section Headers**: Identifies static layout structure. When string tables (`shstrtab`, `strtab`, `dynstr`) are parsed, offsets are resolved to represent section names (e.g. `.text`, `.data`, `.rodata`, `.bss`, `.symtab`).
- **Symbol Table**: Walks `.symtab` and `.dynsym` entries to extract local and global labels.

### 🪟 2. PE (Portable Executable)

Designed to handle both PE32 (32-bit) and PE32+ (64-bit) architectures.

- **DOS Stub**: Locates the `MZ` signature and extracts the `e_lfanew` pointer at offset `0x3C`, which points to the starting location of the NT headers.
- **COFF File Header**: Decodes characteristics, timestamp, number of sections, and machine type (e.g., AMD64, I386, ARM64).
- **Optional Header**: Decodes memory layout settings, including the entrypoint relative virtual address (RVA), section alignment (commonly `0x1000`), file alignment (commonly `0x200`), image base, and size of image.
- **Data Directories**: Parses up to 16 directory structures pointing to import tables, export tables, resources, and exception records.
- **Imports & Exports**: Walks the import address table (IAT) resolving DLL names and imported functions. Decodes the export table to catalog public symbols and ordinals.

### 🍎 3. Mach-O (macOS & iOS Executables)

Capable of processing 32-bit, 64-bit, and Fat/Universal binary wraps.

- **Universal Header**: Detects universal wrappers (`0xcafebabe` or `0xbebafeca`). Iterates over target slices (fat architectures) to automatically select and extract the slice corresponding to x86_64 or ARM.
- **Load Commands**: Iterates through variable-length commands following the main Mach-O header.
  - `LC_SEGMENT` / `LC_SEGMENT_64`: Maps segments (such as `__TEXT`, `__DATA`, `__LINKEDIT`) and sections (`__text`, `__cstring`, `__const`).
  - `LC_SYMTAB`: Provides offsets for symbol tables and string pools.
  - `LC_MAIN`: Contains the offset representing the program's main entrypoint.
  - `LC_LOAD_DYLIB`: Identifies referenced shared libraries (dylibs).

### 🤖 4. DEX (Dalvik Executable)

Decodes Android bytecode files.

- **Header Mapping**: Validates DEX version (`dex\n035\0` or `dex\n039\0`). Collects size boundaries and table offsets for String IDs, Type IDs, Proto IDs, Field IDs, Method IDs, Class Definitions, and the overall Data section.
- **String & Type Resolvers**: Parses the string pool using LEB128 lengths and decodes Type descriptors (e.g. `Ljava/lang/String;`).
- **Prototypes & Methods**: Resolves method signatures (parameters, return types) and associations.
- **Class Definitions**: Iterates over class fields and methods. Extracts `CodeItem` records containing instruction counts, registers used, catch handler tables, and raw bytecode offsets.

### 🕸️ 5. WASM (WebAssembly)

Parses structured WebAssembly binaries conforming to the W3C WASM specs.

- **Leb128 Decoding**: Implements varint parsing to read unsigned/signed 32-bit and 64-bit variables.
- **Section Scanner**: Loops through standard section IDs (Type, Import, Function, Table, Memory, Global, Export, Start, Element, Code, Data).
- **Type & Function Signatures**: Decodes parameter and result types (i32, i64, f32, f64, v128, reference types) into structured objects.
- **Code Section Parser**: Inspects raw bytecode instruction streams within function blocks. Decodes WASM control instructions (`block`, `loop`, `if`, `br`, `br_table`), variable instructions (`local.get`, `global.set`), and numeric operations (`i32.add`, `f64.mul`).

---

## 🔄 Parser Interface Schema

All parsers return a structured format that conforms to or can be mapped by the `DisassemblerRouter` to extract sections, symbols, and code:

```typescript
export interface UnifiedParsedBinary {
  format: 'elf' | 'pe' | 'macho' | 'dex' | 'wasm';
  entryPoint: number;
  sections: UnifiedSection[];
  symbols: UnifiedSymbol[];
  metadata: Record<string, any>;
}

export interface UnifiedSection {
  name: string;
  virtualAddress: number;
  size: number;
  data: Uint8Array;
  permissions: {
    read: boolean;
    write: boolean;
    execute: boolean;
  };
}

export interface UnifiedSymbol {
  name: string;
  address: number;
  type: 'function' | 'object' | 'section' | 'unknown';
}
```
