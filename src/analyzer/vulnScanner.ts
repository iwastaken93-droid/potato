/**
 * Vulnerability Scanner Core Module.
 * Detects security issues like:
 * - Unsafe APIs (strcpy, sprintf, gets, etc.)
 * - Buffer overflows (potential unchecked bounds or loops)
 * - Integer overflows (arithmetic operations on untrusted sizes or near potential bounds)
 */

import { Section, Symbol, Instruction } from '../disassembler/types.js';
import { PEParser } from '../parser/pe.js';

export interface VulnMatch {
  /** Vulnerability type: 'unsafe_api' | 'buffer_overflow' | 'integer_overflow' | 'format_string' */
  category:
    | 'unsafe_api'
    | 'buffer_overflow'
    | 'integer_overflow'
    | 'format_string';
  /** Severity: 'high' | 'medium' | 'low' */
  severity: 'high' | 'medium' | 'low';
  /** Human readable description */
  description: string;
  /** Address where the vulnerability was detected, if applicable */
  address?: number;
  /** Extracted symbol name or trigger string */
  evidence: string;
  /** Library/DLL name where the function is imported from */
  library?: string;
}

export interface VulnScannerConfig {
  /** Check unsafe APIs */
  unsafeApi?: boolean;
  /** Check buffer overflow patterns */
  bufferOverflow?: boolean;
  /** Check integer overflow patterns */
  integerOverflow?: boolean;
}

export class VulnScanner {
  /**
   * Set of unsafe C standard library APIs.
   */
  private static UNSAFE_APIS = new Map<
    string,
    { severity: 'high' | 'medium'; desc: string }
  >([
    [
      'strcpy',
      {
        severity: 'high',
        desc: 'Unsafe copy function (strcpy) does not validate destination buffer bounds. Use strncpy or strlcpy instead.',
      },
    ],
    [
      'strcat',
      {
        severity: 'high',
        desc: 'Unsafe string concatenation (strcat) does not validate bounds. Use strncat or strlcat instead.',
      },
    ],
    [
      'sprintf',
      {
        severity: 'high',
        desc: 'Unsafe formatted string generation (sprintf) does not check bounds. Use snprintf instead.',
      },
    ],
    [
      'gets',
      {
        severity: 'high',
        desc: 'gets() is completely obsolete and highly dangerous as it lacks buffer length validation.',
      },
    ],
    [
      'vsprintf',
      {
        severity: 'high',
        desc: 'Unsafe format string output function (vsprintf) can lead to buffer overflow. Use vsnprintf.',
      },
    ],
    [
      'scanf',
      {
        severity: 'medium',
        desc: 'scanf() can lead to buffer overflows when reading strings if width limiters are omitted.',
      },
    ],
    [
      'sscanf',
      {
        severity: 'medium',
        desc: 'sscanf() can lead to buffer overflows if width limiters are omitted.',
      },
    ],
    [
      'fscanf',
      {
        severity: 'medium',
        desc: 'fscanf() can lead to buffer overflows if width limiters are omitted.',
      },
    ],
    [
      'wcscpy',
      {
        severity: 'high',
        desc: 'Unsafe wide character copy (wcscpy). Use wcsncpy instead.',
      },
    ],
    [
      'wcscat',
      {
        severity: 'high',
        desc: 'Unsafe wide character concatenation (wcscat). Use wcsncat instead.',
      },
    ],
    [
      'realpath',
      {
        severity: 'medium',
        desc: 'realpath() can overflow the destination buffer if it is smaller than PATH_MAX.',
      },
    ],
    [
      'tempnam',
      {
        severity: 'medium',
        desc: 'tempnam() creates temporary files insecurely. Use mkstemp instead.',
      },
    ],
    [
      'tmpnam',
      {
        severity: 'medium',
        desc: 'tmpnam() creates temporary files insecurely. Use mkstemp instead.',
      },
    ],
    [
      'getwd',
      {
        severity: 'high',
        desc: 'getwd() does not prevent overflow of buffer. Use getcwd instead.',
      },
    ],
    [
      'system',
      {
        severity: 'high',
        desc: 'Potential command injection vulnerability on system() calls. Ensure argument inputs are strictly sanitized.',
      },
    ],
  ]);

  /**
   * Scans instructions, symbols, and sections to identify potential vulnerability patterns.
   */
  public scan(
    binaryData: Uint8Array,
    sections: Section[],
    symbols: Symbol[],
    instructions: Instruction[],
    config: VulnScannerConfig = {
      unsafeApi: true,
      bufferOverflow: true,
      integerOverflow: true,
    }
  ): VulnMatch[] {
    const matches: VulnMatch[] = [];

    const symbolToLibrary = new Map<string, string>();
    if (binaryData && binaryData.length > 0) {
      let detected = 'auto';
      if (binaryData[0] === 0x7f && binaryData[1] === 0x45 && binaryData[2] === 0x4c && binaryData[3] === 0x46) {
        detected = 'elf';
      } else if (binaryData[0] === 0x4d && binaryData[1] === 0x5a) {
        detected = 'pe';
      } else if (
        (binaryData[0] === 0xfe && binaryData[1] === 0xed && binaryData[2] === 0xfa && binaryData[3] === 0xcf) ||
        (binaryData[0] === 0xcf && binaryData[1] === 0xfa && binaryData[2] === 0xed && binaryData[3] === 0xfe)
      ) {
        detected = 'macho';
      }

      try {
        if (detected === 'pe') {
          const parser = new PEParser(binaryData.buffer as ArrayBuffer);
          const parsed = parser.parse();
          for (const impTable of parsed.imports) {
            for (const imp of impTable.imports) {
              if (imp.name) {
                symbolToLibrary.set(imp.name, impTable.dllName);
                symbolToLibrary.set(this.cleanSymbolName(imp.name), impTable.dllName);
              }
            }
          }
        }
      } catch (_) {}
    }

    // 1. Unsafe API Checks (via imported symbols & instruction calls)
    if (config.unsafeApi) {
      // Direct symbol scan
      for (const sym of symbols) {
        const cleanedName = this.cleanSymbolName(sym.name);
        if (VulnScanner.UNSAFE_APIS.has(cleanedName)) {
          const apiInfo = VulnScanner.UNSAFE_APIS.get(cleanedName)!;
          let libraryName: string | undefined;
          if (symbolToLibrary.has(sym.name)) {
            libraryName = symbolToLibrary.get(sym.name);
          } else if (symbolToLibrary.has(cleanedName)) {
            libraryName = symbolToLibrary.get(cleanedName);
          }
          matches.push({
            category: 'unsafe_api',
            severity: apiInfo.severity,
            description: apiInfo.desc,
            address: sym.address,
            evidence: sym.name,
            ...(libraryName ? { library: libraryName } : {})
          });
        }
      }

      // Check instructions for direct jumps or calls to known unsafe APIs
      for (const inst of instructions) {
        const isCall =
          inst.mnemonic.toLowerCase() === 'call' ||
          inst.mnemonic.toLowerCase().startsWith('jmp');
        if (isCall && inst.opStr) {
          const dest = inst.opStr.trim();
          const cleanedDest = this.cleanSymbolName(dest);
          if (VulnScanner.UNSAFE_APIS.has(cleanedDest)) {
            const apiInfo = VulnScanner.UNSAFE_APIS.get(cleanedDest)!;
            let libraryName: string | undefined;
            if (symbolToLibrary.has(dest)) {
              libraryName = symbolToLibrary.get(dest);
            } else if (symbolToLibrary.has(cleanedDest)) {
              libraryName = symbolToLibrary.get(cleanedDest);
            }
            matches.push({
              category: 'unsafe_api',
              severity: apiInfo.severity,
              description: `Instruction calls dangerous API: ${cleanedDest}. ${apiInfo.desc}`,
              address: inst.address,
              evidence: inst.opStr,
              ...(libraryName ? { library: libraryName } : {})
            });
          }
        }
      }
    }

    // 2. Buffer Overflow / Out-of-bounds Checks
    if (config.bufferOverflow) {
      // Find patterns of dangerous copy loop or memory manipulations
      for (let i = 0; i < instructions.length; i++) {
        const inst = instructions[i];
        const mnemonic = inst.mnemonic.toLowerCase();

        // Pattern A: rep movs (common assembly block copy without size validation checking)
        if (mnemonic.startsWith('rep movs') || mnemonic === 'repnz movs') {
          matches.push({
            category: 'buffer_overflow',
            severity: 'medium',
            description:
              'Repeated string/memory move instruction (rep movs) detected. May perform an unchecked block copy if the counter register (ecx/rcx) is not securely bounded.',
            address: inst.address,
            evidence: inst.mnemonic + ' ' + inst.opStr,
          });
        }

        // Pattern B: Writing to stacks with huge local buffer displacements (e.g. sub rsp, 0x1000 or similar large structures)
        if (mnemonic === 'sub' && inst.operands && inst.operands.length >= 2) {
          const op0 = inst.operands[0];
          const op1 = inst.operands[1];
          if (op0.type === 'reg' && (op0.reg === 'rsp' || op0.reg === 'esp')) {
            const val = Number(op1.imm);
            if (val >= 1024) {
              matches.push({
                category: 'buffer_overflow',
                severity: 'low',
                description: `Large stack frame allocation (${val} bytes) detected. Large stack buffers can be targets for stack-based buffer overflows. Ensure all bounds check are implemented.`,
                address: inst.address,
                evidence: `sub ${op0.reg}, 0x${val.toString(16)}`,
              });
            }
          }
        }
      }
    }

    // 3. Integer Overflow Checks
    if (config.integerOverflow) {
      for (let i = 0; i < instructions.length; i++) {
        const inst = instructions[i];
        const mnemonic = inst.mnemonic.toLowerCase();

        // Pattern A: Arithmetic operations followed by conditional jump (potential unsafe overflow checks)
        // e.g. add, mul, imul, sub
        if (
          mnemonic === 'add' ||
          mnemonic === 'mul' ||
          mnemonic === 'imul' ||
          mnemonic === 'sub'
        ) {
          // Look ahead to check if the next instruction is a conditional jump for overflow/carry
          if (i + 1 < instructions.length) {
            const nextInst = instructions[i + 1];
            const nextMnemonic = nextInst.mnemonic.toLowerCase();
            // jo (jump on overflow), jc (jump on carry), jb (jump on below), jnae (jump on not above or equal)
            if (['jo', 'jc', 'jb', 'jnae', 'js'].includes(nextMnemonic)) {
              // This is a sign of an overflow check, which is good, but we report it as low/info to guide auditor
              continue;
            }
          }

          // If no jump/check is visible nearby, check if arithmetic operation is done on registers
          // typically involved in length calculation or array indexing (e.g. index/offset registers)
          const hasRegDest =
            inst.operands &&
            inst.operands.length > 0 &&
            inst.operands[0].type === 'reg';
          if (hasRegDest) {
            const regName = String(inst.operands[0].reg).toLowerCase();
            // Common loop/indexing registers or counter registers
            const isIndexReg = [
              'ecx',
              'rcx',
              'esi',
              'rsi',
              'edi',
              'rdi',
            ].includes(regName);

            // Check if there's a large immediate operand
            let isLargeImmediate = false;
            if (inst.operands.length >= 2 && inst.operands[1].type === 'imm') {
              const immVal = Number(inst.operands[1].imm);
              if (immVal >= 32767) {
                isLargeImmediate = true;
              }
            }

            if (isIndexReg || isLargeImmediate) {
              matches.push({
                category: 'integer_overflow',
                severity: 'low',
                description: isLargeImmediate
                  ? `Arithmetic operation (${mnemonic}) with a large immediate value on register (${regName}). Watch out for possible integer overflow.`
                  : `Arithmetic operation (${mnemonic}) on index/counter register (${regName}) without direct adjacent overflow check. Watch out for possible integer wraparound.`,
                address: inst.address,
                evidence: `${inst.mnemonic} ${inst.opStr}`,
              });
            }
          }
        }

        // Pattern B: Signed division (idiv) without overflow checks on divisor
        if (mnemonic === 'idiv') {
          matches.push({
            category: 'integer_overflow',
            severity: 'low',
            description:
              'Signed division instruction (idiv) detected. Division by zero or division of INT_MIN by -1 can cause an integer overflow/CPU exception.',
            address: inst.address,
            evidence: `idiv ${inst.opStr}`,
          });
        }
      }
    }

    // 4. API Combination Risk Scoring
    const cleanSymNames = new Set(symbols.map(s => this.cleanSymbolName(s.name)));

    const hasMemAlloc = cleanSymNames.has('VirtualAlloc') || cleanSymNames.has('VirtualProtect') || cleanSymNames.has('VirtualAllocEx');
    const hasExecution = cleanSymNames.has('system') || cleanSymNames.has('CreateProcess') || cleanSymNames.has('CreateProcessA') || cleanSymNames.has('CreateProcessW') || cleanSymNames.has('ShellExecute') || cleanSymNames.has('ShellExecuteA') || cleanSymNames.has('ShellExecuteW') || cleanSymNames.has('CreateRemoteThread') || cleanSymNames.has('WriteProcessMemory') || cleanSymNames.has('execve');

    if (hasMemAlloc && hasExecution) {
      matches.push({
        category: 'unsafe_api',
        severity: 'high',
        description: 'Dangerous API combination: Memory allocation/protection API (VirtualAlloc/VirtualProtect) + Execution/Injection API (system/CreateProcess/CreateRemoteThread/WriteProcessMemory) detected. Often indicative of dynamic shellcode loading and execution.',
        evidence: Array.from(cleanSymNames).filter(name => ['VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx', 'system', 'CreateProcess', 'CreateProcessA', 'CreateProcessW', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW', 'CreateRemoteThread', 'WriteProcessMemory', 'execve'].includes(name)).join(', ')
      });
    }

    const hasAntiDebug = cleanSymNames.has('IsDebuggerPresent') || cleanSymNames.has('CheckRemoteDebuggerPresent') || cleanSymNames.has('NtQueryInformationProcess') || cleanSymNames.has('ptrace');
    const hasExit = cleanSymNames.has('TerminateProcess') || cleanSymNames.has('ExitProcess') || cleanSymNames.has('exit') || cleanSymNames.has('_exit');

    if (hasAntiDebug && hasExit) {
      matches.push({
        category: 'unsafe_api',
        severity: 'medium',
        description: 'Suspicious API combination: Anti-debugging/evasion API (IsDebuggerPresent/NtQueryInformationProcess/ptrace) + Process termination API (TerminateProcess/ExitProcess/exit) detected. Often indicative of anti-analysis or VM evasion checks.',
        evidence: Array.from(cleanSymNames).filter(name => ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'ptrace', 'TerminateProcess', 'ExitProcess', 'exit', '_exit'].includes(name)).join(', ')
      });
    }

    const hasLoadLib = cleanSymNames.has('LoadLibrary') || cleanSymNames.has('LoadLibraryA') || cleanSymNames.has('LoadLibraryW') || cleanSymNames.has('dlopen');
    const hasGetProc = cleanSymNames.has('GetProcAddress') || cleanSymNames.has('dlsym');

    if (hasLoadLib && hasGetProc) {
      matches.push({
        category: 'unsafe_api',
        severity: 'medium',
        description: 'Evasive API combination: Dynamic library load API (LoadLibrary/dlopen) + Symbol resolution API (GetProcAddress/dlsym) detected. Often used to dynamically resolve and call API functions to evade static analysis.',
        evidence: Array.from(cleanSymNames).filter(name => ['LoadLibrary', 'LoadLibraryA', 'LoadLibraryW', 'dlopen', 'GetProcAddress', 'dlsym'].includes(name)).join(', ')
      });
    }

    return matches;
  }

  /**
   * Cleans symbol names (removes prefixes, namespaces, or DLL linkages).
   */
  private cleanSymbolName(name: string): string {
    let clean = name.replace(/^(__imp_dll_|__imp_|imp_|__dl_)/, '');
    // Clean C++ mangled name or API suffixes
    const dotIndex = clean.indexOf('.');
    if (dotIndex !== -1) {
      clean = clean.substring(dotIndex + 1);
    }
    // Remove Windows call decorations e.g. _strcpy@8
    clean = clean.replace(/^_+/, '');
    const atIndex = clean.indexOf('@');
    if (atIndex !== -1) {
      clean = clean.substring(0, atIndex);
    }
    return clean;
  }
}
