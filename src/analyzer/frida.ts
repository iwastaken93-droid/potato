/**
 * Frida Dynamic Binary Instrumentation (DBI) Scripting Helper and Code Generator
 */

export interface InterceptorOptions {
  name: string;
  target: string | number; // symbol name or numeric offset/address
  libraryName?: string; // e.g. "libc.so" or process name
  args?: { name: string; type: 'int' | 'pointer' | 'string' | 'float' }[];
  logArguments?: boolean;
  logReturnValue?: boolean;
  returnValueType?: 'int' | 'pointer' | 'string' | 'float' | 'void';
  logBacktrace?: boolean;
  customOnEnter?: string;
  customOnLeave?: string;
}

export interface MemoryReadOptions {
  addressExpression: string; // e.g. "args[0]", "this.context.r0", "ptr('0x12345678')"
  type:
    | 'utf8'
    | 'utf16'
    | 'ansi'
    | 'pointer'
    | 'int32'
    | 'uint32'
    | 'int64'
    | 'uint64'
    | 'float'
    | 'double'
    | 'byteArray';
  length?: number; // used for byteArray, strings
  varName?: string; // dynamic variable name in JS output
}

export interface RegisterDumpOptions {
  architecture: 'x64' | 'x86' | 'arm64' | 'arm';
  registers?: string[]; // if empty/omitted, dumps all standard registers
}

export interface JavaHookOptions {
  className: string;
  methodName: string;
  overloadTypes?: string[]; // e.g. ["java.lang.String", "int"]
  logArguments?: boolean;
  logReturnValue?: boolean;
  customImplementation?: string;
}

export interface ObjcHookOptions {
  className: string;
  selectorName: string; // e.g. "- application:didFinishLaunchingWithOptions:"
  logArguments?: boolean;
  logReturnValue?: boolean;
  customImplementation?: string;
}

export class FridaGenerator {
  /**
   * Generates a template script for hooking functions/exports using Interceptor
   */
  public static generateInterceptor(opts: InterceptorOptions): string {
    const lines: string[] = [];
    const name = opts.name || 'hook';

    // Header/Resolution logic
    if (typeof opts.target === 'number') {
      const offsetHex = '0x' + opts.target.toString(16);
      if (opts.libraryName) {
        lines.push(
          `const moduleBase = Module.findBaseAddress("${opts.libraryName}");`
        );
        lines.push(`if (moduleBase) {`);
        lines.push(`  const targetAddress = moduleBase.add(${offsetHex});`);
        lines.push(`  Interceptor.attach(targetAddress, {`);
      } else {
        lines.push(`const targetAddress = ptr("${offsetHex}");`);
        lines.push(`Interceptor.attach(targetAddress, {`);
      }
    } else {
      // target is a string (symbol/export name)
      if (opts.libraryName) {
        lines.push(
          `const targetAddress = Module.findExportByName("${opts.libraryName}", "${opts.target}");`
        );
        lines.push(`if (targetAddress) {`);
        lines.push(`  Interceptor.attach(targetAddress, {`);
      } else {
        lines.push(
          `const targetAddress = Module.findExportByName(null, "${opts.target}");`
        );
        lines.push(`if (targetAddress) {`);
        lines.push(`  Interceptor.attach(targetAddress, {`);
      }
    }

    const indent =
      typeof opts.target === 'number' && !opts.libraryName ? '' : '  ';

    // onEnter
    lines.push(`${indent}  onEnter(args) {`);
    lines.push(`${indent}    console.log("[+] ${name} called");`);

    if (opts.logBacktrace) {
      lines.push(
        `${indent}    console.log("Backtrace:\\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n"));`
      );
    }

    if (opts.logArguments && opts.args && opts.args.length > 0) {
      opts.args.forEach((arg, idx) => {
        if (arg.type === 'string') {
          lines.push(`${indent}    try {`);
          lines.push(
            `${indent}      console.log("  arg[${idx}] (${arg.name}): " + Memory.readUtf8String(args[${idx}]));`
          );
          lines.push(`${indent}    } catch (e) {`);
          lines.push(
            `${indent}      console.log("  arg[${idx}] (${arg.name}): " + args[${idx}] + " (unable to read string)");`
          );
          lines.push(`${indent}    }`);
        } else if (arg.type === 'int') {
          lines.push(
            `${indent}    console.log("  arg[${idx}] (${arg.name}): " + args[${idx}].toInt32());`
          );
        } else if (arg.type === 'float') {
          lines.push(
            `${indent}    console.log("  arg[${idx}] (${arg.name}): " + args[${idx}]);`
          ); // standard pointer dump/float interpretation
        } else {
          lines.push(
            `${indent}    console.log("  arg[${idx}] (${arg.name}): " + args[${idx}]);`
          );
        }
      });
    }

    if (opts.customOnEnter) {
      const indentedCustom = opts.customOnEnter
        .split('\n')
        .map((l) => `${indent}    ${l}`)
        .join('\n');
      lines.push(indentedCustom);
    }
    lines.push(`${indent}  },`);

    // onLeave
    lines.push(`${indent}  onLeave(retval) {`);
    if (opts.logReturnValue) {
      const retType = opts.returnValueType || 'pointer';
      if (retType === 'void') {
        lines.push(`${indent}    console.log("[+] ${name} returned");`);
      } else if (retType === 'string') {
        lines.push(`${indent}    try {`);
        lines.push(
          `${indent}      console.log("[+] ${name} returned string: " + Memory.readUtf8String(retval));`
        );
        lines.push(`${indent}    } catch (e) {`);
        lines.push(
          `${indent}      console.log("[+] ${name} returned: " + retval + " (unable to read string)");`
        );
        lines.push(`${indent}    }`);
      } else if (retType === 'int') {
        lines.push(
          `${indent}    console.log("[+] ${name} returned int: " + retval.toInt32());`
        );
      } else {
        lines.push(
          `${indent}    console.log("[+] ${name} returned: " + retval);`
        );
      }
    } else {
      lines.push(`${indent}    // onLeave snippet`);
    }

    if (opts.customOnLeave) {
      const indentedCustom = opts.customOnLeave
        .split('\n')
        .map((l) => `${indent}    ${l}`)
        .join('\n');
      lines.push(indentedCustom);
    }
    lines.push(`${indent}  }`);
    lines.push(`${indent}});`);

    if (opts.libraryName || typeof opts.target !== 'number') {
      lines.push(`} else {`);
      lines.push(
        `  console.log("[-] Target function ${opts.target} not found");`
      );
      lines.push(`}`);
    }

    return lines.join('\n');
  }

  /**
   * Generates a template snippet for reading memory safe and formatted
   */
  public static generateMemoryRead(opts: MemoryReadOptions): string {
    const varName = opts.varName || 'memVal';
    const lines: string[] = [];
    lines.push(`try {`);

    switch (opts.type) {
      case 'utf8':
        if (opts.length !== undefined) {
          lines.push(
            `  const ${varName} = Memory.readUtf8String(${opts.addressExpression}, ${opts.length});`
          );
        } else {
          lines.push(
            `  const ${varName} = Memory.readUtf8String(${opts.addressExpression});`
          );
        }
        break;
      case 'utf16':
        if (opts.length !== undefined) {
          lines.push(
            `  const ${varName} = Memory.readUtf16String(${opts.addressExpression}, ${opts.length});`
          );
        } else {
          lines.push(
            `  const ${varName} = Memory.readUtf16String(${opts.addressExpression});`
          );
        }
        break;
      case 'ansi':
        if (opts.length !== undefined) {
          lines.push(
            `  const ${varName} = Memory.readAnsiString(${opts.addressExpression}, ${opts.length});`
          );
        } else {
          lines.push(
            `  const ${varName} = Memory.readAnsiString(${opts.addressExpression});`
          );
        }
        break;
      case 'pointer':
        lines.push(
          `  const ${varName} = Memory.readPointer(${opts.addressExpression});`
        );
        break;
      case 'int32':
        lines.push(
          `  const ${varName} = Memory.readS32(${opts.addressExpression});`
        );
        break;
      case 'uint32':
        lines.push(
          `  const ${varName} = Memory.readU32(${opts.addressExpression});`
        );
        break;
      case 'int64':
        lines.push(
          `  const ${varName} = Memory.readS64(${opts.addressExpression});`
        );
        break;
      case 'uint64':
        lines.push(
          `  const ${varName} = Memory.readU64(${opts.addressExpression});`
        );
        break;
      case 'float':
        lines.push(
          `  const ${varName} = Memory.readFloat(${opts.addressExpression});`
        );
        break;
      case 'double':
        lines.push(
          `  const ${varName} = Memory.readDouble(${opts.addressExpression});`
        );
        break;
      case 'byteArray': {
        const len = opts.length || 16;
        lines.push(
          `  const ${varName} = Memory.readByteArray(${opts.addressExpression}, ${len});`
        );
        break;
      }
      default:
        lines.push(
          `  const ${varName} = Memory.readPointer(${opts.addressExpression});`
        );
    }

    lines.push(
      `  console.log("[*] Read ${varName}: " + ${opts.type === 'byteArray' ? `hexdump(${varName})` : varName});`
    );
    lines.push(`} catch (e) {`);
    lines.push(
      `  console.log("[-] Failed to read memory at " + ${opts.addressExpression} + ": " + e);`
    );
    lines.push(`}`);

    return lines.join('\n');
  }

  /**
   * Generates a template snippet for dumping CPU registers
   */
  public static generateRegisterDump(opts: RegisterDumpOptions): string {
    const lines: string[] = [];
    lines.push(`console.log("=== Register Dump (${opts.architecture}) ===");`);

    let targetRegs: string[] = [];
    if (opts.registers && opts.registers.length > 0) {
      targetRegs = opts.registers;
    } else {
      switch (opts.architecture) {
        case 'x64':
          targetRegs = [
            'rax',
            'rbx',
            'rcx',
            'rdx',
            'rsi',
            'rdi',
            'rsp',
            'rbp',
            'rip',
            'r8',
            'r9',
            'r10',
            'r11',
          ];
          break;
        case 'x86':
          targetRegs = [
            'eax',
            'ebx',
            'ecx',
            'edx',
            'esi',
            'edi',
            'esp',
            'ebp',
            'eip',
          ];
          break;
        case 'arm64':
          targetRegs = [
            'x0',
            'x1',
            'x2',
            'x3',
            'x4',
            'x8',
            'x16',
            'x29',
            'x30',
            'sp',
            'pc',
          ];
          break;
        case 'arm':
          targetRegs = [
            'r0',
            'r1',
            'r2',
            'r3',
            'r4',
            'r7',
            'r11',
            'r12',
            'sp',
            'lr',
            'pc',
          ];
          break;
      }
    }

    targetRegs.forEach((reg) => {
      lines.push(`try {`);
      lines.push(
        `  console.log("  ${reg.padEnd(5)}: " + this.context.${reg});`
      );
      lines.push(`} catch (e) {`);
      lines.push(
        `  console.log("  ${reg.padEnd(5)}: unavailable (" + e + ")");`
      );
      lines.push(`}`);
    });

    return lines.join('\n');
  }

  /**
   * Generates a template script for Java hooking (Android)
   */
  public static generateJavaHook(opts: JavaHookOptions): string {
    const lines: string[] = [];
    lines.push(`Java.perform(() => {`);
    lines.push(`  try {`);
    lines.push(`    const targetClass = Java.use("${opts.className}");`);

    const overloadStr =
      opts.overloadTypes && opts.overloadTypes.length > 0
        ? opts.overloadTypes.map((t) => `"${t}"`).join(', ')
        : '';
    const overloadAccessor = overloadStr ? `.overload(${overloadStr})` : '';

    lines.push(
      `    targetClass["${opts.methodName}"]${overloadAccessor}.implementation = function (...args) {`
    );
    lines.push(
      `      console.log("[+] Java ${opts.className}.${opts.methodName} called");`
    );

    if (opts.logArguments) {
      lines.push(`      args.forEach((arg, idx) => {`);
      lines.push(`        console.log("  arg[" + idx + "]: " + arg);`);
      lines.push(`      });`);
    }

    if (opts.customImplementation) {
      const indented = opts.customImplementation
        .split('\n')
        .map((l) => `      ${l}`)
        .join('\n');
      lines.push(indented);
    } else {
      lines.push(
        `      const retval = this["${opts.methodName}"]${overloadAccessor}(...args);`
      );
      if (opts.logReturnValue) {
        lines.push(`      console.log("[+] Returned: " + retval);`);
      }
      lines.push(`      return retval;`);
    }

    lines.push(`    };`);
    lines.push(`  } catch (e) {`);
    lines.push(
      `    console.log("[-] Java hook error for ${opts.className}.${opts.methodName}: " + e);`
    );
    lines.push(`  }`);
    lines.push(`});`);

    return lines.join('\n');
  }

  /**
   * Generates a template script for Objective-C hooking (macOS/iOS)
   */
  public static generateObjcHook(opts: ObjcHookOptions): string {
    const lines: string[] = [];
    lines.push(`if (ObjC.available) {`);
    lines.push(`  try {`);
    lines.push(`    const className = "${opts.className}";`);
    lines.push(`    const selectorName = "${opts.selectorName}";`);
    lines.push(`    const hook = ObjC.classes[className][selectorName];`);
    lines.push(`    `);
    lines.push(`    Interceptor.attach(hook.implementation, {`);
    lines.push(`      onEnter(args) {`);
    lines.push(
      `        console.log("[+] ObjC " + className + " " + selectorName + " called");`
    );

    if (opts.logArguments) {
      lines.push(
        `        // ObjC methods have self at index 0 and _cmd selector at index 1`
      );
      lines.push(`        console.log("  self: " + args[0]);`);
      lines.push(
        `        console.log("  _cmd: " + ObjC.selectorAsString(args[1]));`
      );
      lines.push(`        // Additional arguments start at index 2`);
    }

    lines.push(`      },`);
    lines.push(`      onLeave(retval) {`);

    if (opts.logReturnValue) {
      lines.push(`        console.log("[+] ObjC returned: " + retval);`);
    }

    lines.push(`      }`);
    lines.push(`    });`);
    lines.push(`  } catch (e) {`);
    lines.push(`    console.log("[-] ObjC hook error: " + e);`);
    lines.push(`  }`);
    lines.push(`} else {`);
    lines.push(`  console.log("[-] Objective-C runtime is not available");`);
    lines.push(`}`);

    return lines.join('\n');
  }
}
