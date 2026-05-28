import { describe, it, expect } from 'vitest';
import { FridaGenerator } from '../src/analyzer/frida.js';

describe('Frida Script Generator Tests', () => {
  describe('Interceptor Hooking Templates', () => {
    it('should generate interceptor hook for a named export without libraryName', () => {
      const script = FridaGenerator.generateInterceptor({
        name: 'malloc_hook',
        target: 'malloc',
        args: [{ name: 'size', type: 'int' }],
        logArguments: true,
        logReturnValue: true,
        returnValueType: 'pointer'
      });

      expect(script).toContain('Module.findExportByName(null, "malloc")');
      expect(script).toContain('malloc_hook called');
      expect(script).toContain('arg[0] (size)');
      expect(script).toContain('args[0].toInt32()');
      expect(script).toContain('returned: " + retval');
    });

    it('should generate interceptor hook for a named export with libraryName', () => {
      const script = FridaGenerator.generateInterceptor({
        name: 'open_hook',
        target: 'open',
        libraryName: 'libc.so',
        args: [
          { name: 'path', type: 'string' },
          { name: 'flags', type: 'int' }
        ],
        logArguments: true,
        logReturnValue: true,
        returnValueType: 'int',
        logBacktrace: true
      });

      expect(script).toContain('Module.findExportByName("libc.so", "open")');
      expect(script).toContain('Memory.readUtf8String(args[0])');
      expect(script).toContain('Thread.backtrace');
      expect(script).toContain('returned int: " + retval.toInt32()');
    });

    it('should generate interceptor hook for an offset/address with libraryName', () => {
      const script = FridaGenerator.generateInterceptor({
        name: 'sub_1234',
        target: 0x1234,
        libraryName: 'libfoo.so',
        logReturnValue: false
      });

      expect(script).toContain('Module.findBaseAddress("libfoo.so")');
      expect(script).toContain('moduleBase.add(0x1234)');
    });

    it('should generate interceptor hook for absolute address without libraryName', () => {
      const script = FridaGenerator.generateInterceptor({
        name: 'abs_addr',
        target: 0x7fff0000,
        logReturnValue: false
      });

      expect(script).toContain('ptr("0x7fff0000")');
      expect(script).not.toContain('Module.findBaseAddress');
    });
  });

  describe('Memory Read Templates', () => {
    it('should generate utf8 memory read', () => {
      const script = FridaGenerator.generateMemoryRead({
        addressExpression: 'args[0]',
        type: 'utf8',
        length: 256,
        varName: 'myString'
      });

      expect(script).toContain('Memory.readUtf8String(args[0], 256)');
      expect(script).toContain('const myString =');
      expect(script).toContain('console.log("[*] Read myString: " + myString)');
    });

    it('should generate pointer memory read', () => {
      const script = FridaGenerator.generateMemoryRead({
        addressExpression: 'this.context.rsp',
        type: 'pointer',
        varName: 'stackPtr'
      });

      expect(script).toContain('Memory.readPointer(this.context.rsp)');
      expect(script).toContain('const stackPtr =');
    });

    it('should generate int32 and byteArray memory reads', () => {
      const script32 = FridaGenerator.generateMemoryRead({
        addressExpression: 'ptr("0x4000")',
        type: 'int32'
      });
      const scriptBytes = FridaGenerator.generateMemoryRead({
        addressExpression: 'ptr("0x5000")',
        type: 'byteArray',
        length: 64
      });

      expect(script32).toContain('Memory.readS32(ptr("0x4000"))');
      expect(scriptBytes).toContain('Memory.readByteArray(ptr("0x5000"), 64)');
      expect(scriptBytes).toContain('hexdump(memVal)');
    });
  });

  describe('Register Dump Templates', () => {
    it('should generate register dump for x64', () => {
      const script = FridaGenerator.generateRegisterDump({
        architecture: 'x64'
      });

      expect(script).toContain('rax');
      expect(script).toContain('rbx');
      expect(script).toContain('rip');
      expect(script).toContain('this.context.rax');
    });

    it('should generate register dump for arm64 with specific registers', () => {
      const script = FridaGenerator.generateRegisterDump({
        architecture: 'arm64',
        registers: ['x0', 'x1', 'sp']
      });

      expect(script).toContain('x0');
      expect(script).toContain('this.context.x0');
      expect(script).not.toContain('x8');
    });
  });

  describe('Java Hooking Templates', () => {
    it('should generate Java hook code', () => {
      const script = FridaGenerator.generateJavaHook({
        className: 'com.example.MainActivity',
        methodName: 'checkLicense',
        overloadTypes: ['java.lang.String', 'int'],
        logArguments: true,
        logReturnValue: true
      });

      expect(script).toContain('Java.perform(');
      expect(script).toContain('Java.use("com.example.MainActivity")');
      expect(script).toContain('.overload("java.lang.String", "int")');
      expect(script).toContain('args.forEach(');
    });
  });

  describe('Objective-C Hooking Templates', () => {
    it('should generate Objective-C hook code', () => {
      const script = FridaGenerator.generateObjcHook({
        className: 'AppDelegate',
        selectorName: '- application:didFinishLaunchingWithOptions:',
        logArguments: true,
        logReturnValue: true
      });

      expect(script).toContain('ObjC.available');
      expect(script).toContain('ObjC.classes[className][selectorName]');
      expect(script).toContain('Interceptor.attach(hook.implementation');
      expect(script).toContain('ObjC.selectorAsString(args[1])');
    });
  });
});
