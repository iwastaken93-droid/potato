import { describe, it, expect } from 'vitest';
import { demangle } from '../src/analyzer/demangler.js';

describe('Symbol Demangler Unit Tests', () => {
  describe('Unmangled symbols', () => {
    it('should return the original string for non-mangled names', () => {
      const sym = 'main';
      const result = demangle(sym);
      expect(result.isMangled).toBe(false);
      expect(result.demangled).toBe('main');
      expect(result.name).toBe('main');
    });
  });

  describe('Itanium ABI Demangling (GCC/Clang)', () => {
    it('should demangle simple function with void parameters', () => {
      const result = demangle('_Z3foov');
      expect(result.isMangled).toBe(true);
      expect(result.language).toBe('c++');
      expect(result.name).toBe('foo');
      expect(result.demangled).toBe('foo()');
      expect(result.parameters).toEqual([]);
    });

    it('should demangle namespaced functions with arguments', () => {
      const result = demangle('_ZN3foo3bar3bazEib');
      expect(result.isMangled).toBe(true);
      expect(result.name).toBe('baz');
      expect(result.className).toBe('bar');
      expect(result.namespaces).toEqual(['foo']);
      expect(result.demangled).toBe('foo::bar::baz(int, bool)');
      expect(result.parameters).toEqual(['int', 'bool']);
    });

    it('should demangle functions with pointers and const references', () => {
      const result = demangle('_ZN3foo6helperEPiRKc');
      expect(result.isMangled).toBe(true);
      expect(result.name).toBe('helper');
      expect(result.className).toBe(null);
      expect(result.namespaces).toEqual(['foo']);
      expect(result.demangled).toBe('foo::helper(int*, const char&)');
      expect(result.parameters).toEqual(['int*', 'const char&']);
    });

    it('should handle const modifiers for member functions', () => {
      const result = demangle('_ZNK3foo3bar5printEv');
      expect(result.isMangled).toBe(true);
      expect(result.modifiers).toContain('const');
      expect(result.demangled).toBe('foo::bar::print() const');
    });

    it('should support templates and substitutions', () => {
      // E.g., std::vector<int> substitution
      const result = demangle('_ZN3std6vectorIiSaIiEE9push_backERKi');
      expect(result.isMangled).toBe(true);
      expect(result.name).toBe('push_back');
      expect(result.demangled).toBe('std::vector<int, std::allocator<int>>::push_back(const int&)');
    });
  });

  describe('MSVC ABI Demangling', () => {
    it('should demangle simple MSVC symbol', () => {
      const result = demangle('?add@Math@@YAHHH@Z');
      expect(result.isMangled).toBe(true);
      expect(result.language).toBe('c++');
      expect(result.name).toBe('add');
      expect(result.className).toBe('Math');
      expect(result.namespaces).toEqual([]);
      expect(result.demangled).toBe('int Math::add(int, int)');
      expect(result.parameters).toEqual(['int', 'int']);
      expect(result.returnType).toBe('int');
    });

    it('should demangle namespaced MSVC function with void return/parameters', () => {
      const result = demangle('?func@Class@Namespace@@YAXXZ');
      expect(result.isMangled).toBe(true);
      expect(result.name).toBe('func');
      expect(result.className).toBe('Class');
      expect(result.namespaces).toEqual(['Namespace']);
      expect(result.demangled).toBe('void Namespace::Class::func()');
      expect(result.parameters).toEqual([]);
      expect(result.returnType).toBe('void');
    });
  });
});
