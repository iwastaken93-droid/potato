/**
 * Symbol Demangler for C++ Symbols (GCC/Clang Itanium ABI & MSVC)
 * Part of the Universal Reverse Engineering Tool
 */

export interface DemangledSymbol {
  original: string;
  demangled: string;
  language: 'c++' | 'unknown';
  kind: 'function' | 'variable' | 'unknown';
  namespaces: string[];
  className: string | null;
  name: string;
  parameters: string[];
  returnType: string | null;
  modifiers: string[];
  isMangled: boolean;
}

// Map for Itanium ABI primitive types
const ITANIUM_PRIMITIVES: Record<string, string> = {
  v: 'void',
  b: 'bool',
  c: 'char',
  a: 'signed char',
  h: 'unsigned char',
  s: 'short',
  t: 'unsigned short',
  i: 'int',
  j: 'unsigned int',
  l: 'long',
  m: 'unsigned long',
  x: 'long long',
  y: 'unsigned long long',
  f: 'float',
  d: 'double',
  z: '...',
};

// Map for MSVC primitive types
const MSVC_PRIMITIVES: Record<string, string> = {
  X: 'void',
  _N: 'bool',
  D: 'char',
  E: 'unsigned char',
  F: 'short',
  G: 'unsigned short',
  H: 'int',
  I: 'unsigned int',
  J: 'long',
  K: 'unsigned long',
  _J: '__int64',
  _K: 'unsigned __int64',
  M: 'float',
  N: 'double',
};

/**
 * Demangles a mangled C++ symbol.
 * Falls back to returning the original string if not mangled or if parsing fails.
 */
export function demangle(mangled: string): DemangledSymbol {
  const trimmed = mangled.trim();

  if (trimmed.startsWith('_Z')) {
    try {
      return parseItanium(trimmed);
    } catch (e) {
      // Fallback
    }
  } else if (trimmed.startsWith('?')) {
    try {
      return parseMsvc(trimmed);
    } catch (e) {
      // Fallback
    }
  }

  // Not a mangled symbol or parsing failed
  return {
    original: mangled,
    demangled: mangled,
    language: 'unknown',
    kind: 'unknown',
    namespaces: [],
    className: null,
    name: mangled,
    parameters: [],
    returnType: null,
    modifiers: [],
    isMangled: false,
  };
}

/**
 * Parse Itanium ABI mangled name
 */
function parseItanium(mangled: string): DemangledSymbol {
  // E.g., _ZN3foo3bar3bazEv -> foo::bar::baz()
  // _ZNK3std6vectorIiSaIiEE9push_backERKi -> std::vector<int, std::allocator<int>>::push_back(const int&) const
  let index = 2; // skip '_Z'
  const modifiers: string[] = [];

  // Check global modifiers or transaction info
  if (mangled[index] === 'G') {
    modifiers.push('global constructor');
    index++;
  }

  let isNested = false;
  if (mangled[index] === 'N') {
    isNested = true;
    index++;

    // Check nested const/volatile qualifiers
    if (mangled[index] === 'K') {
      modifiers.push('const');
      index++;
    }
    if (mangled[index] === 'V') {
      modifiers.push('volatile');
      index++;
    }
    if (mangled[index] === 'r') {
      modifiers.push('restrict');
      index++;
    }
  }

  const names: string[] = [];

  // Helper to parse a single source name component, handling potential templates
  function parseNameComponent(): string {
    let len = 0;
    while (index < mangled.length && /\d/.test(mangled[index])) {
      len = len * 10 + parseInt(mangled[index]);
      index++;
    }
    if (len === 0) {
      throw new Error('Invalid name length');
    }

    const end = index + len;
    if (end > mangled.length) {
      throw new Error('Name component length out of bounds');
    }

    let nameStr = mangled.slice(index, end);
    index = end;

    // Handle standard operators if any (e.g. cv, etc. in name components)
    if (nameStr.startsWith('op')) {
      nameStr = 'operator ' + nameStr.slice(2);
    }

    // Check if there are template parameters for this component (e.g. 'I...E')
    if (mangled[index] === 'I') {
      index++; // consume 'I'
      const templateArgs: string[] = [];
      while (index < mangled.length && mangled[index] !== 'E') {
        templateArgs.push(parseType());
      }
      if (mangled[index] === 'E') {
        index++; // consume 'E'
      }
      nameStr += `<${templateArgs.join(', ')}>`;
    }

    return nameStr;
  }

  // Parse type signatures (parameters or template args)
  function parseType(): string {
    if (index >= mangled.length) return '';

    const char = mangled[index];

    // Pointers, References, Const modifiers
    if (char === 'P') {
      index++;
      return parseType() + '*';
    }
    if (char === 'R') {
      index++;
      return parseType() + '&';
    }
    if (char === 'O') {
      index++;
      return parseType() + '&&';
    }
    if (char === 'K') {
      index++;
      return 'const ' + parseType();
    }
    if (char === 'V') {
      index++;
      return 'volatile ' + parseType();
    }

    // Arrays
    if (char === 'A') {
      index++;
      let size = '';
      while (index < mangled.length && /\d/.test(mangled[index])) {
        size += mangled[index];
        index++;
      }
      if (mangled[index] === '_') {
        index++;
      }
      return parseType() + `[${size}]`;
    }

    // Nested name as a type (starts with 'N' or length)
    if (char === 'N' || /\d/.test(char)) {
      const typeNames: string[] = [];
      let typeIsNested = false;
      if (char === 'N') {
        typeIsNested = true;
        index++;
      }
      while (index < mangled.length && /\d/.test(mangled[index])) {
        typeNames.push(parseNameComponent());
      }
      if (typeIsNested && mangled[index] === 'E') {
        index++;
      }
      return typeNames.join('::');
    }

    // Primitives
    if (ITANIUM_PRIMITIVES[char]) {
      index++;
      return ITANIUM_PRIMITIVES[char];
    }

    // Substitution (S_ or S[a-z] or S[0-9A-Z]_)
    if (char === 'S') {
      index++;
      const nextChar = mangled[index];
      let baseType = 'std';

      if (/[a-z]/.test(nextChar)) {
        index++; // consume standard substitution character
        if (nextChar === 'a') baseType = 'std::allocator';
        else if (nextChar === 'b') baseType = 'std::basic_string';
        else if (nextChar === 's') baseType = 'std::string';
        else if (nextChar === 'i') baseType = 'std::istream';
        else if (nextChar === 'o') baseType = 'std::ostream';
        else if (nextChar === 'd') baseType = 'std::iostream';
        else if (nextChar !== 't') baseType = `std::sub_${nextChar}`;
      } else {
        let subIndex = '';
        while (index < mangled.length && mangled[index] !== '_') {
          subIndex += mangled[index];
          index++;
        }
        if (mangled[index] === '_') {
          index++;
        }
        if (subIndex !== '') {
          baseType = `std::sub_${subIndex}`;
        }
      }

      // Check if substitution has its own template parameters
      if (mangled[index] === 'I') {
        index++; // consume 'I'
        const templateArgs: string[] = [];
        while (index < mangled.length && mangled[index] !== 'E') {
          templateArgs.push(parseType());
        }
        if (mangled[index] === 'E') {
          index++; // consume 'E'
        }
        baseType += `<${templateArgs.join(', ')}>`;
      }

      return baseType;
    }

    // Fallback if unrecognized type char
    index++;
    return char;
  }

  // Parse name components
  if (isNested) {
    while (index < mangled.length && mangled[index] !== 'E') {
      names.push(parseNameComponent());
    }
    if (mangled[index] === 'E') {
      index++; // consume 'E'
    }
  } else {
    // Single component
    names.push(parseNameComponent());
  }

  // Rest of the mangled string contains parameter types
  const params: string[] = [];
  while (index < mangled.length) {
    const t = parseType();
    if (t) {
      params.push(t);
    }
  }

  // Handle single 'void' parameter representation
  const cleanParams = params.length === 1 && params[0] === 'void' ? [] : params;

  // Heuristic rule for class name vs namespace
  const name = names[names.length - 1] || '';
  const remainingScopes = names.slice(0, -1);
  let className: string | null = null;
  let namespaces: string[] = [];

  if (remainingScopes.length > 1) {
    className = remainingScopes[remainingScopes.length - 1];
    namespaces = remainingScopes.slice(0, -1);
  } else if (remainingScopes.length === 1) {
    namespaces = [remainingScopes[0]];
  }

  let demangled = names.join('::');
  demangled += `(${cleanParams.join(', ')})`;
  if (modifiers.length > 0) {
    demangled +=
      ' ' +
      modifiers.filter((m) => m === 'const' || m === 'volatile').join(' ');
  }

  return {
    original: mangled,
    demangled: demangled.trim(),
    language: 'c++',
    kind: 'function',
    namespaces,
    className,
    name,
    parameters: cleanParams,
    returnType: null,
    modifiers,
    isMangled: true,
  };
}

/**
 * Parse MSVC mangled name
 */
function parseMsvc(mangled: string): DemangledSymbol {
  // E.g. ?func@Class@Namespace@@YAXXZ -> void Namespace::Class::func(void)
  // ?add@Math@@YAHHH@Z -> int Math::add(int, int)
  let index = 1; // skip '?'

  const endOfNames = mangled.indexOf('@@');
  if (endOfNames === -1) {
    throw new Error('Invalid MSVC mangled name');
  }

  const namesPart = mangled.slice(1, endOfNames);
  const names = namesPart.split('@');
  index = endOfNames + 2;

  // MSVC places function name first, followed by class name, then namespaces
  // E.g. ?name@Class@Namespace@@ -> names is ['name', 'Class', 'Namespace']
  // So reversed order gives Namespace::Class::name
  const reversedNames = [...names].reverse();
  const name = names[0] || '';
  const remaining = reversedNames.slice(0, -1);
  const className =
    remaining.length > 0 ? remaining[remaining.length - 1] : null;
  const namespaces = className ? remaining.slice(0, -1) : remaining;

  // Let's parse calling convention and return/params if present
  // In MSVC, following '@@' is the access/calling convention code, e.g., 'Y', 'Q', etc.
  let returnType: string | null = null;
  const params: string[] = [];
  const modifiers: string[] = [];

  function parseMsvcType(): string {
    if (index >= mangled.length) return '';

    // Check for pointer/reference prefix
    if (mangled[index] === 'P' || mangled[index] === 'A') {
      const isConst = mangled[index + 1] === 'B';
      index += 2; // consume prefix and cv-qualifier
      return parseMsvcType() + '*' + (isConst ? ' const' : '');
    }
    if (mangled[index] === 'Q') {
      index += 2;
      return parseMsvcType() + ' const*';
    }
    if (mangled[index] === 'R') {
      index += 2;
      return parseMsvcType() + '&';
    }

    // Extended primitives starting with '_'
    if (mangled[index] === '_') {
      const typeCode = mangled.slice(index, index + 2);
      if (MSVC_PRIMITIVES[typeCode]) {
        index += 2;
        return MSVC_PRIMITIVES[typeCode];
      }
    }

    const typeCode = mangled[index];
    if (MSVC_PRIMITIVES[typeCode]) {
      index++;
      return MSVC_PRIMITIVES[typeCode];
    }

    // User defined types (struct/class/union)
    if (typeCode === 'U' || typeCode === 'V' || typeCode === 'W') {
      index++; // consume type descriptor
      const uNames: string[] = [];
      while (index < mangled.length && mangled[index] !== '@') {
        let end = mangled.indexOf('@', index);
        if (end === -1) {
          uNames.push(mangled.slice(index));
          index = mangled.length;
          break;
        }
        uNames.push(mangled.slice(index, end));
        index = end + 1;
      }
      if (mangled[index] === '@') {
        index++;
      }
      return uNames.reverse().join('::');
    }

    index++;
    return typeCode;
  }

  if (index < mangled.length) {
    const callingConvCode = mangled[index];
    index++; // consume calling convention prefix (e.g. Y, Q, etc.)

    // If it's a member function, there might be CV qualifiers for 'this'
    if (callingConvCode === 'Q' || callingConvCode === 'R') {
      modifiers.push('const');
    }

    // Consume the actual calling convention code (A = __cdecl, I = __fastcall, etc.)
    if (index < mangled.length) {
      index++;
    }

    // Next is return type
    returnType = parseMsvcType();

    // Then parameters up to '@' or end of string
    while (
      index < mangled.length &&
      mangled[index] !== '@' &&
      mangled[index] !== 'Z'
    ) {
      const paramType = parseMsvcType();
      if (paramType) {
        params.push(paramType);
      }
    }
  }

  const cleanParams = params.length === 1 && params[0] === 'void' ? [] : params;

  let demangled = returnType ? `${returnType} ` : '';
  demangled += reversedNames.join('::');
  demangled += `(${cleanParams.join(', ')})`;
  if (modifiers.length > 0) {
    demangled += ' ' + modifiers.join(' ');
  }

  return {
    original: mangled,
    demangled: demangled.trim(),
    language: 'c++',
    kind: 'function',
    namespaces,
    className,
    name,
    parameters: cleanParams,
    returnType,
    modifiers,
    isMangled: true,
  };
}
