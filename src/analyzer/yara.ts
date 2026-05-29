/**
 * YARA-like rule-based signature engine.
 * Supports parsing and scanning binary buffers using YARA-like syntax.
 */

import { parseHexPattern } from './search.js';

export interface YaraStringPattern {
  id: string; // e.g., "$a"
  type: 'text' | 'hex';
  value: string;
  modifiers?: {
    nocase?: boolean;
    ascii?: boolean;
    wide?: boolean;
  };
}

export interface YaraRule {
  name: string;
  meta?: Record<string, string | number | boolean>;
  strings: YaraStringPattern[];
  condition: string;
}

export interface YaraMatch {
  stringId: string;
  offset: number;
  matchedValue: string;
}

export interface YaraScanResult {
  ruleName: string;
  matched: boolean;
  matches: YaraMatch[];
}

/**
 * Unescapes special characters and hex escapes in double-quoted strings.
 */
export function unescapeString(val: string): string {
  return val.replace(/\\(x[0-9a-fA-F]{2}|[nrt"\\])/g, (match, p1) => {
    if (p1.startsWith('x')) {
      return String.fromCharCode(parseInt(p1.substring(1), 16));
    }
    switch (p1) {
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case '"':
        return '"';
      case '\\':
        return '\\';
      default:
        return match;
    }
  });
}

/**
 * Parses YARA-like rule source code into structured YaraRule objects.
 */
export function parseYaraRules(source: string): YaraRule[] {
  const rules: YaraRule[] = [];
  // Strip single-line and multi-line comments
  const cleanSource = source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*/g, '');

  const ruleRegex = /\brule\s+(\w+)\s*\{/g;
  let match;
  while ((match = ruleRegex.exec(cleanSource)) !== null) {
    const ruleName = match[1];
    const startIdx = match.index + match[0].length - 1; // '{' position

    let braceCount = 0;
    let endIdx = -1;
    for (let i = startIdx; i < cleanSource.length; i++) {
      if (cleanSource[i] === '{') {
        braceCount++;
      } else if (cleanSource[i] === '}') {
        braceCount--;
        if (braceCount === 0) {
          endIdx = i;
          break;
        }
      }
    }

    if (endIdx === -1) {
      throw new Error(`Unmatched opening brace for rule ${ruleName}`);
    }

    const ruleBody = cleanSource.substring(startIdx + 1, endIdx);
    rules.push(parseRuleBody(ruleName, ruleBody));
  }

  return rules;
}

function parseRuleBody(name: string, body: string): YaraRule {
  const meta: Record<string, string | number | boolean> = {};
  const strings: YaraStringPattern[] = [];
  let condition = '';

  const metaIndex = body.indexOf('meta:');
  const stringsIndex = body.indexOf('strings:');
  const conditionIndex = body.indexOf('condition:');

  const sections = [
    { name: 'meta', index: metaIndex },
    { name: 'strings', index: stringsIndex },
    { name: 'condition', index: conditionIndex },
  ]
    .filter((x) => x.index !== -1)
    .sort((a, b) => a.index - b.index);

  for (let i = 0; i < sections.length; i++) {
    const start = sections[i].index + sections[i].name.length + 1;
    const end = i + 1 < sections.length ? sections[i + 1].index : body.length;
    const content = body.substring(start, end).trim();

    if (sections[i].name === 'meta') {
      const metaLines = content.split('\n');
      for (const line of metaLines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx !== -1) {
          const key = trimmed.substring(0, eqIdx).trim();
          let valStr = trimmed.substring(eqIdx + 1).trim();
          if (valStr.endsWith(';')) {
            valStr = valStr.substring(0, valStr.length - 1).trim();
          }
          if (valStr.startsWith('"') && valStr.endsWith('"')) {
            meta[key] = valStr.substring(1, valStr.length - 1);
          } else if (valStr === 'true') {
            meta[key] = true;
          } else if (valStr === 'false') {
            meta[key] = false;
          } else if (!isNaN(Number(valStr))) {
            meta[key] = Number(valStr);
          } else {
            meta[key] = valStr;
          }
        }
      }
    } else if (sections[i].name === 'strings') {
      const stringDefRegex =
        /\$([a-zA-Z0-9_]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|\{([^}]+)\})([a-zA-Z0-9_\s]*)/g;
      let strMatch;
      while ((strMatch = stringDefRegex.exec(content)) !== null) {
        const id = '$' + strMatch[1];
        const textVal = strMatch[2];
        const hexVal = strMatch[3];
        const modStr = strMatch[4] || '';

        const modifiers = {
          nocase: modStr.includes('nocase'),
          ascii: modStr.includes('ascii'),
          wide: modStr.includes('wide'),
        };

        if (!modifiers.ascii && !modifiers.wide) {
          modifiers.ascii = true;
        }

        if (textVal !== undefined) {
          strings.push({
            id,
            type: 'text',
            value: unescapeString(textVal),
            modifiers,
          });
        } else if (hexVal !== undefined) {
          strings.push({
            id,
            type: 'hex',
            value: hexVal.trim(),
            modifiers,
          });
        }
      }
    } else if (sections[i].name === 'condition') {
      condition = content;
    }
  }

  return {
    name,
    meta: Object.keys(meta).length > 0 ? meta : undefined,
    strings,
    condition,
  };
}

/**
 * Searches for a string pattern in a binary buffer.
 */
export function matchPattern(
  buffer: Uint8Array,
  pattern: YaraStringPattern
): YaraMatch[] {
  const matches: YaraMatch[] = [];

  if (pattern.type === 'hex') {
    const parsed = parseHexPattern(pattern.value);
    if (parsed.length === 0 || parsed.length > buffer.length) {
      return [];
    }
    const limit = buffer.length - parsed.length;
    for (let i = 0; i <= limit; i++) {
      let matched = true;
      for (let j = 0; j < parsed.length; j++) {
        const pByte = parsed[j];
        if (pByte !== null && buffer[i + j] !== pByte) {
          matched = false;
          break;
        }
      }
      if (matched) {
        const matchedBytes = buffer.subarray(i, i + parsed.length);
        const hexVal = Array.from(matchedBytes)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(' ');
        matches.push({
          stringId: pattern.id,
          offset: i,
          matchedValue: hexVal,
        });
      }
    }
  } else {
    const nocase = !!pattern.modifiers?.nocase;
    const ascii = !!pattern.modifiers?.ascii;
    const wide = !!pattern.modifiers?.wide;

    const searchInBuffer = (needleBytes: Uint8Array, isWide: boolean) => {
      if (needleBytes.length === 0 || needleBytes.length > buffer.length) {
        return;
      }
      const limit = buffer.length - needleBytes.length;
      for (let i = 0; i <= limit; i++) {
        let matched = true;
        for (let j = 0; j < needleBytes.length; j++) {
          const b = buffer[i + j];
          const n = needleBytes[j];
          if (nocase) {
            const bLower = b >= 65 && b <= 90 ? b + 32 : b;
            const nLower = n >= 65 && n <= 90 ? n + 32 : n;
            if (bLower !== nLower) {
              matched = false;
              break;
            }
          } else {
            if (b !== n) {
              matched = false;
              break;
            }
          }
        }
        if (matched) {
          const matchedBytes = buffer.subarray(i, i + needleBytes.length);
          const decoder = new TextDecoder(isWide ? 'utf-16le' : 'utf-8');
          let matchedValue = '';
          try {
            matchedValue = decoder.decode(matchedBytes);
          } catch {
            matchedValue = String.fromCharCode(...matchedBytes);
          }
          matches.push({
            stringId: pattern.id,
            offset: i,
            matchedValue,
          });
        }
      }
    };

    if (ascii) {
      const needleBytes = new TextEncoder().encode(pattern.value);
      searchInBuffer(needleBytes, false);
    }
    if (wide) {
      const needleBytes = new Uint8Array(pattern.value.length * 2);
      for (let j = 0; j < pattern.value.length; j++) {
        const code = pattern.value.charCodeAt(j);
        needleBytes[j * 2] = code & 0xff;
        needleBytes[j * 2 + 1] = (code >> 8) & 0xff;
      }
      searchInBuffer(needleBytes, true);
    }
  }

  return matches;
}

/**
 * Safely evaluates a boolean condition string using matched variable values.
 */
export function evaluateCondition(
  condition: string,
  variableValues: Record<string, boolean>
): boolean {
  let cond = condition.trim();

  cond = cond.replace(
    /\bany of them\b/gi,
    variableValues['any of them'] ? 'true' : 'false'
  );
  cond = cond.replace(
    /\ball of them\b/gi,
    variableValues['all of them'] ? 'true' : 'false'
  );

  const sortedKeys = Object.keys(variableValues)
    .filter((k) => k.startsWith('$'))
    .sort((a, b) => b.length - a.length);

  for (const key of sortedKeys) {
    const escapedKey = key.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
    const regex = new RegExp(escapedKey + '\\b', 'g');
    cond = cond.replace(regex, variableValues[key] ? 'true' : 'false');
  }

  cond = cond
    .replace(/\band\b/gi, '&&')
    .replace(/\bor\b/gi, '||')
    .replace(/\bnot\b/gi, '!');

  const tokenRegex = /\(|\)|&&|\|\||!|true|false/g;
  const tokens = cond.match(tokenRegex) || [];
  if (tokens.length === 0) {
    return false;
  }

  let index = 0;

  function parseExpression(): boolean {
    return parseOr();
  }

  function parseOr(): boolean {
    let val = parseAnd();
    while (index < tokens.length && tokens[index] === '||') {
      index++;
      const right = parseAnd();
      val = val || right;
    }
    return val;
  }

  function parseAnd(): boolean {
    let val = parsePrimary();
    while (index < tokens.length && tokens[index] === '&&') {
      index++;
      const right = parsePrimary();
      val = val && right;
    }
    return val;
  }

  function parsePrimary(): boolean {
    if (index >= tokens.length) {
      return false;
    }
    const token = tokens[index];
    if (token === '!') {
      index++;
      return !parsePrimary();
    }
    if (token === '(') {
      index++;
      const val = parseExpression();
      if (index < tokens.length && tokens[index] === ')') {
        index++;
      }
      return val;
    }
    if (token === 'true') {
      index++;
      return true;
    }
    if (token === 'false') {
      index++;
      return false;
    }
    index++;
    return false;
  }

  return parseExpression();
}

/**
 * Signature engine class to compile and scan rules against target binaries.
 */
export class YaraEngine {
  private rules: YaraRule[] = [];

  /**
   * Compiles rules from a YARA-like string.
   */
  public compile(source: string): void {
    const parsed = parseYaraRules(source);
    this.rules.push(...parsed);
  }

  /**
   * Registers a rule programmatically.
   */
  public addRule(rule: YaraRule): void {
    this.rules.push(rule);
  }

  /**
   * Clears compiled rules.
   */
  public clear(): void {
    this.rules = [];
  }

  /**
   * Gets the list of current compiled rules.
   */
  public getRules(): YaraRule[] {
    return this.rules;
  }

  /**
   * Scans a buffer against the compiled rules.
   */
  public scan(buffer: Uint8Array): YaraScanResult[] {
    const results: YaraScanResult[] = [];

    for (const rule of this.rules) {
      const matches: YaraMatch[] = [];
      const variableValues: Record<string, boolean> = {};

      for (const pattern of rule.strings) {
        const patternMatches = matchPattern(buffer, pattern);
        if (patternMatches.length > 0) {
          matches.push(...patternMatches);
          variableValues[pattern.id] = true;
        } else {
          variableValues[pattern.id] = false;
        }
      }

      // Check "any of them" / "all of them"
      const values = rule.strings.map((p) => variableValues[p.id]);
      variableValues['any of them'] = values.some((v) => v);
      variableValues['all of them'] =
        rule.strings.length > 0 && values.every((v) => v);

      const matched = evaluateCondition(rule.condition, variableValues);

      results.push({
        ruleName: rule.name,
        matched,
        matches: matched ? matches : [],
      });
    }

    return results;
  }
}
