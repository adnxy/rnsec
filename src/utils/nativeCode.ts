import type { NativeLanguage } from '../types/ruleTypes.js';

/**
 * Lightweight helpers for Java / Kotlin / Swift / Objective-C sources. There is no real parser here:
 * everything is a documented heuristic that is good enough to answer "is this a method named X and
 * what does its body do" without a toolchain. All masking helpers preserve offsets and newlines, so
 * indexes into masked code are valid indexes into the original, and line numbers stay accurate.
 */

export type { NativeLanguage };

/** Language for a native source path, or undefined for other files. */
export function languageForPath(filePath: string): NativeLanguage | undefined {
  if (filePath.endsWith('.java')) return 'java';
  if (filePath.endsWith('.kt')) return 'kotlin';
  if (filePath.endsWith('.swift')) return 'swift';
  if (/\.mm?$/.test(filePath)) return 'objc';
  return undefined;
}

/**
 * Walk the code once, tracking comments and string literals, and blank what was asked for.
 * Handles: `//`, block comments (nested for Swift and Kotlin), Java/Kotlin/Swift triple-quoted strings,
 * Swift raw strings (`#"..."#`), char literals (Java/Kotlin/ObjC), Swift `\( )` and Kotlin `${ }`
 * interpolation (which may itself contain quotes). Unterminated single-line strings end at the newline.
 */
function mask(code: string, language: NativeLanguage, comments: boolean, strings: boolean): string {
  const out = code.split('');
  const n = code.length;
  const nestedComments = language === 'swift' || language === 'kotlin';

  const blank = (from: number, to: number): void => {
    for (let k = from; k < to && k < n; k++) {
      if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' ';
    }
  };

  /** Scan code until the unmatched `closer` (index of it) or the end of the input. */
  const scanCode = (start: number, closer?: string): number => {
    const opener = closer === ')' ? '(' : '{';
    let depth = 0;
    let i = start;
    while (i < n) {
      const c = code[i];
      const next = code[i + 1];
      if (c === '/' && next === '/') {
        let end = code.indexOf('\n', i);
        if (end === -1) end = n;
        if (comments) blank(i, end);
        i = end;
      } else if (c === '/' && next === '*') {
        let level = 1;
        let j = i + 2;
        while (j < n && level > 0) {
          if (code[j] === '*' && code[j + 1] === '/') {
            level--;
            j += 2;
          } else if (nestedComments && code[j] === '/' && code[j + 1] === '*') {
            level++;
            j += 2;
          } else {
            j++;
          }
        }
        if (comments) blank(i, j);
        i = j;
      } else if (c === '"' || (c === '#' && language === 'swift' && /^#+"/.test(code.slice(i, i + 8)))) {
        i = scanString(i);
      } else if (c === "'" && language !== 'swift') {
        // char literal; bounded so a stray apostrophe cannot swallow the file
        let j = i + 1;
        while (j < n && code[j] !== "'" && code[j] !== '\n' && j - i < 12) j += code[j] === '\\' ? 2 : 1;
        if (code[j] === "'") {
          if (strings) blank(i + 1, j);
          i = j + 1;
        } else {
          i++;
        }
      } else {
        if (closer) {
          if (c === opener) depth++;
          else if (c === closer) {
            if (depth === 0) return i;
            depth--;
          }
        }
        i++;
      }
    }
    return n;
  };

  /** `start` is the opening delimiter (`"`, `"""` or `#"`). Returns the index after the closing one. */
  const scanString = (start: number): number => {
    let hashes = 0;
    let i = start;
    while (code[i] === '#') {
      hashes++;
      i++;
    }
    const triple = code.startsWith('"""', i);
    const quoteLen = triple ? 3 : 1;
    const closing = '"'.repeat(quoteLen) + '#'.repeat(hashes);
    const contentStart = i + quoteLen;
    i = contentStart;
    // Kotlin raw strings have no escapes
    const escapes = !(language === 'kotlin' && triple);
    while (i < n) {
      const c = code[i];
      if (code.startsWith(closing, i)) {
        if (strings) blank(contentStart, i);
        return i + closing.length;
      }
      if (c === '\n' && !triple) break;
      if (escapes && c === '\\' && (hashes === 0 || code.startsWith('#'.repeat(hashes), i + 1))) {
        const after = i + 1 + hashes;
        if (language === 'swift' && code[after] === '(') {
          i = scanCode(after + 1, ')') + 1;
          continue;
        }
        i = after + 1;
        continue;
      }
      if (language === 'kotlin' && c === '$' && code[i + 1] === '{') {
        i = scanCode(i + 2, '}') + 1;
        continue;
      }
      i++;
    }
    if (strings) blank(contentStart, Math.min(i, n));
    return i;
  };

  scanCode(0);
  return out.join('');
}

/** Replace comment text with spaces (newlines and offsets kept). `//` inside string literals is not a comment. */
export function maskComments(code: string, language: NativeLanguage): string {
  return mask(code, language, true, false);
}

/** Replace the contents of string / char literals with spaces, keeping the quotes. Comments are left as they are. */
export function maskStrings(code: string, language: NativeLanguage): string {
  return mask(code, language, false, true);
}

/** Comments and string contents masked: safe to brace-match and to search with structural regexes. */
export function maskCode(code: string, language: NativeLanguage): string {
  return mask(code, language, true, true);
}

/**
 * Index of the `}` matching the `{` at `openIndex`, or -1. Expects masked code
 * (see `maskCode`), otherwise braces inside comments or strings are counted.
 */
export function matchingBrace(code: string, openIndex: number): number {
  return matching(code, openIndex, '{', '}');
}

function matching(code: string, openIndex: number, open: string, close: string): number {
  if (code[openIndex] !== open) return -1;
  let depth = 0;
  for (let i = openIndex; i < code.length; i++) {
    if (code[i] === open) depth++;
    else if (code[i] === close && --depth === 0) return i;
  }
  return -1;
}

export interface NativeFunction {
  /**
   * Java/Kotlin/Swift: the bare method name (`urlSession` for `urlSession(_:didReceive:completionHandler:)`).
   * Objective-C: the full selector (`URLSession:didReceiveChallenge:completionHandler:`, `viewDidLoad`);
   * `nameRegex` is tested against the selector and against its first keyword.
   */
  name: string;
  /** Offset of the declaration start (annotations and modifiers on the same statement included) */
  start: number;
  /** Offset just after the opening `{` (Kotlin expression body: just after `=`) */
  bodyStart: number;
  /** Offset of the closing `}` (Kotlin expression body: end of the expression); `body === code.slice(bodyStart, bodyEnd)` */
  bodyEnd: number;
  /** Text between `bodyStart` and `bodyEnd`, taken from the original code (comments included) */
  body: string;
  /** Declaration text from `start` up to the body (parameters, `throws`, return type, `override`...) */
  signature: string;
}

const NOT_A_METHOD = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'synchronized', 'return', 'new', 'else', 'try', 'throw',
  'guard', 'when', 'do', 'case', 'super', 'this', 'init',
]);

/** Make a non-global copy so `.test` is stateless. */
const plain = (re: RegExp): RegExp => new RegExp(re.source, re.flags.replace(/[gy]/g, ''));

/** Offset of the first non-blank character on the line of `index`, moved up over preceding annotation lines (`@Override`). */
function declarationStart(masked: string, index: number): number {
  const lineBegin = (at: number): number => masked.lastIndexOf('\n', at - 1) + 1;
  let begin = lineBegin(index);
  while (begin > 0) {
    const previousBegin = lineBegin(begin - 1);
    const previous = masked.slice(previousBegin, begin).trim();
    if (!/^@[\w.]+(\([^)]*\))?$/.test(previous)) break;
    begin = previousBegin;
  }
  while (begin < index && /[ \t]/.test(masked[begin])) begin++;
  return begin;
}

/** End offset (exclusive) of a Kotlin expression body starting at `from`. */
function expressionEnd(masked: string, from: number): number {
  let depth = 0;
  for (let i = from; i < masked.length; i++) {
    const c = masked[i];
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) {
      if (depth === 0) return i;
      depth--;
    } else if (depth === 0 && c === ';') return i;
    else if (depth === 0 && c === '\n') {
      const before = masked.slice(from, i).trimEnd();
      const after = masked.slice(i).trimStart();
      const continues = /[=+\-*/%&|,.:?<]$/.test(before) || /^(\.|\?\.|\?:|&&|\|\||\+|\*|\/)/.test(after);
      if (before.trim() === '' || continues) continue;
      return i;
    }
  }
  return masked.length;
}

/**
 * Find method definitions whose name satisfies `nameRegex` (matched against the whole identifier,
 * so anchored patterns work). Heuristics, per language:
 * - Java: `[annotations/modifiers] Type name(params) [throws X] {`. The token before the name must look like
 *   a type or modifier, which excludes calls (`foo(x)`), `new Foo() {` and control keywords. Abstract
 *   declarations ending in `;` have no body and are skipped.
 * - Kotlin: `[modifiers] fun [<T>] [Receiver.]name(params)[: Type] {` and expression bodies `= expr`
 *   (the expression ends at a depth-0 newline unless the line visibly continues).
 * - Swift: `func name[<T>](params) [async] [throws] [-> Type] [where ...] {`; protocol requirements without a body are skipped.
 * - Objective-C: `- (Type)keyword:(T)arg keyword2:(U)arg2 {` and `+` class methods at the start of a line;
 *   `@interface` declarations ending in `;` are skipped.
 * Nested and anonymous-class methods are found too. Parsing happens on comment- and string-masked
 * code, so offsets refer to the original text.
 */
export function findFunctions(code: string, language: NativeLanguage, nameRegex: RegExp): NativeFunction[] {
  const masked = maskCode(code, language);
  const matches = plain(nameRegex);
  const found: NativeFunction[] = [];

  const push = (name: string, start: number, openIndex: number, closeIndex: number, expression: boolean): void => {
    const bodyStart = expression ? openIndex : openIndex + 1;
    found.push({
      name,
      start,
      bodyStart,
      bodyEnd: closeIndex,
      body: code.slice(bodyStart, closeIndex),
      signature: code.slice(start, openIndex).trim(),
    });
  };

  if (language === 'objc') {
    findObjc(masked, matches, push);
    return found;
  }

  if (language === 'java') {
    const call = /([A-Za-z_$][\w$]*)\s*\(/g;
    for (let m = call.exec(masked); m; m = call.exec(masked)) {
      const name = m[1];
      if (NOT_A_METHOD.has(name) || !matches.test(name)) continue;
      const nameStart = m.index;
      const before = masked.slice(0, nameStart).trimEnd();
      const prevWord = /([\w$]+)$/.exec(before)?.[1];
      if (!/[\w$>\]]$/.test(before) || (prevWord && NOT_A_METHOD.has(prevWord))) continue;
      const open = m.index + m[0].length - 1;
      const close = matching(masked, open, '(', ')');
      if (close === -1) continue;
      const tail = /^\s*(?:throws\s+[\w$.,\s<>]+?)?\s*\{/.exec(masked.slice(close + 1));
      if (!tail) continue;
      const braceIndex = close + 1 + tail[0].length - 1;
      const braceClose = matchingBrace(masked, braceIndex);
      if (braceClose === -1) continue;
      push(name, declarationStart(masked, nameStart), braceIndex, braceClose, false);
    }
    return found;
  }

  const keyword = language === 'kotlin' ? 'fun' : 'func';
  const head =
    language === 'kotlin'
      ? /^\s*(?:<[^>(]*>\s*)?(?:[\w.?<>, ]*?\.)?(`[^`]+`|[A-Za-z_$][\w$]*)\s*\(/
      : /^\s*(`[^`]+`|[A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(/;
  const kw = new RegExp(`(?<![\\w$.])${keyword}(?![\\w$])`, 'g');
  for (let m = kw.exec(masked); m; m = kw.exec(masked)) {
    const afterKw = m.index + keyword.length;
    const h = head.exec(masked.slice(afterKw));
    if (!h) continue;
    const name = h[1].replace(/`/g, '');
    if (!matches.test(name)) continue;
    const open = afterKw + h[0].length - 1;
    const close = matching(masked, open, '(', ')');
    if (close === -1) continue;
    const bodyOpen = findBodyOpen(masked, close + 1, language);
    if (!bodyOpen) continue;
    const start = declarationStart(masked, m.index);
    if (bodyOpen.kind === 'expression') {
      const end = expressionEnd(masked, bodyOpen.index + 1);
      push(name, start, bodyOpen.index + 1, end, true);
    } else {
      const braceClose = matchingBrace(masked, bodyOpen.index);
      if (braceClose === -1) continue;
      push(name, start, bodyOpen.index, braceClose, false);
    }
  }
  return found;
}

/** After the parameter list: skip return type / throws / where, return the body opener (`{` or Kotlin `=`). */
function findBodyOpen(
  masked: string,
  from: number,
  language: 'kotlin' | 'swift'
): { index: number; kind: 'block' | 'expression' } | undefined {
  let depth = 0;
  for (let i = from; i < masked.length; i++) {
    const c = masked[i];
    if (c === '-' && masked[i + 1] === '>') {
      i++;
      continue;
    }
    if (depth === 0 && c === '{') return { index: i, kind: 'block' };
    if (depth === 0 && c === '=' && language === 'kotlin' && masked[i + 1] !== '=') return { index: i, kind: 'expression' };
    if (c === '(' || c === '[' || c === '<') depth++;
    else if (c === ')' || c === ']' || c === '>') depth = Math.max(0, depth - 1);
    else if (depth === 0 && c === ';') return undefined;
    else if (depth === 0 && c === '\n') {
      // the body must start on this or the next code line; otherwise this is an abstract / protocol declaration
      const rest = masked.slice(i).trimStart();
      if (rest[0] === '{') continue;
      if (language === 'swift' && /^(->|where\b|throws\b|rethrows\b|async\b)/.test(rest)) continue;
      if (language === 'kotlin' && /^[:=]/.test(rest) && !rest.startsWith('==')) continue;
      return undefined;
    }
  }
  return undefined;
}

function findObjc(
  masked: string,
  matches: RegExp,
  push: (name: string, start: number, open: number, close: number, expression: boolean) => void
): void {
  const lineStart = /^[ \t]*([-+])[ \t]*\(/gm;
  for (let m = lineStart.exec(masked); m; m = lineStart.exec(masked)) {
    const start = m.index + m[0].indexOf(m[1]);
    const retOpen = m.index + m[0].length - 1;
    const retClose = matching(masked, retOpen, '(', ')');
    if (retClose === -1) continue;
    // selector: `keyword:(Type)arg keyword:(Type)arg` or a bare keyword, up to `{` or `;`
    let i = retClose + 1;
    const keywords: string[] = [];
    let ok = true;
    while (i < masked.length) {
      const rest = masked.slice(i);
      const part = /^\s*([A-Za-z_]\w*)\s*(:)?/.exec(rest);
      if (!part) break;
      keywords.push(part[2] ? `${part[1]}:` : part[1]);
      i += part[0].length;
      if (!part[2]) break;
      const arg = /^\s*\(/.exec(masked.slice(i));
      if (!arg) {
        ok = false;
        break;
      }
      const argOpen = i + arg[0].length - 1;
      const argClose = matching(masked, argOpen, '(', ')');
      if (argClose === -1) {
        ok = false;
        break;
      }
      const argName = /^\s*([A-Za-z_]\w*)/.exec(masked.slice(argClose + 1));
      if (!argName) {
        ok = false;
        break;
      }
      i = argClose + 1 + argName[0].length;
      // variadic `, ...` and attribute macros between parts are not supported
    }
    if (!ok || keywords.length === 0) continue;
    const braceIndex = /^\s*\{/.exec(masked.slice(i))?.[0].length;
    if (braceIndex === undefined) continue; // declaration in an @interface (`;`)
    const open = i + braceIndex - 1;
    const close = matchingBrace(masked, open);
    if (close === -1) continue;
    const selector = keywords.join('');
    if (!matches.test(selector) && !matches.test(keywords[0].replace(/:$/, ''))) continue;
    push(selector, start, open, close, false);
  }
}

/**
 * True when a function body does nothing: only whitespace, comments, `return` / `return;` or Kotlin `Unit`
 * (e.g. an empty `checkServerTrusted` override).
 */
export function isTrivialBody(body: string): boolean {
  // comments are C-style in every supported language; Swift/Kotlin nesting does not matter for this check
  const stripped = maskComments(body, 'swift').trim();
  return /^(?:;|\s|return(?![\w$])|Unit(?![\w$]))*$/.test(stripped);
}
