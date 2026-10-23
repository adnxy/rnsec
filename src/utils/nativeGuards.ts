import type { NativeLanguage } from '../types/ruleTypes.js';
import type { LineRange } from './devGuards.js';
import { maskCode, maskComments, matchingBrace } from './nativeCode.js';

/**
 * Development-only line ranges for native files, the counterpart of `collectDevOnlyRanges` (which needs a JS AST):
 * - Swift / Objective-C: `#if DEBUG` / `#ifdef DEBUG` branches, up to the matching `#else` / `#elseif` / `#elif` / `#endif`.
 *   `#if !DEBUG` and `#ifndef DEBUG` make their else branch dev-only instead. `A && DEBUG` is dev-only,
 *   `A || DEBUG` is not. Nesting is handled; the else branch of `#if DEBUG` is NOT dev-only.
 * - Java / Kotlin: `if (BuildConfig.DEBUG) { ... }` and `if (BuildConfig.DEBUG && ...) { ... }` blocks (also a
 *   brace-less single statement). The else branch is not dev-only (but it is for `if (!BuildConfig.DEBUG)`).
 *   `else if` chains are evaluated per condition only.
 * Ranges are 1-based inclusive lines of the branch body.
 */

interface Guard {
  devWhenTrue: boolean;
  devWhenFalse: boolean;
}
const NONE: Guard = { devWhenTrue: false, devWhenFalse: false };

/** Split `text` on a top-level (depth 0) operator. */
function splitTop(text: string, op: '&&' | '||'): string[] {
  const parts: string[] = [];
  let depth = 0;
  let last = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth === 0 && text.startsWith(op, i)) {
      parts.push(text.slice(last, i));
      last = i + 2;
      i++;
    }
  }
  parts.push(text.slice(last));
  return parts;
}

function isWrapped(text: string): boolean {
  if (!text.startsWith('(') || !text.endsWith(')')) return false;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0 && i < text.length - 1) return false;
  }
  return true;
}

function evaluate(expression: string, isDevAtom: (atom: string) => boolean): Guard {
  const text = expression.trim();
  const ors = splitTop(text, '||');
  if (ors.length > 1) {
    const guards = ors.map(p => evaluate(p, isDevAtom));
    return { devWhenTrue: guards.every(g => g.devWhenTrue), devWhenFalse: guards.some(g => g.devWhenFalse) };
  }
  const ands = splitTop(text, '&&');
  if (ands.length > 1) {
    const guards = ands.map(p => evaluate(p, isDevAtom));
    return { devWhenTrue: guards.some(g => g.devWhenTrue), devWhenFalse: guards.every(g => g.devWhenFalse) };
  }
  if (text.startsWith('!') && text[1] !== '=') {
    const inner = evaluate(text.slice(1), isDevAtom);
    return { devWhenTrue: inner.devWhenFalse, devWhenFalse: inner.devWhenTrue };
  }
  if (isWrapped(text)) return evaluate(text.slice(1, -1), isDevAtom);
  return isDevAtom(text) ? { devWhenTrue: true, devWhenFalse: false } : NONE;
}

const isPreprocessorDebug = (atom: string): boolean =>
  /^(?:DEBUG|_DEBUG|defined\s*\(\s*DEBUG\s*\)|defined\s+DEBUG)$/.test(atom.trim());
const isBuildConfigDebug = (atom: string): boolean => /(?:^|[\s.(])BuildConfig\.DEBUG$/.test(atom.trim());

function lineStarts(code: string): number[] {
  const starts = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') starts.push(i + 1);
  return starts;
}

function lineOf(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

interface Frame {
  /** guards of the conditions seen so far in this #if chain */
  guards: Guard[];
  branchStart: number;
  branchDev: boolean;
}

function preprocessorRanges(code: string, language: NativeLanguage): LineRange[] {
  const lines = maskComments(code, language).split('\n');
  const ranges: LineRange[] = [];
  const stack: Frame[] = [];

  const close = (frame: Frame, endLine: number): void => {
    if (frame.branchDev && frame.branchStart <= endLine) ranges.push({ start: frame.branchStart, end: endLine });
  };
  /** the branch after a failed chain is dev-only when any earlier condition being false implies a debug build */
  const earlierFalseIsDev = (frame: Frame): boolean => frame.guards.some(g => g.devWhenFalse);

  lines.forEach((raw, index) => {
    const lineNo = index + 1;
    const line = raw.trim();
    const directive = /^#\s*(ifdef|ifndef|if|elseif|elif|else|endif)\b\s*(.*)$/.exec(line);
    if (!directive) return;
    const [, kind, rest] = directive;
    if (kind === 'if' || kind === 'ifdef' || kind === 'ifndef') {
      let guard: Guard;
      if (kind === 'if') guard = evaluate(rest, isPreprocessorDebug);
      else {
        const base = evaluate(rest, isPreprocessorDebug);
        guard = kind === 'ifdef' ? base : { devWhenTrue: base.devWhenFalse, devWhenFalse: base.devWhenTrue };
      }
      stack.push({ guards: [guard], branchStart: lineNo + 1, branchDev: guard.devWhenTrue });
      return;
    }
    const frame = stack[stack.length - 1];
    if (!frame) return; // unbalanced directive
    close(frame, lineNo - 1);
    if (kind === 'endif') {
      stack.pop();
    } else if (kind === 'else') {
      frame.branchDev = earlierFalseIsDev(frame);
      frame.branchStart = lineNo + 1;
    } else {
      const guard = evaluate(rest, isPreprocessorDebug);
      frame.branchDev = guard.devWhenTrue || earlierFalseIsDev(frame);
      frame.guards.push(guard);
      frame.branchStart = lineNo + 1;
    }
  });
  return ranges;
}

function buildConfigRanges(code: string, language: NativeLanguage): LineRange[] {
  const masked = maskCode(code, language);
  const starts = lineStarts(masked);
  const ranges: LineRange[] = [];
  const ifRe = /(?<![\w$])if\s*\(/g;

  for (let m = ifRe.exec(masked); m; m = ifRe.exec(masked)) {
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let close = -1;
    for (let i = open; i < masked.length; i++) {
      if (masked[i] === '(') depth++;
      else if (masked[i] === ')' && --depth === 0) {
        close = i;
        break;
      }
    }
    if (close === -1) continue;
    const guard = evaluate(masked.slice(open + 1, close), isBuildConfigDebug);
    if (!guard.devWhenTrue && !guard.devWhenFalse) continue;

    const bodyBegin = /^\s*/.exec(masked.slice(close + 1))![0].length + close + 1;
    let thenEnd: number;
    if (masked[bodyBegin] === '{') {
      thenEnd = matchingBrace(masked, bodyBegin);
      if (thenEnd === -1) continue;
    } else {
      thenEnd = statementEnd(masked, bodyBegin);
    }
    const thenRange = { start: lineOf(starts, bodyBegin), end: lineOf(starts, thenEnd) };

    // optional else branch directly after the then branch
    const afterThen = thenEnd + 1;
    const elseMatch = /^\s*else(?![\w$])\s*/.exec(masked.slice(afterThen));
    let elseRange: { start: number; end: number } | undefined;
    if (elseMatch) {
      const elseBegin = afterThen + elseMatch[0].length;
      if (masked.startsWith('if', elseBegin) && /^if\s*\(/.test(masked.slice(elseBegin))) {
        elseRange = undefined; // `else if`: the chain is not simple enough to reason about
      } else {
        const elseEnd = masked[elseBegin] === '{' ? matchingBrace(masked, elseBegin) : statementEnd(masked, elseBegin);
        if (elseEnd !== -1) elseRange = { start: lineOf(starts, elseBegin), end: lineOf(starts, elseEnd) };
      }
    }

    if (guard.devWhenTrue) ranges.push({ ...thenRange, exclude: elseRange ? [elseRange] : undefined });
    if (guard.devWhenFalse && elseRange) ranges.push({ ...elseRange, exclude: [thenRange] });
  }
  return ranges;
}

/** Last offset of a brace-less statement starting at `from` (the `;`, or the end of a Kotlin line). */
function statementEnd(masked: string, from: number): number {
  let depth = 0;
  for (let i = from; i < masked.length; i++) {
    const c = masked[i];
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (depth <= 0 && c === ';') return i;
    else if (depth <= 0 && c === '\n') {
      const before = masked.slice(from, i).trimEnd();
      const after = masked.slice(i).trimStart();
      if (before === '' || /[=+\-*/%&|,.:?(]$/.test(before) || /^(\.|\?\.|\?:|&&|\|\|)/.test(after)) continue;
      return i - 1;
    }
  }
  return masked.length - 1;
}

/** Line ranges (1-based, inclusive) of a native file that only run in debug builds. */
export function collectNativeDevOnlyRanges(code: string, language: NativeLanguage): LineRange[] {
  if (language === 'swift' || language === 'objc') return preprocessorRanges(code, language);
  return buildConfigRanges(code, language);
}
