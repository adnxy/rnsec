import type { Node } from '@babel/types';
import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;

/**
 * A source range (1-based, inclusive lines) that only executes in development
 * builds. `exclude` holds sibling code that stays reachable in production but
 * may share lines with the range (e.g. both arms of a one-line ternary).
 */
export interface LineRange {
  start: number;
  end: number;
  exclude?: Array<{ start: number; end: number }>;
}

/**
 * What a test expression tells us:
 * - `devWhenTrue`: a truthy result guarantees a development build
 * - `devWhenFalse`: a falsy result guarantees a development build
 */
interface Guard {
  devWhenTrue: boolean;
  devWhenFalse: boolean;
}

const NONE: Guard = { devWhenTrue: false, devWhenFalse: false };
const DEV: Guard = { devWhenTrue: true, devWhenFalse: false };
const PROD: Guard = { devWhenTrue: false, devWhenFalse: true };

const DEV_IDENTIFIERS = new Set([
  '__DEV__',
  'isDev',
  'isDevelopment',
  'isDebug',
  'IS_DEV',
  'IS_DEBUG',
  'DEBUG',
]);

function isNodeEnvMember(node: any): boolean {
  return (
    node?.type === 'MemberExpression' &&
    !node.computed &&
    node.property?.name === 'NODE_ENV' &&
    node.object?.type === 'MemberExpression' &&
    node.object.property?.name === 'env'
  );
}

function isProcessEnvDebug(node: any): boolean {
  return (
    node?.type === 'MemberExpression' &&
    !node.computed &&
    node.property?.name === 'DEBUG' &&
    node.object?.type === 'MemberExpression' &&
    node.object.property?.name === 'env'
  );
}

const not = (g: Guard): Guard => ({ devWhenTrue: g.devWhenFalse, devWhenFalse: g.devWhenTrue });

/** Classify a test expression. Unknown expressions guarantee nothing. */
export function classifyGuard(node: any): Guard {
  if (!node) return NONE;

  switch (node.type) {
    case 'Identifier':
      return DEV_IDENTIFIERS.has(node.name) ? DEV : NONE;

    case 'MemberExpression':
      return isProcessEnvDebug(node) ? DEV : NONE;

    case 'ParenthesizedExpression':
      return classifyGuard(node.expression);

    case 'UnaryExpression':
      return node.operator === '!' ? not(classifyGuard(node.argument)) : NONE;

    case 'BinaryExpression': {
      const { operator, left, right } = node;
      const isEq = operator === '===' || operator === '==';
      const isNeq = operator === '!==' || operator === '!=';
      if (!isEq && !isNeq) return NONE;

      const [envSide, litSide] = isNodeEnvMember(left) ? [left, right] : [right, left];
      if (!isNodeEnvMember(envSide) || litSide?.type !== 'StringLiteral') return NONE;

      const base = litSide.value === 'development' ? DEV : litSide.value === 'production' ? PROD : NONE;
      return isEq ? base : not(base);
    }

    case 'LogicalExpression': {
      const l = classifyGuard(node.left);
      const r = classifyGuard(node.right);
      if (node.operator === '&&') {
        // truthy needs both truthy; falsy means either is falsy
        return {
          devWhenTrue: l.devWhenTrue || r.devWhenTrue,
          devWhenFalse: l.devWhenFalse && r.devWhenFalse,
        };
      }
      if (node.operator === '||') {
        // truthy means either is truthy; falsy needs both falsy
        return {
          devWhenTrue: l.devWhenTrue && r.devWhenTrue,
          devWhenFalse: l.devWhenFalse || r.devWhenFalse,
        };
      }
      return NONE;
    }

    default:
      return NONE;
  }
}

function lineRange(node: any): { start: number; end: number } | null {
  if (!node?.loc) return null;
  return { start: node.loc.start.line, end: node.loc.end.line };
}

/**
 * Collect the line ranges of code that is only reachable in development builds:
 * the branch of an `if` / ternary / `&&` / `||` whose guard proves a dev build.
 * Sibling branches that remain reachable in production are excluded, so
 * `__DEV__ ? 'test-key' : 'live-key'` on one line never hides the live key.
 */
export function collectDevOnlyRanges(ast: Node | undefined): LineRange[] {
  const ranges: LineRange[] = [];
  if (!ast) return ranges;

  const push = (devBranch: any, prodSiblings: any[]) => {
    const r = lineRange(devBranch);
    if (!r) return;
    const exclude = prodSiblings.map(lineRange).filter((x): x is { start: number; end: number } => x !== null);
    ranges.push({ ...r, exclude });
  };

  try {
    traverse(ast, {
      IfStatement(path: any) {
        const { test, consequent, alternate } = path.node;
        const g = classifyGuard(test);
        if (g.devWhenTrue) push(consequent, [alternate]);
        if (g.devWhenFalse && alternate) push(alternate, [consequent]);
      },
      ConditionalExpression(path: any) {
        const { test, consequent, alternate } = path.node;
        const g = classifyGuard(test);
        if (g.devWhenTrue) push(consequent, [alternate]);
        if (g.devWhenFalse) push(alternate, [consequent]);
      },
      LogicalExpression(path: any) {
        const { operator, left, right } = path.node;
        const g = classifyGuard(left);
        if (operator === '&&' && g.devWhenTrue) push(right, []);
        // `isProd || devOnly()` runs the right side only when not production
        if (operator === '||' && g.devWhenFalse) push(right, []);
      },
    });
  } catch {
    // A traversal failure must never hide findings
  }

  return ranges;
}

export function isLineInRanges(line: number | undefined, ranges: LineRange[]): boolean {
  if (line === undefined) return false;
  return ranges.some(
    r =>
      line >= r.start &&
      line <= r.end &&
      !(r.exclude ?? []).some(e => line >= e.start && line <= e.end)
  );
}
