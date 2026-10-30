/**
 * Where does the value of a URL expression come from? Used by rules that open or load a URL (`Linking.openURL`).
 *
 * - `constant`:  string literal, template with a fixed `scheme://host/` (or `mailto:` / `tel:`) prefix, module-level
 *                constant or enum (UPPER_SNAKE / PascalCase name, import), i18n lookup with a literal key
 * - `untrusted`: route params, deep-link input, a network response (fetch/axios/query result)
 * - `param`:     a function parameter, hook state or something derived from one: the caller decides, nothing here proves it safe
 * - `unknown`:   could not be resolved (global, loop variable, ...)
 */
export type UrlOrigin = 'constant' | 'param' | 'untrusted' | 'unknown';

const RANK: Record<UrlOrigin, number> = { constant: 0, unknown: 1, param: 2, untrusted: 3 };
const worst = (...origins: UrlOrigin[]): UrlOrigin => origins.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'constant' as UrlOrigin);

// `https://host/...`: scheme and host are fixed, only the path / query varies
const FIXED_HOST_PREFIX = /^[a-z][a-z0-9+.-]*:\/\/[^\s/${}?#]+(?:\/|$)/i;
// schemes whose payload (number, address, query) is data, not a destination
const FIXED_DATA_SCHEME = /^(?:mailto|tel|telprompt|sms|geo|maps):/i;

const ROUTE_HOOKS = new Set(['useRoute', 'useLocalSearchParams', 'useGlobalSearchParams', 'useSearchParams', 'useParams', 'useRouteParams']);
// calls that return server or stored user data: `await Note.load(id)` is not a constant just because `Note` is imported
const DATA_CALLEES = new Set([
  'fetch', 'axios', 'request', 'post', 'put', 'patch', 'query', 'mutate', 'useQuery', 'useLazyQuery', 'useSWR', 'useMutation', 'useFragment',
  'load', 'findOne', 'findById', 'getItem', 'readFile',
]);
// too generic to count on a constant receiver (`URLS.get('help')`)
const WEAK_DATA_CALLEES = new Set(['get', 'json', 'text', 'read', 'find']);
const I18N_CALLEES = new Set(['t', 'strings', 'translate', 'i18n', 'formatMessage', 'localize', 'tr', '_', '__']);
const ROUTE_PROPERTIES = new Set(['params', 'query', 'searchParams']);
const CONST_NAME = /^(?:[A-Z][A-Z0-9_]*|[A-Z][A-Za-z0-9]*)$/;

export function hasFixedUrlPrefix(text: string | null | undefined): boolean {
  return !!text && (FIXED_HOST_PREFIX.test(text) || FIXED_DATA_SCHEME.test(text));
}

function calleeName(callee: any): string | null {
  if (!callee) return null;
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property?.type === 'Identifier') return callee.property.name;
  return null;
}

function leadingText(node: any): string | null {
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral') return node.quasis[0]?.value?.cooked ?? null;
  return null;
}

function classifyBinding(binding: any, name: string, seen: Set<any>, depth: number): UrlOrigin {
  if (binding.kind === 'module') return 'constant';
  if (binding.kind === 'param') {
    const call = binding.path.getFunctionParent?.()?.parentPath?.node;
    // Linking.addEventListener('url', ({ url }) => ...): the deep-link URL itself
    if (
      call?.type === 'CallExpression' &&
      call.callee?.property?.name === 'addEventListener' &&
      call.arguments[0]?.value === 'url'
    ) {
      return 'untrusted';
    }
    return 'param';
  }
  if (binding.kind === 'hoisted') return 'unknown';
  const declarator = binding.path;
  if (declarator?.node?.type !== 'VariableDeclarator' || !declarator.node.init) return 'unknown';
  if (seen.has(declarator.node)) return 'unknown';
  seen.add(declarator.node);
  const scope = binding.scope;
  let result = classifyUrlOrigin(declarator.node.init, scope, seen, depth + 1);
  for (const violation of binding.constantViolations ?? []) {
    const n = violation.node;
    result = worst(result, n.type === 'AssignmentExpression' ? classifyUrlOrigin(n.right, violation.scope, seen, depth + 1) : 'unknown');
  }
  return result;
}

export function classifyUrlOrigin(node: any, scope: any, seen: Set<any> = new Set(), depth = 0): UrlOrigin {
  if (!node || depth > 8) return 'unknown';
  switch (node.type) {
    case 'StringLiteral':
    case 'NumericLiteral':
    case 'BooleanLiteral':
    case 'NullLiteral':
      return 'constant';
    case 'TemplateLiteral': {
      if (node.expressions.length === 0 || hasFixedUrlPrefix(leadingText(node))) return 'constant';
      return worst(...node.expressions.map((e: any) => classifyUrlOrigin(e, scope, seen, depth + 1)));
    }
    case 'BinaryExpression': {
      if (node.operator !== '+') return 'unknown';
      const lead = node.left.type === 'BinaryExpression' ? null : leadingText(node.left);
      if (hasFixedUrlPrefix(lead)) return 'constant';
      return worst(classifyUrlOrigin(node.left, scope, seen, depth + 1), classifyUrlOrigin(node.right, scope, seen, depth + 1));
    }
    case 'Identifier': {
      if (node.name === 'undefined') return 'constant';
      const binding = scope?.getBinding(node.name);
      if (!binding) return CONST_NAME.test(node.name) ? 'constant' : 'unknown';
      return classifyBinding(binding, node.name, seen, depth);
    }
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const prop = !node.computed && node.property?.type === 'Identifier' ? node.property.name : null;
      const base = classifyUrlOrigin(node.object, scope, seen, depth + 1);
      if (base === 'constant') return 'constant';
      if (prop && ROUTE_PROPERTIES.has(prop)) return 'untrusted';
      return base;
    }
    case 'CallExpression':
    case 'OptionalCallExpression': {
      const name = calleeName(node.callee);
      const first = node.arguments[0];
      if (name && I18N_CALLEES.has(name) && first && leadingText(first) !== null && first.type !== 'TemplateLiteral') return 'constant';
      if (name && ROUTE_HOOKS.has(name)) return 'untrusted';
      if (name === 'getInitialURL') return 'untrusted';
      const args = node.arguments.map((a: any) => classifyUrlOrigin(a, scope, seen, depth + 1));
      const callee = node.callee.type === 'MemberExpression' ? classifyUrlOrigin(node.callee.object, scope, seen, depth + 1) : 'constant';
      if (name && DATA_CALLEES.has(name)) return 'untrusted';
      if (name && WEAK_DATA_CALLEES.has(name) && (callee !== 'constant' || node.callee.type === 'Identifier')) return 'untrusted';
      // useState('') / useMemo(...) / a selector: dynamic state the setter or the store fills later, not a constant
      if (name && /^use[A-Z]/.test(name)) return 'param';
      if (args.length === 0 && node.callee.type === 'Identifier') return 'unknown';
      return worst(callee, ...args);
    }
    case 'NewExpression':
      return worst(...node.arguments.map((a: any) => classifyUrlOrigin(a, scope, seen, depth + 1)));
    case 'AwaitExpression':
      return classifyUrlOrigin(node.argument, scope, seen, depth + 1);
    case 'ConditionalExpression':
      return worst(classifyUrlOrigin(node.consequent, scope, seen, depth + 1), classifyUrlOrigin(node.alternate, scope, seen, depth + 1));
    case 'LogicalExpression':
      return worst(classifyUrlOrigin(node.left, scope, seen, depth + 1), classifyUrlOrigin(node.right, scope, seen, depth + 1));
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'TSTypeAssertion':
    case 'TypeCastExpression':
    case 'ParenthesizedExpression':
      return classifyUrlOrigin(node.expression, scope, seen, depth + 1);
    default:
      return 'unknown';
  }
}
