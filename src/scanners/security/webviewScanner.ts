import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';


/** Local names under which react-native-webview's WebView is used in this file ("WebView" plus aliases) */
function webViewNames(ast: any): Set<string> {
  const names = new Set<string>(['WebView']);
  traverse(ast, {
    ImportDeclaration(path: any) {
      if (path.node.source.value !== 'react-native-webview') return;
      for (const sp of path.node.specifiers) {
        if (sp.type === 'ImportDefaultSpecifier') names.add(sp.local.name);
        else if (sp.type === 'ImportSpecifier' && sp.imported?.name === 'WebView') names.add(sp.local.name);
      }
    },
  });
  return names;
}

/** Visit every <WebView> element of the file */
function walkWebViews(context: RuleContext, visit: (el: any, path: any) => void): void {
  if (!context.ast) return;
  const names = webViewNames(context.ast);
  traverse(context.ast, {
    JSXElement(path: any) {
      const name = path.node.openingElement.name;
      if (name.type === 'JSXIdentifier' && names.has(name.name)) {
        visit(path.node, path);
      }
    },
  });
}

function findAttr(el: any, name: string): any {
  return el.openingElement.attributes.find(
    (a: any) => a.type === 'JSXAttribute' && a.name.type === 'JSXIdentifier' && a.name.name === name
  );
}

/** `prop={true}` or the bare shorthand `<WebView prop />` */
function attrIsTrue(attr: any): boolean {
  if (!attr) return false;
  if (attr.value === null) return true;
  return (
    attr.value?.type === 'JSXExpressionContainer' &&
    attr.value.expression.type === 'BooleanLiteral' &&
    attr.value.expression.value === true
  );
}

/** Only the explicit `prop={true}` form (what INSECURE_WEBVIEW in networkScanner.ts checks) */
function attrIsExplicitTrue(attr: any): boolean {
  return (
    !!attr &&
    attr.value?.type === 'JSXExpressionContainer' &&
    attr.value.expression.type === 'BooleanLiteral' &&
    attr.value.expression.value === true
  );
}

/** String value of `prop="x"` or `prop={'x'}` */
function attrString(attr: any): string | undefined {
  if (!attr?.value) return undefined;
  if (attr.value.type === 'StringLiteral') return attr.value.value;
  if (attr.value.type === 'JSXExpressionContainer' && attr.value.expression.type === 'StringLiteral') {
    return attr.value.expression.value;
  }
  return undefined;
}

const hasSpreadAttribute = (el: any): boolean =>
  el.openingElement.attributes.some((a: any) => a.type === 'JSXSpreadAttribute');

function isStaticString(node: any): boolean {
  return !!node && (node.type === 'StringLiteral' || (node.type === 'TemplateLiteral' && node.expressions.length === 0));
}

type SourceKind =
  | 'none' // no source prop (or only headers)
  | 'local' // source={require('./page.html')}
  | 'html-literal' // source={{ html: '<p>..</p>' }}
  | 'html-dynamic'
  | 'uri-literal'
  | 'uri-template' // `https://fixed.host/${id}`: host is fixed, path is not
  | 'uri-dynamic'
  | 'dynamic'; // identifier/call/etc. that we cannot resolve

interface SourceInfo {
  kind: SourceKind;
  /** Resolved expression node, for text inspection */
  node?: any;
  /** Initializer of the const that `{ html }` / `{ html: someConst }` refers to, when it resolved to a static string */
  htmlNode?: any;
  uri?: string;
}

/** `const html = '<p>..</p>'` behind an identifier (shorthand `{ html }` or `{ html: page }`), or the node itself when static */
function resolveStaticHtml(node: any, scope: any, depth = 0): any | undefined {
  if (isStaticString(node)) return node;
  if (node?.type === 'Identifier' && depth < 3 && scope) {
    const binding = scope.getBinding(node.name);
    if (binding && binding.constant && binding.path.isVariableDeclarator() && binding.path.node.init) {
      return resolveStaticHtml(binding.path.node.init, binding.path.scope, depth + 1);
    }
  }
  return undefined;
}

function classifySourceExpr(expr: any, scope: any, depth = 0): SourceInfo {
  if (!expr) return { kind: 'none' };

  if (
    expr.type === 'CallExpression' &&
    expr.callee.type === 'Identifier' &&
    expr.callee.name === 'require' &&
    expr.arguments[0]?.type === 'StringLiteral'
  ) {
    return { kind: 'local', node: expr };
  }

  if (expr.type === 'ObjectExpression') {
    if (expr.properties.some((p: any) => p.type === 'SpreadElement')) return { kind: 'dynamic', node: expr };
    const prop = (key: string) =>
      expr.properties.find(
        (p: any) =>
          p.type === 'ObjectProperty' && !p.computed &&
          ((p.key.type === 'Identifier' && p.key.name === key) || (p.key.type === 'StringLiteral' && p.key.value === key))
      );
    const html = prop('html');
    if (html) {
      const htmlNode = resolveStaticHtml(html.value, scope);
      return { kind: htmlNode ? 'html-literal' : 'html-dynamic', node: expr, htmlNode: htmlNode !== html.value ? htmlNode : undefined };
    }
    const uri = prop('uri');
    if (uri) {
      const v = uri.value;
      if (isStaticString(v)) {
        const literal = v.type === 'StringLiteral' ? v.value : v.quasis[0].value.cooked;
        // Bundled assets (Android asset dir, file:// resources) are content shipped with the app
        if (/^(file:\/\/\/android_(asset|res)\/|file:\/\/\/android_asset|asset:\/\/|file:\/\/\/(?!\/))/i.test(literal ?? '') && /android_(asset|res)|^asset:/i.test(literal ?? '')) {
          return { kind: 'local', node: expr, uri: literal };
        }
        return { kind: 'uri-literal', node: expr, uri: literal };
      }
      if (v.type === 'TemplateLiteral' && /^[a-z][a-z0-9+.-]*:\/\/[^/$\s]+\//i.test(v.quasis[0].value.cooked ?? '')) {
        return { kind: 'uri-template', node: expr };
      }
      return { kind: 'uri-dynamic', node: expr };
    }
    return { kind: 'none', node: expr };
  }

  // `cond ? a : b` (e.g. Platform.OS === 'ios' ? require(..) : { uri: 'file:///android_asset/..' }):
  // static only when both branches are static, otherwise report the riskier branch
  if (expr.type === 'ConditionalExpression' && depth < 3) {
    const a = classifySourceExpr(expr.consequent, scope, depth + 1);
    const b = classifySourceExpr(expr.alternate, scope, depth + 1);
    if (isStaticSource(a) && isStaticSource(b)) return { kind: 'local', node: expr };
    return isDynamicSource(a) ? a : isDynamicSource(b) ? b : a.kind === 'none' ? b : a;
  }

  if (expr.type === 'Identifier' && depth < 3 && scope) {
    const binding = scope.getBinding(expr.name);
    if (binding && binding.constant && binding.path.isVariableDeclarator() && binding.path.node.init) {
      return classifySourceExpr(binding.path.node.init, binding.path.scope, depth + 1);
    }
  }

  return { kind: 'dynamic', node: expr };
}

function classifySource(el: any, path: any): SourceInfo {
  const attr = findAttr(el, 'source');
  if (!attr) return { kind: 'none' };
  if (attr.value?.type !== 'JSXExpressionContainer') return { kind: 'dynamic' };
  return classifySourceExpr(attr.value.expression, path.scope);
}

/** Content shipped inside the app: it cannot be attacker-controlled web content */
const isStaticSource = (info: SourceInfo): boolean => info.kind === 'local' || info.kind === 'html-literal';
const isDynamicSource = (info: SourceInfo): boolean =>
  info.kind === 'dynamic' || info.kind === 'html-dynamic' || info.kind === 'uri-dynamic' || info.kind === 'uri-template';

const webviewJavascriptInjectionRule: Rule = {
  id: 'WEBVIEW_JAVASCRIPT_INJECTION',
  description: 'WebView with JavaScript enabled loading dynamic or user-controlled content',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, (node, path) => {
      if (!attrIsTrue(findAttr(node, 'javaScriptEnabled'))) return;

      const source = classifySource(node, path);
      if (!isDynamicSource(source)) return;

      const line = getLineNumber(context.fileContent, node.start || 0);
      // A fixed host with only the path interpolated is a much narrower risk than an arbitrary URL
      const fixedHost = source.kind === 'uri-template';

      findings.push({
        ruleId: 'WEBVIEW_JAVASCRIPT_INJECTION',
        description: 'WebView with JavaScript enabled loading dynamic content - potential XSS vulnerability',
        severity: fixedHost ? Severity.MEDIUM : Severity.HIGH,
        ...(fixedHost ? { confidence: 'medium' as const } : {}),
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Validate and sanitize URLs before loading, use originWhitelist to restrict allowed domains, or disable JavaScript if not needed',
      });
    });

    return findings;
  },
};

const webviewFileAccessRule: Rule = {
  id: 'WEBVIEW_FILE_ACCESS',
  description: 'WebView with file access enabled - allows access to local files',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, (node, path) => {
      const source = classifySource(node, path);

      for (const propName of ['allowFileAccess', 'allowFileAccessFromFileURLs', 'allowUniversalAccessFromFileURLs']) {
        if (!attrIsTrue(findAttr(node, propName))) continue;

        const line = getLineNumber(context.fileContent, node.start || 0);
        // Plain allowFileAccess is how bundled local HTML is loaded on Android; the *FromFileURLs
        // flags let file:// pages read other files/origins and stay HIGH.
        const bundledLocalContent = propName === 'allowFileAccess' && (isStaticSource(source) || (source.kind === 'uri-literal' && /^file:/i.test(source.uri ?? '')));

        findings.push({
          ruleId: 'WEBVIEW_FILE_ACCESS',
          description: `WebView with ${propName}={true} - exposes local file system`,
          severity: bundledLocalContent ? Severity.MEDIUM : Severity.HIGH,
          ...(bundledLocalContent ? { confidence: 'medium' as const } : {}),
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Disable file access unless absolutely necessary. If required, implement strict validation and access controls',
        });
      }
    });

    return findings;
  },
};

const webviewDomStorageRule: Rule = {
  id: 'WEBVIEW_DOM_STORAGE_ENABLED',
  description: 'WebView with DOM storage enabled - may expose sensitive data',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, (node, path) => {
      if (!attrIsTrue(findAttr(node, 'domStorageEnabled')) || !attrIsTrue(findAttr(node, 'javaScriptEnabled'))) return;
      // App-bundled content has no XSS vector to read the storage
      if (isStaticSource(classifySource(node, path))) return;

      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEBVIEW_DOM_STORAGE_ENABLED',
        description: 'WebView with DOM storage and JavaScript enabled - sensitive data may be exposed to XSS',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Avoid storing sensitive data in localStorage/sessionStorage, use secure native storage instead',
      });
    });

    return findings;
  },
};

const webviewGeolocationRule: Rule = {
  id: 'WEBVIEW_GEOLOCATION_ENABLED',
  description: 'WebView with geolocation enabled - requires proper permission handling',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, node => {
      if (!attrIsTrue(findAttr(node, 'geolocationEnabled'))) return;

      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEBVIEW_GEOLOCATION_ENABLED',
        description: 'WebView with geolocation enabled - ensure proper permission handling',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Implement onGeolocationPermissionsShowPrompt to properly handle location permissions and user consent',
      });
    });

    return findings;
  },
};

const webviewMixedContentRule: Rule = {
  id: 'WEBVIEW_MIXED_CONTENT',
  description: 'WebView allows mixed content - HTTPS pages can load HTTP resources',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, node => {
      if (attrString(findAttr(node, 'mixedContentMode')) !== 'always') return;

      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEBVIEW_MIXED_CONTENT',
        description: 'WebView allows mixed content (HTTP resources on HTTPS pages)',
        severity: Severity.MEDIUM,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Set mixedContentMode to "never" to prevent loading insecure content on HTTPS pages',
      });
    });

    return findings;
  },
};

const webviewUnvalidatedNavigationRule: Rule = {
  id: 'WEBVIEW_UNVALIDATED_NAVIGATION',
  description: 'WebView without URL validation on navigation - potential open redirect',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, (node, path) => {
      if (!attrIsTrue(findAttr(node, 'javaScriptEnabled'))) return;
      if (findAttr(node, 'onShouldStartLoadWithRequest') || findAttr(node, 'onNavigationStateChange')) return;
      // Content bundled with the app is not an open-redirect surface
      if (isStaticSource(classifySource(node, path))) return;

      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEBVIEW_UNVALIDATED_NAVIGATION',
        description: 'WebView without URL validation - vulnerable to open redirect and phishing',
        severity: Severity.HIGH,
        // Props may be supplied through a spread we cannot see
        ...(hasSpreadAttribute(node) ? { confidence: 'low' as const } : {}),
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Implement onShouldStartLoadWithRequest to validate URLs before navigation and restrict to trusted domains',
      });
    });

    return findings;
  },
};

const webviewPostMessageRule: Rule = {
  id: 'WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK',
  description: 'WebView onMessage handler without origin validation',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, (node, path) => {
      const onMessage = findAttr(node, 'onMessage');
      if (!onMessage || onMessage.value?.type !== 'JSXExpressionContainer') return;
      // Messages from app-bundled pages come from our own code
      if (isStaticSource(classifySource(node, path))) return;

      // Find the handler's code: inline function, or a function/const in this file
      let handler: any = onMessage.value.expression;
      if (handler.type === 'Identifier') {
        const binding = path.scope.getBinding(handler.name);
        if (binding?.path.isFunctionDeclaration()) {
          handler = binding.path.node;
        } else if (binding?.path.isVariableDeclarator() && binding.path.node.init) {
          handler = binding.path.node.init;
        }
      }
      const inspectable = handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression' || handler.type === 'FunctionDeclaration';

      if (inspectable) {
        const handlerCode = context.fileContent.substring(handler.start || 0, handler.end || 0);
        if (/origin|nativeEvent\.url|event\.url|source.*url/i.test(handlerCode)) return;
      }

      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK',
        description: 'WebView onMessage handler does not validate message origin',
        severity: Severity.HIGH,
        // A handler defined elsewhere may validate; we only know it is not visible here
        ...(inspectable ? {} : { confidence: 'low' as const }),
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Always validate event.nativeEvent.url or message origin before processing postMessage data',
      });
    });

    return findings;
  },
};

const webviewCachingRule: Rule = {
  id: 'WEBVIEW_CACHING_ENABLED',
  description: 'WebView with caching enabled - may cache sensitive content',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, node => {
      if (!attrIsTrue(findAttr(node, 'cacheEnabled'))) return;

      const sourceAttr = findAttr(node, 'source');
      const sourceCode = context.fileContent.substring(sourceAttr?.value?.start || 0, sourceAttr?.value?.end || 0);
      if (!/header|authorization|token|bearer/i.test(sourceCode)) return;

      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEBVIEW_CACHING_ENABLED',
        description: 'WebView with caching enabled while loading authenticated content',
        severity: Severity.LOW,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Disable caching for pages with sensitive content or authentication tokens',
      });
    });

    return findings;
  },
};

/**
 * react-native-webview defaults to originWhitelist ['http://*', 'https://*']; only a bare '*'
 * widens it (documented use: static `html` sources). https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md
 */
const webviewOriginWhitelistWildcardRule: Rule = {
  id: 'WEBVIEW_ORIGIN_WHITELIST_WILDCARD',
  description: "WebView originWhitelist contains '*' - any URL scheme/origin may be navigated to",
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, (node, path) => {
      const attr = findAttr(node, 'originWhitelist');
      if (!attr || attr.value?.type !== 'JSXExpressionContainer') return;

      let list: any = attr.value.expression;
      const inlineArray = list.type === 'ArrayExpression';
      if (list.type === 'Identifier') {
        const binding = path.scope.getBinding(list.name);
        if (binding?.constant && binding.path.isVariableDeclarator()) list = binding.path.node.init;
      }
      if (!list || list.type !== 'ArrayExpression') return;

      const hasBareWildcard = list.elements.some((el: any) => el && el.type === 'StringLiteral' && el.value.trim() === '*');
      if (!hasBareWildcard) return;

      // INSECURE_WEBVIEW (networkScanner.ts) already reports explicit javaScriptEnabled={true} + inline ['*']
      if (inlineArray && attrIsExplicitTrue(findAttr(node, 'javaScriptEnabled'))) return;

      const source = classifySource(node, path);
      let severity = Severity.MEDIUM;
      let confidence: 'high' | 'medium' | 'low' | undefined;
      if (isStaticSource(source)) {
        // The documented reason to set '*': content shipped with the app
        severity = Severity.LOW;
        confidence = 'low';
      } else if (source.kind === 'dynamic' || source.kind === 'uri-dynamic') {
        severity = Severity.HIGH;
      }

      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEBVIEW_ORIGIN_WHITELIST_WILDCARD',
        description: "WebView originWhitelist contains '*' - allows navigation to any origin and custom URL scheme",
        severity,
        ...(confidence ? { confidence } : {}),
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: "Restrict originWhitelist to the https origins you need (e.g. ['https://example.com']). '*' is only appropriate for static html shipped with the app.",
      });
    });

    return findings;
  },
};

const missingSecurityHeadersRule: Rule = {
  id: 'MISSING_SECURITY_HEADERS',
  description: 'WebView missing important security headers (CSP, X-Frame-Options)',
  severity: Severity.LOW,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    walkWebViews(context, (node, path) => {
      const hasInjectedJavaScript = !!findAttr(node, 'injectedJavaScript');
      const source = classifySource(node, path);
      const sourceAttr = findAttr(node, 'source');
      const sourceCode =
        (source.node
          ? context.fileContent.substring(source.node.start || 0, source.node.end || 0)
          : context.fileContent.substring(sourceAttr?.value?.start || 0, sourceAttr?.value?.end || 0)) +
        // the markup lives in the const behind `{ html }`
        (source.htmlNode ? `\n${context.fileContent.substring(source.htmlNode.start || 0, source.htmlNode.end || 0)}` : '');

      const injectsHeaders = /headers\s*:/i.test(sourceCode);
      const loadsHtml = source.kind === 'html-literal' || source.kind === 'html-dynamic';

      if (loadsHtml) {
        // Check for CSP in HTML
        const hasCSP = /content-security-policy/i.test(sourceCode);
        const hasScript = /<script\b/i.test(sourceCode);

        if (!hasCSP && (hasInjectedJavaScript || hasScript)) {
          const line = getLineNumber(context.fileContent, node.start || 0);

          findings.push({
            ruleId: 'MISSING_SECURITY_HEADERS',
            description: 'WebView loading HTML without Content-Security-Policy header',
            severity: Severity.LOW,
            filePath: context.filePath,
            line,
            snippet: extractSnippet(context.fileContent, line),
            suggestion: 'Add Content-Security-Policy meta tag to HTML: <meta http-equiv="Content-Security-Policy" content="default-src \'self\'" />',
          });
        }
        return;
      }

      // External content: only meaningful when the WebView actually loads a remote page
      const loadsRemote = source.kind !== 'none' && source.kind !== 'local';
      if (loadsRemote && !injectsHeaders) {
        const line = getLineNumber(context.fileContent, node.start || 0);

        findings.push({
          ruleId: 'MISSING_SECURITY_HEADERS',
          description: 'WebView loading external content without security headers',
          severity: Severity.LOW,
          filePath: context.filePath,
          line,
          snippet: extractSnippet(context.fileContent, line),
          suggestion: 'Add security headers to WebView source: X-Frame-Options, Content-Security-Policy. Validate origin of loaded content.',
        });
      }
    });

    return findings;
  },
};

export const webviewRules: RuleGroup = {
  category: RuleCategory.NETWORK,
  rules: [
    webviewJavascriptInjectionRule,
    webviewFileAccessRule,
    webviewDomStorageRule,
    webviewGeolocationRule,
    webviewMixedContentRule,
    webviewUnvalidatedNavigationRule,
    webviewPostMessageRule,
    webviewCachingRule,
    webviewOriginWhitelistWildcardRule,
    missingSecurityHeadersRule,
  ],
};
