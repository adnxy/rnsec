import { Severity, type Finding } from '../../types/findings.js';
import type { Rule, RuleContext } from '../../types/ruleTypes.js';
import { findFunctions, isTrivialBody, maskCode, maskComments } from '../../utils/nativeCode.js';
import { extractSnippet, getLineNumber } from '../../utils/stringUtils.js';

/**
 * TLS_VALIDATION_DISABLED_NATIVE: certificate or hostname validation switched off in the app's own Java / Kotlin /
 * Swift / Objective-C code. Only constructs that are unsafe by themselves are reported (an empty `checkServerTrusted`,
 * a hostname verifier that is just `true`, `proceed()` on every WebView SSL error, an auth-challenge handler that
 * trusts whatever the server presents). Code behind `BuildConfig.DEBUG` / `#if DEBUG` never reaches this rule's
 * findings (the engine drops it). Code behind any other condition is reported as MEDIUM (opt-in switch).
 */

interface Block {
  /** Offset of the `{` */
  open: number;
  /** Text between the previous statement boundary and the `{`, e.g. `if (!validateCertificates)` */
  header: string;
}

/** Blocks that enclose `offset` in masked code, outermost first. */
function enclosingBlocks(masked: string, offset: number): Block[] {
  const stack: number[] = [];
  for (let i = 0; i < offset; i++) {
    if (masked[i] === '{') stack.push(i);
    else if (masked[i] === '}') stack.pop();
  }
  return stack.map(open => ({ open, header: headerBefore(masked, open) }));
}

/**
 * The statement header in front of a `{`: back to the previous `;`, `{` or `}`, and (Kotlin and Swift have no `;`)
 * to the start of the line unless parentheses are open or the previous line visibly continues (`,` `&&` `||` `(`).
 */
function headerBefore(masked: string, open: number): string {
  let depth = 0;
  let j = open - 1;
  for (; j >= 0; j--) {
    const c = masked[j];
    if (';{}'.includes(c)) break;
    if (c === ')') depth++;
    else if (c === '(') depth--;
    else if (c === '\n' && depth <= 0) {
      const previous = masked.slice(0, j).trimEnd();
      if (!/[,&|(]$/.test(previous)) break;
    }
  }
  return masked.slice(j + 1, open).trim();
}

const CONDITIONAL_HEADER = /^(?:if|else|when|guard|switch|while)\b/;

/** Words of an auth-challenge condition that only ask "is this a server-trust challenge" (not an opt-in switch). */
const CHALLENGE_PLUMBING = new Set([
  'if', 'else', 'guard', 'let', 'var', 'case', 'switch', 'challenge', 'protectionSpace', 'authenticationMethod',
  'NSURLAuthenticationMethodServerTrust', 'serverTrust', 'trust', 'isEqualToString', 'isEqual', 'nil', 'true',
  'false', 'self', 'authMethod', 'method',
]);

function isOptInHeader(header: string, plumbing: Set<string> | null): boolean {
  if (!CONDITIONAL_HEADER.test(header)) return false;
  if (!plumbing) return true;
  return (header.match(/[A-Za-z_]\w*/g) ?? []).some(word => !plumbing.has(word));
}

const lineOf = (code: string, offset: number): number => getLineNumber(code, offset);

function makeFinding(
  context: RuleContext,
  offset: number,
  optIn: boolean,
  what: string,
  platformNote: string,
  suggestion: string
): Finding {
  const line = lineOf(context.fileContent, offset);
  return {
    ruleId: 'TLS_VALIDATION_DISABLED_NATIVE',
    description: optIn ? `${what} (only behind a condition: an opt-in switch)` : what,
    severity: optIn ? Severity.MEDIUM : Severity.HIGH,
    confidence: optIn ? 'medium' : 'high',
    filePath: context.filePath,
    line,
    snippet: extractSnippet(context.fileContent, line, 1),
    reason: `${platformNote} A network attacker (rogue Wi-Fi, malicious proxy) can then present any certificate and read or modify the traffic.`,
    suggestion,
  };
}

const TRUST_SUGGESTION =
  'Remove the trust-all implementation and use the platform trust store. To trust a private CA, pin its certificate or public key (network security config on Android, a real SecTrust evaluation on iOS) instead of disabling validation.';

function androidFindings(context: RuleContext, masked: string): Finding[] {
  const language = context.language!;
  const code = context.fileContent;
  const findings: Finding[] = [];
  const seen = new Set<number>();
  const add = (offset: number, optIn: boolean, what: string, note: string, suggestion = TRUST_SUGGESTION): void => {
    const line = lineOf(code, offset);
    if (seen.has(line)) return;
    seen.add(line);
    findings.push(makeFinding(context, offset, optIn, what, note, suggestion));
  };
  const optInAt = (offset: number, from = 0): boolean =>
    enclosingBlocks(masked, offset).some(b => b.open >= from && isOptInHeader(b.header, null));
  const nameOffset = (fnStart: number, bodyStart: number, name: string): number => {
    const at = code.slice(fnStart, bodyStart).search(new RegExp(`\\b${name}\\b`));
    return fnStart + Math.max(at, 0);
  };

  // 1. X509TrustManager that accepts every server certificate
  if (/checkServerTrusted/.test(code)) {
    for (const fn of findFunctions(code, language, /^checkServerTrusted$/)) {
      if (!/Certificate/.test(fn.signature) || !isTrivialBody(fn.body)) continue;
      add(
        nameOffset(fn.start, fn.bodyStart, 'checkServerTrusted'),
        optInAt(fn.start),
        'X509TrustManager.checkServerTrusted is empty: every server certificate is accepted',
        'The trust manager performs no validation of the server certificate chain.'
      );
    }
  }

  // 2. HostnameVerifier that always returns true
  if (/HostnameVerifier|hostnameVerifier|SSLSession/.test(code)) {
    for (const fn of findFunctions(code, language, /^verify$/)) {
      if (!/SSLSession/.test(fn.signature)) continue;
      const body = maskComments(fn.body, language).trim().replace(/;$/, '');
      if (!/^(?:return\s+)?true$/.test(body)) continue;
      add(
        nameOffset(fn.start, fn.bodyStart, 'verify'),
        optInAt(fn.start),
        'HostnameVerifier.verify always returns true: any certificate is accepted for any host name',
        'Host name verification is switched off, so a valid certificate for another site is accepted.',
        'Remove the custom HostnameVerifier (the default one checks the host name) or compare the host against the one you intend to reach.'
      );
    }
    const lambda =
      /\(\s*(?:[\w.<>?]+\s+)?\w+\s*,\s*(?:[\w.<>?]+\s+)?\w+\s*\)\s*->\s*true\b|\b[Hh]ostname[Vv]erifier\s*(?:\(\s*)?\{\s*\w+\s*,\s*\w+\s*->\s*true\s*\}/g;
    for (let m = lambda.exec(masked); m; m = lambda.exec(masked)) {
      let from = m.index - 1;
      while (from >= 0 && !';{}'.includes(masked[from]) && m.index - from < 220) from--;
      if (!/[Hh]ostname[Vv]erifier/.test(masked.slice(from + 1, m.index + m[0].length))) continue;
      add(
        m.index,
        optInAt(m.index),
        'Hostname verifier lambda always returns true: any certificate is accepted for any host name',
        'Host name verification is switched off, so a valid certificate for another site is accepted.',
        'Remove the custom hostname verifier (the default one checks the host name) or compare the host against the one you intend to reach.'
      );
    }
    const allowAll = /\b(?:ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NoopHostnameVerifier)\b/g;
    for (let m = allowAll.exec(masked); m; m = allowAll.exec(masked)) {
      const lineStart = masked.lastIndexOf('\n', m.index) + 1;
      if (/^\s*import\b/.test(masked.slice(lineStart, m.index))) continue;
      add(
        m.index,
        optInAt(m.index),
        `${m[0]} disables host name verification`,
        'The allow-all host name verifier accepts a certificate for any host name.',
        'Use the default HostnameVerifier (StrictHostnameVerifier / the platform default).'
      );
    }
  }

  // 3. WebViewClient that continues loading after every SSL error
  if (/onReceivedSslError/.test(code)) {
    for (const fn of findFunctions(code, language, /^onReceivedSslError$/)) {
      const handler = /SslErrorHandler\s+(\w+)/.exec(fn.signature)?.[1] ?? /(\w+)\s*:\s*(?:[\w.]*\.)?SslErrorHandler/.exec(fn.signature)?.[1];
      if (!handler) continue;
      const body = masked.slice(fn.bodyStart, fn.bodyEnd);
      const proceed = new RegExp(`\\b${handler}\\s*(?:\\?|!!)?\\.\\s*proceed\\s*\\(\\s*\\)`).exec(body);
      if (!proceed) continue;
      const offset = fn.bodyStart + proceed.index;
      const blocks = enclosingBlocks(masked, offset).filter(b => b.open >= fn.bodyStart);
      // `(dialog, which) -> handler.proceed()`: the user decides
      const statementStart = Math.max(masked.lastIndexOf(';', offset), masked.lastIndexOf('{', offset), masked.lastIndexOf('}', offset));
      if (masked.slice(statementStart + 1, offset).includes('->')) continue;
      let optIn = false;
      if (blocks.length > 0 || /\.cancel\s*\(\s*\)/.test(body)) {
        // a dialog / listener / lambda (user decides) or a check of the error, URL or certificate is not a bypass
        if (blocks.some(b => !CONDITIONAL_HEADER.test(b.header))) continue;
        if (blocks.some(b => /error|url|host|cert/i.test(b.header))) continue;
        optIn = true;
      }
      add(
        offset,
        optIn,
        'onReceivedSslError calls proceed(): the WebView loads pages whose certificate failed validation',
        'The WebView ignores SSL errors (expired, self-signed or wrong-host certificates) and keeps loading.',
        'Call handler.cancel() (the default) and show an error. If you must reach a server with a private CA, pin that certificate instead of proceeding on every error.'
      );
    }
  }
  return findings;
}

const CREDENTIAL_FROM_TRUST = /\bURLCredential\s*\(\s*trust\s*:|\bcredentialForTrust\s*:/;
const USE_CREDENTIAL = /\.useCredential\b|UseCredential\b/;
/** Anything in the handler that evaluates the trust or compares a certificate / key / pin */
const TRUST_EVALUATION = /\bSec(?:Trust|Certificate|Key|Policy)\w*|\b(?:isEqualToData|evaluat|validat|verif|pin)\w*/i;

function iosFindings(context: RuleContext, masked: string): Finding[] {
  const language = context.language!;
  const code = context.fileContent;
  const findings: Finding[] = [];
  if (!/Challenge/.test(code)) return findings;
  for (const fn of findFunctions(code, language, /(?:urlSession|URLSession|webView|connection)/)) {
    if (!/Challenge/.test(fn.signature)) continue;
    const body = masked.slice(fn.bodyStart, fn.bodyEnd);
    const credential = CREDENTIAL_FROM_TRUST.exec(body);
    if (!credential || !USE_CREDENTIAL.test(body) || TRUST_EVALUATION.test(body)) continue;
    const offset = fn.bodyStart + credential.index;
    const optIn = enclosingBlocks(masked, offset).some(
      b => b.open >= fn.bodyStart && isOptInHeader(b.header, CHALLENGE_PLUMBING)
    );
    const kind = /WKWebView|WKNavigation/.test(fn.signature) ? 'WKNavigationDelegate' : 'URLSession / NSURLConnection delegate';
    findings.push(
      makeFinding(
        context,
        offset,
        optIn,
        `${kind} auth-challenge handler trusts the server with a credential built from the presented trust, without evaluating it`,
        'The challenge handler answers with .useCredential and a credential created from the server trust, but never evaluates the trust or compares a certificate or public key.',
        'Evaluate the trust (SecTrustEvaluateWithError) against the system roots or a pinned certificate / public key, and call the completion handler with .cancelAuthenticationChallenge when it fails. Use .performDefaultHandling for everything else.'
      )
    );
  }
  return findings;
}

export const nativeTlsValidationRule: Rule = {
  id: 'TLS_VALIDATION_DISABLED_NATIVE',
  description: 'TLS certificate or host name validation disabled in native Android / iOS code',
  severity: Severity.HIGH,
  fileTypes: ['.java', '.kt', '.swift', '.m', '.mm'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const language = context.language;
    if (!language) return [];
    const masked = maskCode(context.fileContent, language);
    return language === 'java' || language === 'kotlin' ? androidFindings(context, masked) : iosFindings(context, masked);
  },
};
