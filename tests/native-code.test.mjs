import { test } from 'node:test';
import assert from 'node:assert/strict';
import { maskComments, maskStrings, maskCode, matchingBrace, findFunctions, isTrivialBody, languageForPath } from '../dist/utils/nativeCode.js';
import { collectNativeDevOnlyRanges } from '../dist/utils/nativeGuards.js';
import { isLineInRanges } from '../dist/utils/devGuards.js';

test('languageForPath maps native extensions', () => {
  assert.equal(languageForPath('A.java'), 'java');
  assert.equal(languageForPath('A.kt'), 'kotlin');
  assert.equal(languageForPath('A.swift'), 'swift');
  assert.equal(languageForPath('A.m'), 'objc');
  assert.equal(languageForPath('A.mm'), 'objc');
  assert.equal(languageForPath('A.ts'), undefined);
});

test('maskComments blanks comments, keeps offsets and newlines, ignores // in strings', () => {
  const code = 'a(); // x\nString u = "https://x.com/a"; /* b\n c */ d();';
  const masked = maskComments(code, 'java');
  assert.equal(masked.length, code.length);
  assert.equal(masked.split('\n').length, code.split('\n').length);
  assert.ok(masked.includes('"https://x.com/a"'));
  assert.ok(!masked.includes('// x') && !masked.includes('/* b'));
  assert.ok(masked.includes('a();') && masked.includes('d();'));
});

test('maskComments: Swift nested block comments and string interpolation', () => {
  const code = 'let a = 1 /* outer /* inner */ still */ let b = "x \\(f("//y")) /* z */"\n';
  const masked = maskComments(code, 'swift');
  assert.ok(!masked.includes('outer') && !masked.includes('still'));
  assert.ok(masked.includes('let b = "x \\(f("//y")) /* z */"'));
});

test('maskComments: Kotlin templates, raw strings and char literals', () => {
  const code = 'val a = "${foo("//q")}" // c\nval r = """ // not a comment """\nval c = \'"\' // after\n';
  const masked = maskComments(code, 'kotlin');
  assert.ok(masked.includes('"${foo("//q")}"'));
  assert.ok(masked.includes('""" // not a comment """'));
  assert.ok(!masked.includes('after') && !masked.includes('// c'));
});

test('maskStrings blanks contents but keeps quotes; maskCode does both', () => {
  const code = 'x = "a{b}"; // c {\ny = \'}\';';
  assert.equal(maskStrings(code, 'java'), 'x = "    "; // c {\ny = \' \';');
  assert.equal(maskCode(code, 'java'), 'x = "    ";' + ' '.repeat(7) + '\ny = \' \';');
});

test('matchingBrace on masked code', () => {
  const code = 'void f() { if (a) { s("}"); } // }\n }';
  const masked = maskCode(code, 'java');
  const open = code.indexOf('{');
  assert.equal(matchingBrace(masked, open), code.length - 1);
  assert.equal(matchingBrace(masked, 0), -1);
});

const java = `
public class A {
  // void onReceivedSslError(fake) { }
  @Override
  public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) {
    h.proceed();
  }
  public void checkServerTrusted(X509Certificate[] c, String t) throws CertificateException {
  }
  void caller() {
    checkServerTrusted(a, b);
    new Thread() { public void run() { x(); } };
  }
  abstract void checkServerTrusted();
}
`;

test('findFunctions (Java): definitions only, with body and signature', () => {
  const fns = findFunctions(java, 'java', /^(onReceivedSslError|checkServerTrusted)$/);
  assert.deepEqual(fns.map(f => f.name), ['onReceivedSslError', 'checkServerTrusted']);
  const [ssl, trust] = fns;
  assert.ok(ssl.body.includes('h.proceed();'));
  assert.equal(java[ssl.bodyEnd], '}');
  assert.equal(java[ssl.bodyStart - 1], '{');
  assert.ok(ssl.signature.startsWith('@Override'));
  assert.equal(isTrivialBody(ssl.body), false);
  assert.equal(isTrivialBody(trust.body), true);
  assert.equal(java.slice(ssl.start, ssl.start + 9), '@Override');
});

const kotlin = `
class A : X509TrustManager {
  override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
    // trust everything
  }
  override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
  fun String.shout(): String = this.uppercase()
  override fun onReceivedSslError(v: WebView?, h: SslErrorHandler?, e: SslError?) {
    h?.proceed()
  }
  override fun checkClientTrusted(c: Array<X509Certificate>?, t: String?) = Unit
  fun lines() =
    foo()
      .bar()
  interface I { fun nobody(x: Int) }
}`;

test('findFunctions (Kotlin): block and expression bodies, receivers', () => {
  const by = Object.fromEntries(findFunctions(kotlin, 'kotlin', /.*/).map(f => [f.name, f]));
  assert.equal(isTrivialBody(by.checkServerTrusted.body), true);
  assert.equal(by.getAcceptedIssuers.body.trim(), 'arrayOf()');
  assert.equal(by.shout.body.trim(), 'this.uppercase()');
  assert.equal(by.onReceivedSslError.body.trim(), 'h?.proceed()');
  assert.equal(isTrivialBody(by.checkClientTrusted.body), true);
  assert.equal(by.lines.body.replace(/\s+/g, ''), 'foo().bar()');
  assert.equal(by.nobody, undefined);
  assert.ok(by.checkServerTrusted.signature.startsWith('override fun'));
});

const swift = `
class D: NSObject, URLSessionDelegate {
    // func urlSession(fake)
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
    func other() throws -> [String: Int]
    {
        return [:]
    }
}
protocol P { func required(_ x: Int) -> Int
  func second() }
`;

test('findFunctions (Swift): multi-line signatures, closure types, Allman braces, protocol requirements', () => {
  const fns = findFunctions(swift, 'swift', /.*/);
  assert.deepEqual(fns.map(f => f.name), ['urlSession', 'other']);
  assert.ok(fns[0].body.includes('useCredential'));
  assert.equal(swift[fns[0].bodyEnd], '}');
  assert.ok(fns[1].body.includes('return [:]'));
});

const objc = `
@interface A : NSObject
- (void)URLSession:(NSURLSession *)s didReceiveChallenge:(NSURLAuthenticationChallenge *)c completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))h;
@end
@implementation A
- (void)URLSession:(NSURLSession *)s didReceiveChallenge:(NSURLAuthenticationChallenge *)c
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))h {
  h(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:c.protectionSpace.serverTrust]);
}
+ (void)viewDidLoad {
}
@end
`;

test('findFunctions (Objective-C): selector names, declarations skipped', () => {
  const fns = findFunctions(objc, 'objc', /^URLSession|viewDidLoad/);
  assert.deepEqual(fns.map(f => f.name), ['URLSession:didReceiveChallenge:completionHandler:', 'viewDidLoad']);
  assert.ok(fns[0].body.includes('credentialForTrust'));
  assert.equal(isTrivialBody(fns[1].body), true);
  assert.equal(objc[fns[0].start], '-');
});

test('isTrivialBody', () => {
  for (const body of ['', '  \n', '// nothing', '/* a */ return;', 'return', ' Unit ', 'return Unit;', ';']) {
    assert.equal(isTrivialBody(body), true, JSON.stringify(body));
  }
  for (const body of ['return true;', 'x();', '// c\nreturn false;', 'returned', 'Units']) {
    assert.equal(isTrivialBody(body), false, JSON.stringify(body));
  }
});

const inRange = (ranges, line) => isLineInRanges(line, ranges);

test('native guards: Swift #if DEBUG with #else and nesting', () => {
  const code = [
    'let a = 1',            // 1
    '#if DEBUG',            // 2
    'print(a)',             // 3
    '#if os(iOS)',          // 4
    'print(b)',             // 5
    '#endif',               // 6
    '#else',                // 7
    'print(release)',       // 8
    '#endif',               // 9
    '// #if DEBUG',         // 10
    'print(c)',             // 11
    '#if !DEBUG',           // 12
    'print(prod)',          // 13
    '#else',                // 14
    'print(dev)',           // 15
    '#endif',               // 16
    '#if DEBUG || STAGING', // 17
    'print(maybe)',         // 18
    '#endif',               // 19
    '#if DEBUG && FOO',     // 20
    'print(dbg)',           // 21
    '#elseif BAR',          // 22
    'print(bar)',           // 23
    '#else',                // 24
    'print(rest)',          // 25
    '#endif',
  ].join('\n');
  const r = collectNativeDevOnlyRanges(code, 'swift');
  const dev = [3, 4, 5, 6, 15, 21];
  const prod = [1, 8, 11, 13, 18, 23, 25];
  dev.forEach(l => assert.ok(inRange(r, l), `line ${l} should be dev-only`));
  prod.forEach(l => assert.ok(!inRange(r, l), `line ${l} should not be dev-only`));
});

test('native guards: Objective-C #ifdef / #ifndef / defined()', () => {
  const code = [
    '#ifdef DEBUG',          // 1
    'NSLog(@"a");',          // 2
    '#else',                 // 3
    'prod();',               // 4
    '#endif',                // 5
    '#ifndef DEBUG',         // 6
    'prod2();',              // 7
    '#else',                 // 8
    'dev2();',               // 9
    '#endif',                // 10
    '#if defined(DEBUG) && DEBUG', // 11
    'dev3();',               // 12
    '#endif',
  ].join('\n');
  const r = collectNativeDevOnlyRanges(code, 'objc');
  [2, 9, 12].forEach(l => assert.ok(inRange(r, l), `line ${l}`));
  [4, 7].forEach(l => assert.ok(!inRange(r, l), `line ${l}`));
});

test('native guards: BuildConfig.DEBUG blocks (Java and Kotlin)', () => {
  const code = [
    'void f() {',                                    // 1
    '  if (BuildConfig.DEBUG) {',                    // 2
    '    Log.d(T, "dev");',                          // 3
    '  } else {',                                    // 4
    '    Log.d(T, "prod");',                         // 5
    '  }',                                           // 6
    '  if (BuildConfig.DEBUG && flag) {',            // 7
    '    a();',                                      // 8
    '  }',                                           // 9
    '  if (flag || BuildConfig.DEBUG) { b(); }',     // 10
    '  if (!BuildConfig.DEBUG) { c(); } else { d(); }', // 11
    '  if (BuildConfig.DEBUG) Log.d(T, "one");',     // 12
    '  // if (BuildConfig.DEBUG) {',                 // 13
    '  e();',                                        // 14
    '  if (BuildConfig.DEBUG) { s("}"); }',          // 15
    '  after();',                                    // 16
    '}',
  ].join('\n');
  for (const lang of ['java', 'kotlin']) {
    const r = collectNativeDevOnlyRanges(code, lang);
    [3, 8, 12, 15].forEach(l => assert.ok(inRange(r, l), `${lang} line ${l} should be dev-only`));
    [1, 5, 10, 14, 16].forEach(l => assert.ok(!inRange(r, l), `${lang} line ${l} should not be dev-only`));
  }
  const r = collectNativeDevOnlyRanges(code, 'java');
  assert.ok(!inRange(r, 4), 'the "} else {" line of a DEBUG block stays production code');
});
