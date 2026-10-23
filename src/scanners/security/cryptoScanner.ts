import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet, isLikelyIdentifier, looksLikeSecret } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import { identifierHasTerm, identifierEndsWithTerm } from '../../utils/identifierUtils.js';

// Names that tell us a digest protects something (credentials, tokens, signatures), as opposed to
// identifying content (checksums, ETags, cache keys, git shas, file integrity).
const SECURITY_CONTEXT_TERMS: ReadonlySet<string> = new Set([
  'password', 'passwd', 'pwd', 'passcode', 'pin',
  'token', 'jwt', 'bearer', 'secret', 'apikey', 'credential', 'otp', 'session',
  'signature', 'sign', 'signing', 'auth', 'authorization', 'authenticate', 'authentication',
]);

const DIGEST_CALLEES = new Set(['createHash', 'createHmac', 'digest', 'hash', 'getHash', 'digestStringAsync']);
const ALGORITHM_NAME_TERMS: ReadonlySet<string> = new Set(['algorithm', 'algo', 'alg', 'hash', 'digest']);

function nameOfFunction(fnPath: any): string | null {
  const node = fnPath.node;
  if (node.id?.name) return node.id.name;
  if (node.key?.name) return node.key.name; // class/object method
  const parent = fnPath.parent;
  if (parent?.type === 'VariableDeclarator' && parent.id?.type === 'Identifier') return parent.id.name;
  if (parent?.type === 'ObjectProperty' && parent.key?.name) return parent.key.name;
  if (parent?.type === 'AssignmentExpression') return nameOfTarget(parent.left);
  return null;
}

function nameOfTarget(node: any): string | null {
  if (node?.type === 'Identifier') return node.name;
  if (node?.type === 'MemberExpression' && !node.computed) return node.property?.name ?? null;
  return null;
}

/**
 * Does the statement (or expression-bodied arrow) containing this node, or the function around it,
 * talk about passwords/tokens/signatures? Collects identifier and property names only, so words in
 * strings and comments do not count.
 */
function hasSecurityContext(path: any): boolean {
  let scope: any = path;
  while (scope.parentPath && !scope.isStatement() && !scope.isFunction()) scope = scope.parentPath;

  const names: string[] = [];
  const collect = (node: any) => {
    if (!node || typeof node.type !== 'string') return;
    if (node.type === 'Identifier') names.push(node.name);
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key.endsWith('Comments')) continue;
      const child = node[key];
      if (Array.isArray(child)) child.forEach(collect);
      else if (child && typeof child.type === 'string') collect(child);
    }
  };
  collect(scope.node);

  const fn = path.getFunctionParent();
  if (fn) {
    const fnName = nameOfFunction(fn);
    if (fnName) names.push(fnName);
  }
  return names.some(n => identifierHasTerm(n, SECURITY_CONTEXT_TERMS));
}

const weakHashAlgorithmRule: Rule = {
  id: 'WEAK_HASH_ALGORITHM',
  description: 'Weak or deprecated cryptographic hash algorithm detected (MD5, SHA1)',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const report = (path: any, what: string, suggestion: string) => {
      const sensitive = hasSecurityContext(path);
      const line = getLineNumber(context.fileContent, path.node.start || 0);
      findings.push({
        ruleId: 'WEAK_HASH_ALGORITHM',
        description: sensitive
          ? what
          : `${what} (no password/token/signature context found; likely a checksum or cache key)`,
        severity: sensitive ? Severity.HIGH : Severity.LOW,
        ...(sensitive ? {} : { confidence: 'low' as const }),
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion,
      });
    };

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (node.callee.type === 'MemberExpression') {
          const objectName = node.callee.object.name;
          const propertyName = node.callee.property?.name;
          
          const weakAlgorithms = ['MD5', 'SHA1', 'md5', 'sha1'];
          
          if (
            (objectName === 'CryptoJS' || objectName === 'crypto') &&
            propertyName && weakAlgorithms.includes(propertyName)
          ) {
            report(
              path,
              `Weak hash algorithm detected: ${propertyName}`,
              'Use SHA-256 or stronger algorithms (SHA-384, SHA-512) instead of MD5 or SHA-1'
            );
          }
        }
      },

      // Crypto.CryptoDigestAlgorithm.SHA1 (expo-crypto)
      MemberExpression(path: any) {
        const { node } = path;
        if (
          !node.computed &&
          (node.property?.name === 'MD5' || node.property?.name === 'SHA1') &&
          /DigestAlgorithm$/.test(node.object?.property?.name ?? node.object?.name ?? '')
        ) {
          report(path, `Weak hash algorithm specified: ${node.property.name}`, 'Use SHA-256 or stronger algorithms instead of MD5 or SHA-1');
        }
      },
      
      StringLiteral(path: any) {
        const { node } = path;
        const value = node.value.toLowerCase();
        
        if (value !== 'md5' && value !== 'sha1' && value !== 'sha-1') return;

        // Only where the string actually selects an algorithm: createHash('md5'), { algorithm: 'sha1' }, const algo = 'md5'
        const parent = path.parent;
        let selectsAlgorithm = false;
        if (parent?.type === 'CallExpression' && parent.arguments.includes(node)) {
          const callee = parent.callee;
          const calleeName = callee.type === 'Identifier' ? callee.name : callee.property?.name;
          selectsAlgorithm = DIGEST_CALLEES.has(calleeName);
        } else if (parent?.type === 'ObjectProperty' && parent.value === node) {
          selectsAlgorithm = identifierHasTerm(parent.key?.name ?? parent.key?.value ?? '', ALGORITHM_NAME_TERMS);
        } else if (parent?.type === 'VariableDeclarator' && parent.init === node && parent.id?.type === 'Identifier') {
          selectsAlgorithm = identifierHasTerm(parent.id.name, ALGORITHM_NAME_TERMS);
        }

        if (selectsAlgorithm) {
          report(path, `Weak hash algorithm specified: "${node.value}"`, 'Use SHA-256 or stronger algorithms instead of MD5 or SHA-1');
        }
      },
    });

    return findings;
  },
};

const hardcodedEncryptionKeyRule: Rule = {
  id: 'HARDCODED_ENCRYPTION_KEY',
  description: 'Hardcoded encryption key or initialization vector (IV) detected',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      VariableDeclarator(path: any) {
        const { node } = path;
        
        if (node.id.type === 'Identifier') {
          const varName = node.id.name;
          const lowerVarName = varName.toLowerCase();
          
          const encryptionKeywords = ['encryptionkey', 'encryption_key', 'cryptokey', 'crypto_key', 'cipherkey', 'cipher_key'];
          const hasStrongEncryptionKeyword = encryptionKeywords.some(keyword => lowerVarName.includes(keyword));
          
          const isIvOrSalt = lowerVarName === 'iv' || lowerVarName === 'salt' || lowerVarName.endsWith('iv') || lowerVarName.endsWith('salt');
          
          if ((hasStrongEncryptionKeyword || isIvOrSalt) && node.init && node.init.type === 'StringLiteral') {
            const value = node.init.value;
            
            if (isLikelyIdentifier(value)) {
              return;
            }
            
            if (looksLikeSecret(value) || value.length > 20) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'HARDCODED_ENCRYPTION_KEY',
                description: `Hardcoded encryption key or IV in variable "${varName}"`,
                severity: Severity.HIGH,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Encryption keys should be generated dynamically or stored in secure environment variables, not hardcoded',
              });
            }
          }
        }
      },
      
      ObjectProperty(path: any) {
        const { node } = path;
        
        if (
          (node.key.type === 'Identifier' || node.key.type === 'StringLiteral') &&
          node.value.type === 'StringLiteral'
        ) {
          const keyName = node.key.type === 'Identifier' ? node.key.name : node.key.value;
          const lowerKeyName = keyName.toLowerCase();
          const value = node.value.value;
          
          if (isLikelyIdentifier(value)) {
            return;
          }
          
          const encryptionKeywords = ['encryptionkey', 'encryption_key', 'cryptokey', 'crypto_key', 'cipherkey', 'cipher_key'];
          const hasStrongEncryptionKeyword = encryptionKeywords.some(keyword => lowerKeyName.includes(keyword));
          
          const isIvOrSalt = lowerKeyName === 'iv' || lowerKeyName === 'salt';
          
          if ((hasStrongEncryptionKeyword || isIvOrSalt) && (looksLikeSecret(value) || value.length > 20)) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'HARDCODED_ENCRYPTION_KEY',
              description: `Hardcoded encryption key or IV in property "${keyName}"`,
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Encryption keys should be generated dynamically or stored in secure environment variables',
            });
          }
        }
      },
    });

    return findings;
  },
};

// crypto-js primitives that are broken or obsolete (AES is fine; its ECB mode is not)
const WEAK_CRYPTOJS_CIPHERS = new Set(['DES', 'TripleDES', 'RC4', 'RC4Drop', 'Rabbit', 'RabbitLegacy', 'Blowfish']);
const WEAK_CRYPTOJS_MODULES = /^crypto-js\/(?:tripledes|rc4|rc4drop|rabbit|rabbit-legacy|mode-ecb)$/;
const CIPHER_FACTORIES = new Set(['createCipheriv', 'createDecipheriv', 'createCipher', 'createDecipher']);
// Exact algorithm names passed to encrypt()/decrypt() of native crypto wrappers (react-native-aes-crypto, simple-crypto, ...)
const WEAK_ALGORITHM_ARG = /^(?:aes[-_/]?(?:128|192|256)?[-_/]?ecb(?:[-_/]\w+)*|des|3des|des3|des-ede3?(?:-cbc)?|triple-?des|rc4|rc2|blowfish|bf(?:-\w+)?)$/i;

function weakNodeAlgorithm(name: string): string | null {
  const alg = name.toLowerCase();
  if (alg.includes('ecb')) return 'ECB mode';
  if (/^des(?:\d|-|$)/.test(alg) || alg.startsWith('des-ede')) return alg.includes('ede3') || alg === 'des3' ? '3DES' : 'DES';
  if (alg.startsWith('rc4') || alg.startsWith('rc2')) return alg.slice(0, 3).toUpperCase();
  if (alg.startsWith('bf') || alg.includes('blowfish')) return 'Blowfish';
  return null;
}

function cryptoJsRoot(node: any): string | null {
  let cur = node;
  while (cur) {
    if (cur.type === 'Identifier') return cur.name;
    if (cur.type === 'MemberExpression') cur = cur.object;
    else if (cur.type === 'CallExpression') cur = cur.callee;
    else return null;
  }
  return null;
}

/** `CryptoJS.enc.Utf8.parse('0123456789abcdef')` or `Buffer.from('literal')`: a constant IV. */
function isLiteralIvExpression(node: any): boolean {
  if (!node) return false;
  if (node.type === 'StringLiteral') return node.value.length > 0;
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') return false;
  const first = node.arguments[0];
  const method = node.callee.property?.name;
  if (method === 'parse' && cryptoJsRoot(node.callee.object) === 'CryptoJS') return first?.type === 'StringLiteral';
  if (node.callee.object?.name === 'Buffer') {
    if (method === 'from') return first?.type === 'StringLiteral';
    if (method === 'alloc') return !node.arguments[1] || node.arguments[1]?.value === 0; // all-zero IV
  }
  return false;
}

const weakCipherOrModeRule: Rule = {
  id: 'WEAK_CIPHER_OR_MODE',
  description: 'Weak cipher (DES, 3DES, RC4, Blowfish), ECB block mode, or hardcoded IV',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    const reportWeak = (node: any, what: string) => {
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEAK_CIPHER_OR_MODE',
        description: `Weak cipher or block mode: ${what}`,
        severity: Severity.HIGH,
        confidence: 'high',
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Use AES-256-GCM (authenticated encryption) or AES-CBC/CTR with a random IV plus an HMAC. ECB leaks plaintext patterns; DES, 3DES, RC4 and Blowfish are broken or obsolete.',
      });
    };

    const reportIv = (node: any, how: string) => {
      const line = getLineNumber(context.fileContent, node.start || 0);
      findings.push({
        ruleId: 'WEAK_CIPHER_OR_MODE',
        description: `Hardcoded initialization vector (IV): ${how}`,
        severity: Severity.MEDIUM,
        confidence: 'medium',
        filePath: context.filePath,
        line,
        snippet: extractSnippet(context.fileContent, line),
        suggestion: 'Generate a fresh random IV for every encryption (crypto.randomBytes / getRandomValues) and store it next to the ciphertext. A constant IV makes encryption deterministic and breaks CBC/CTR/GCM guarantees.',
      });
    };

    traverse(context.ast, {
      ImportDeclaration(path: any) {
        if (WEAK_CRYPTOJS_MODULES.test(path.node.source.value)) reportWeak(path.node, `import of ${path.node.source.value}`);
      },

      MemberExpression(path: any) {
        const { node } = path;
        if (node.computed || node.object?.type === undefined) return;
        const prop = node.property?.name;
        // CryptoJS.mode.ECB
        if (
          prop === 'ECB' &&
          node.object.type === 'MemberExpression' &&
          node.object.property?.name === 'mode' &&
          cryptoJsRoot(node.object.object) === 'CryptoJS'
        ) {
          reportWeak(node, 'CryptoJS.mode.ECB');
          return;
        }
        // CryptoJS.DES / CryptoJS.TripleDES / CryptoJS.RC4 / CryptoJS.Rabbit
        if (node.object.type === 'Identifier' && node.object.name === 'CryptoJS' && WEAK_CRYPTOJS_CIPHERS.has(prop)) {
          reportWeak(node, `CryptoJS.${prop}`);
        }
      },

      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;
        const calleeName = callee.type === 'Identifier' ? callee.name : callee.property?.name;

        // crypto.createCipheriv('aes-128-ecb' | 'des-ede3' | 'rc4', key, iv)
        if (CIPHER_FACTORIES.has(calleeName)) {
          const alg = node.arguments[0];
          if (alg?.type === 'StringLiteral') {
            const weak = weakNodeAlgorithm(alg.value);
            if (weak) reportWeak(node, `${alg.value} (${weak})`);
          }
          const iv = node.arguments[2];
          if ((calleeName === 'createCipheriv' || calleeName === 'createDecipheriv') && isLiteralIvExpression(iv)) {
            reportIv(node, 'constant value passed to ' + calleeName);
          }
          return;
        }

        // Aes.encrypt(text, key, iv, 'AES-ECB'), RNSimpleCrypto.*.encrypt(..., 'des')
        if (calleeName === 'encrypt' || calleeName === 'decrypt') {
          for (const arg of node.arguments) {
            if (arg.type === 'StringLiteral' && WEAK_ALGORITHM_ARG.test(arg.value)) {
              reportWeak(node, `${calleeName}() with algorithm "${arg.value}"`);
              break;
            }
          }
        }
      },

      ObjectProperty(path: any) {
        const { node } = path;
        if (node.computed) return;
        const key = node.key?.name ?? node.key?.value;

        // { mode: 'ecb' }
        if ((key === 'mode' || key === 'blockMode' || key === 'cipherMode') && node.value.type === 'StringLiteral' && /^ecb$/i.test(node.value.value)) {
          reportWeak(node, `${key}: '${node.value.value}'`);
        }

        // { iv: CryptoJS.enc.Utf8.parse('1234567890123456') }
        if (key === 'iv' && isLiteralIvExpression(node.value)) {
          // A bare string `iv: '...'` is only unambiguous inside a CryptoJS call; HARDCODED_ENCRYPTION_KEY covers long ones elsewhere.
          const insideCryptoJs =
            node.value.type !== 'StringLiteral' ||
            (path.parentPath?.parent?.type === 'CallExpression' && cryptoJsRoot(path.parentPath.parent.callee) === 'CryptoJS');
          if (insideCryptoJs) reportIv(node, 'iv option set to a constant');
        }
      },

      VariableDeclarator(path: any) {
        const { node } = path;
        // const iv = CryptoJS.enc.Utf8.parse('...') / Buffer.from('...')
        if (
          node.id?.type === 'Identifier' &&
          node.init?.type === 'CallExpression' &&
          identifierEndsWithTerm(node.id.name, new Set(['iv'])) &&
          isLiteralIvExpression(node.init)
        ) {
          reportIv(node, `${node.id.name} is a constant`);
        }
      },
    });

    return findings;
  },
};

const customCryptoImplementationRule: Rule = {
  id: 'CUSTOM_CRYPTO_IMPLEMENTATION',
  description: 'Custom/DIY cryptographic implementation instead of standard library',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.ast) {
      return findings;
    }

    const filePath = context.filePath.toLowerCase();
    if (
      filePath.includes('node_modules') ||
      filePath.includes('.test.') ||
      filePath.includes('.spec.') ||
      filePath.includes('/__tests__/')
    ) {
      return findings;
    }

    // Check for functions that implement crypto primitives
    traverse(context.ast, {
      FunctionDeclaration(path: any) {
        const { node } = path;
        if (!node.id) return;

        const funcName = node.id.name.toLowerCase();
        const diyCryptoPatterns = [
          /^(custom|my|simple|basic|diy)?(encrypt|decrypt|hash|cipher)/,
          /^(xor|rot13|caesar|vigenere)(encrypt|decrypt|cipher)?$/,
          /^(base64)?(encode|decode)(password|token|secret)/,
        ];

        if (diyCryptoPatterns.some(p => p.test(funcName))) {
          // Check if it actually implements crypto (not just a wrapper around a library)
          const funcBody = context.fileContent.substring(node.start || 0, node.end || 0).toLowerCase();
          const usesLibrary =
            funcBody.includes('cryptojs') ||
            funcBody.includes('crypto.') ||
            funcBody.includes('expo-crypto') ||
            funcBody.includes('react-native-aes') ||
            funcBody.includes('tweetnacl') ||
            funcBody.includes('sjcl') ||
            funcBody.includes('forge');

          if (!usesLibrary) {
            const line = getLineNumber(context.fileContent, node.start || 0);

            findings.push({
              ruleId: 'CUSTOM_CRYPTO_IMPLEMENTATION',
              description: `Custom cryptographic function "${node.id.name}" - likely insecure implementation`,
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Never implement custom cryptographic algorithms. Use established libraries like CryptoJS, expo-crypto, react-native-aes-gcm-crypto, or tweetnacl.',
            });
          }
        }
      },

      // Detect XOR-based "encryption"
      CallExpression(path: any) {
        const { node } = path;
        if (node.callee.type === 'Identifier') {
          const funcName = node.callee.name.toLowerCase();

          // XOR encryption pattern
          if (funcName.includes('xor') && (funcName.includes('encrypt') || funcName.includes('cipher') || funcName.includes('decode'))) {
            const line = getLineNumber(context.fileContent, node.start || 0);

            findings.push({
              ruleId: 'CUSTOM_CRYPTO_IMPLEMENTATION',
              description: `XOR-based encryption "${node.callee.name}" - trivially breakable`,
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'XOR encryption is not secure. Use AES-GCM via CryptoJS or react-native-aes-gcm-crypto for proper encryption.',
            });
          }
        }
      },
    });

    return findings;
  },
};

export const cryptoRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [weakHashAlgorithmRule, hardcodedEncryptionKeyRule, weakCipherOrModeRule, customCryptoImplementationRule],
};
