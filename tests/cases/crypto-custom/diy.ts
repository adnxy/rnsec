import { md5Kdf, aesCbc } from './vendor';
import { sha256 } from '@noble/hashes/sha256';
import { xorEncrypt as importedXor } from './vendor';

// positives: primitives in the body
export function customEncrypt(data: string, key: string) {
  let out = '';
  for (let i = 0; i < data.length; i++) out += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  return out;
}
export const rotateHash = (x: number) => ((x << 5) | (x >>> 27)) + 0x9e3779b9;
const SBOX = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118];
export function cipherBlock(bytes: number[]) { return bytes.map(b => SBOX[b & 15]); }
export function encryptBackup(data: string, password: string) {
  const kdf = md5Kdf(password, 'salt');
  const key = kdf.subarray(0, 32);
  const iv = kdf.subarray(32);
  return aesCbc(key, iv).encrypt(data);
}
export function xorWrapper(a: string) { return xorEncrypt(a, 'k'); }
function xorEncrypt(a: string, k: string) { return a + k; }

// negatives
export function hashContent(content: string) { return sha256(content); }
export function HashtagIcon() { return null; }
export function decryptionWorker_done() { return 1 << 3 >> 1 ^ 2; }
export function forgetPassword(user: string) { return user.length ^ 1; }
export function encryptWithLibrary(data: string, key: string) { return CryptoJS.AES.encrypt(data, key).toString(); }
export function encryptStrong(data: string, key: string) {
  const derived = pbkdf2(key, 'salt');
  return aesCbc(derived, 'iv').encrypt(data);
}
export function callImported(a: string) { return importedXor(a, 'k'); }
export const hashBucket = (a: number, b: number) => ((a << 3) ^ b) & 255;
