import CryptoJS from 'crypto-js';
import crypto from 'crypto';
import Aes from 'react-native-aes-crypto';

// CryptoJS.mode.ECB, CryptoJS.DES.encrypt('x', 'k') in a comment are not code
export const safeAes = (data, key, iv) =>
  CryptoJS.AES.encrypt(data, key, { iv, mode: CryptoJS.mode.CBC });
export function safeNode(key, iv) {
  return crypto.createCipheriv('aes-256-gcm', key, iv);
}
export function randomIv(key) {
  return crypto.createCipheriv('aes-256-cbc', key, crypto.randomBytes(16));
}
export const safeNative = (text, key, iv) => Aes.encrypt(text, key, iv, 'aes-256-cbc');
export const desc = { description: 'DES and ECB are weak', mode: 'cbc' };

export const ecb = (data, key) =>
  CryptoJS.AES.encrypt(data, key, { mode: CryptoJS.mode.ECB });
export const des = (data, key) => CryptoJS.DES.encrypt(data, key).toString();
export const tdes = (data, key) => CryptoJS.TripleDES.encrypt(data, key).toString();
export const rc4 = (data, key) => CryptoJS.RC4.encrypt(data, key).toString();
export function nodeEcb(key) {
  return crypto.createCipheriv('aes-128-ecb', key, null);
}
export function nodeDes(key, iv) {
  return crypto.createCipheriv('des-ede3', key, iv);
}
export const nativeEcb = (text, key, iv) => Aes.encrypt(text, key, iv, 'AES-ECB');
export function staticIvCryptoJs(data, key) {
  return CryptoJS.AES.encrypt(data, key, { iv: CryptoJS.enc.Utf8.parse('1234567890123456') });
}
export function staticIvNode(key) {
  return crypto.createCipheriv('aes-256-cbc', key, Buffer.from('0123456789abcdef'));
}
const DEFAULT_IV = CryptoJS.enc.Utf8.parse('abcdefghijklmnop');
const div = Buffer.from('not an iv');
export const bf = (d, k) => CryptoJS.Blowfish.encrypt(d, k);
export { DEFAULT_IV, div };
