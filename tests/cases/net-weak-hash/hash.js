import CryptoJS from 'crypto-js';
import crypto from 'crypto';

export function etagFor(body) {
  return crypto.createHash('md5').update(body).digest('hex');
}
export function cacheKey(url) {
  return CryptoJS.MD5(url).toString();
}
export function gitSha(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex');
}
export function hashPassword(pwd) {
  return CryptoJS.MD5(pwd).toString();
}
export function signRequest(payload) {
  const signature = crypto.createHash('sha1').update(payload).digest('hex');
  return signature;
}
export function makeLoginToken(user) {
  return crypto.createHash('md5').update(user).digest('hex');
}
const unrelated = ['md5', 'sha1'];
export { unrelated };
import * as Crypto from 'expo-crypto';
export async function digestPassword(password) {
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, password);
}
export async function digestAsset(data) {
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.MD5, data);
}
