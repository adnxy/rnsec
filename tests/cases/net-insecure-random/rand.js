export function jitter(base) {
  const delay = base * Math.random();
  return delay;
}
export function pickColor() {
  const color = '#' + Math.floor(Math.random() * 0xffffff).toString(16);
  return color;
}
export function chartPoint() {
  return { x: Math.random(), y: Math.random() };
}
export function shuffle(list) {
  return list.sort(() => Math.random() - 0.5);
}
export function listKey() {
  const key = Math.random();
  return key;
}
export const refreshTokenDelay = Math.random() * 100;
export function retryTokenFetch() {
  const wait = 100 + Math.random() * 50;
  return wait;
}
const tokenExpiresAt = Date.now() + 3600;
const lastSessionStart = Date.now();
export { tokenExpiresAt, lastSessionStart };

export function generateSessionId() {
  const sessionId = Math.random().toString(36).substring(2);
  return sessionId;
}
export function makeToken() {
  const token = 'TOKEN-' + Math.random().toString(36);
  return token;
}
export const makeOtp = () => Math.floor(100000 + Math.random() * 900000);
export function build(user) {
  return { nonce: Math.random().toString(16), user };
}
export function uuid() {
  return 'xxxxxxxx'.replace(/x/g, () => ((Math.random() * 16) | 0).toString(16));
}
export function storeSecret(store) {
  store.apiKey = Math.random().toString(36);
}
export function stamp() {
  const sessionKey = 'k' + Date.now();
  return sessionKey;
}
const CHARS = 'abcdef0123456789';
export function generateToken(n) {
  let r = '';
  for (let i = 0; i < n; i++) r += CHARS[Math.floor(Math.random() * CHARS.length)];
  return r;
}
export function createSecretString(n) {
  return Array.from({ length: n }, () => CHARS[Math.floor(Math.random() * CHARS.length)]).join('');
}
export function generateAnimationFrame() {
  let r = '';
  r += Math.random();
  return r;
}
