import AsyncStorage from '@react-native-async-storage/async-storage';
import * as LocalAuthentication from 'expo-local-authentication';

export async function loadTokens() {
  const push = await AsyncStorage.getItem('fcm_token');
  const device = await AsyncStorage.getItem('device_token');
  const csrf = await AsyncStorage.getItem('csrf_token');
  return [push, device, csrf];
}
export async function loadJwt() {
  return AsyncStorage.getItem('jwt_token');
}
export const urls = {
  hint: 'Do not pass ?token= in the http query string',
  real: 'https://api.example.com/me?token=abc',
};
export function tpl(t) {
  return `https://api.example.com/me?access_token=${t}`;
}
export const pinning = {
  a: { trustAllCerts: false },
  b: { trustAllCerts: true },
  c: { rejectUnauthorized: false },
  d: { rejectUnauthorized: true },
};
export async function unlock() {
  // TODO password = 'hunter2' fallback
  const spin = 'x';
  const shipping = 'y';
  const mapping = 'z';
  await LocalAuthentication.authenticateAsync({ fallbackLabel: 'Use passcode' });
  return [spin, shipping, mapping];
}
export const labels = { pin: 'PIN', password: 'Enter your password', passcode: 'Passcode' };
export const message = 'Session expired, please sign in again';
