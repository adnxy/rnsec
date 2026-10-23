import { MMKV } from 'react-native-mmkv';
import * as SecureStore from 'expo-secure-store';

export const prefs = new MMKV({ id: 'prefs' });
export function save(theme: string, expiresAt: number) {
  prefs.set('theme', theme);
  prefs.set('onboardingSeen', true);
  prefs.set('tokenizerVersion', 2);
  prefs.set('tokenExpiresAt', expiresAt);
  prefs.set('sessionCount', 3);
}

const key = SecureStore.getItem('mmkv-key') as string;
export const secure = new MMKV({ id: 'secure', encryptionKey: key });
secure.set('authToken', 'value');
