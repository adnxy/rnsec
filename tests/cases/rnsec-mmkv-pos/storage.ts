import { MMKV } from 'react-native-mmkv';

export const storage = new MMKV({ id: 'user' });

export function saveSession(token: string) {
  storage.set('authToken', token);
}

export const vault = new MMKV({ id: 'vault', encryptionKey: 'static-literal-key' });
