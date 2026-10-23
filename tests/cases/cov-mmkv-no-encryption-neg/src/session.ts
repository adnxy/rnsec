import { createMMKV } from 'react-native-mmkv';

const storage = createMMKV({ id: 'session', encryptionKey: 'derived-at-runtime' });

export function saveSession(token: string) {
  storage.set('authToken', token);
}
