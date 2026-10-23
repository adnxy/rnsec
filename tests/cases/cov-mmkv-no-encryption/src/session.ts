import { createMMKV } from 'react-native-mmkv';

const storage = createMMKV();

export function saveSession(token: string) {
  storage.set('authToken', token);
}
