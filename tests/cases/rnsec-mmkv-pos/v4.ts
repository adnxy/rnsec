import { createMMKV } from 'react-native-mmkv';
const store = createMMKV({ id: 'auth' });
const KEYS = { REFRESH_TOKEN: 'rt' };
export const save = (v: string) => store.set(KEYS.REFRESH_TOKEN, v);
