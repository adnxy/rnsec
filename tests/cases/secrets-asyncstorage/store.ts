import AS from '@react-native-async-storage/async-storage';
import { createJSONStorage } from 'zustand/middleware';

const storage = createJSONStorage(() => AS);
const TOKEN_KEY = 'auth_token';
const KEYS = { email: 'user_email' };

async function persist(k: string, v: string) {
  await AS.setItem(k, v);
}

export async function save(token: string) {
  await AS.setItem('authToken', token);          // L13 camelCase alias
  await storage.setItem('refresh_token', token);  // L14 derived from alias via wrapper call
  await AS.setItem(TOKEN_KEY, token);             // L15 const key
  await persist('password', token);               // L16 in-file wrapper
  await AS.setItem(KEYS.email, 'x@y.z');          // L17 PII through object const
  await AS.multiSet([['session_id', 'a'], ['theme', 'dark']]); // L18
  await AS.setItem(`user_${token}_secret`, token); // L19 template
}

export async function benign(v: string) {
  await AS.setItem('tokenizer_enabled', v);
  await AS.setItem('bypass_count', v);
  await AS.setItem('token_expiry', v);
  await AS.setItem('theme', v);
  await AS.setItem('ip_address', v);
  await AS.setItem('email_verified', v);
}
