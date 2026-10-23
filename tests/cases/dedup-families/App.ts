import { MMKV } from 'react-native-mmkv';
import jwt from 'jsonwebtoken';

export const storage = new MMKV({ id: 'app', encryptionKey: 'Hw5nR8cT2yQ7vB3xZk9LmP4dFg' });

export const signOptions = { secret: 'Zk8Qm3Rt7LpW9sYb3HcD5fGj6KaE1uT0' };

export function token() {
  return jwt.sign({ id: 1 }, 'Zk8Qm3Rt7LpW9sYb3HcD5fGj6KaE1uT0');
}

export function report(error: Error, token: string) {
  console.log('auth failed', token, error);
}
