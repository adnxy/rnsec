import * as SecureStore from 'expo-secure-store';

export async function save(value: string) {
  await SecureStore.setItemAsync('auth_token', value, { keychainAccessible: SecureStore.ALWAYS });
  await SecureStore.setItemAsync('theme', value, { keychainAccessible: SecureStore.ALWAYS_THIS_DEVICE_ONLY });
  await SecureStore.setItemAsync('userAgent', value, { keychainAccessible: SecureStore['ALWAYS'] });
}

export const shared = { keychainAccessible: SecureStore.ALWAYS };
