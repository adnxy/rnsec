import * as SecureStore from 'expo-secure-store';

export async function save(value: string) {
  await SecureStore.setItemAsync('auth_token', value, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK });
  await SecureStore.setItemAsync('refresh_token', value, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY });
  await SecureStore.setItemAsync('auth_token', value, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
}
