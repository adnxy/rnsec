import * as SecureStore from 'expo-secure-store';

// EXPO_SECURE_STORE_WEAK_OPTIONS - Rule should detect this
export async function storeAuthToken(token: string) {
  await SecureStore.setItemAsync('auth_token', token, {
    keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK,
  });
}

export async function storePassword(password: string) {
  await SecureStore.setItemAsync('password', password, {
    keychainAccessible: SecureStore.ALWAYS,
  });
}
