import * as SecureStore from 'expo-secure-store';

// SAFE: SecureStore with strong accessibility options
export async function storeAuthToken(token: string) {
  await SecureStore.setItemAsync('auth_token', token, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

// SAFE: SecureStore without options (defaults are secure)
export async function storeRefreshToken(refreshToken: string) {
  await SecureStore.setItemAsync('refresh_token', refreshToken);
}

// SAFE: Non-sensitive key with weak options - should NOT trigger
export async function storeTheme(theme: string) {
  await SecureStore.setItemAsync('app_theme', theme, {
    keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK,
  });
}
