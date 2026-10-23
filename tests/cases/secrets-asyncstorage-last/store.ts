import AsyncStorage from '@react-native-async-storage/async-storage';

export async function save(value: string) {
  await AsyncStorage.setItem('last_token', value);
  await AsyncStorage.setItem('lastToken', value);
  await AsyncStorage.setItem('lastAuthToken', value);
  await AsyncStorage.setItem('last_access_token', value);
  await AsyncStorage.setItem('lastSessionToken', value);
  await AsyncStorage.setItem('LAST_REFRESH_TOKEN', value);
  await AsyncStorage.setItem('token', value);
  await AsyncStorage.setItem('authToken', value);
  await AsyncStorage.setItem('auth_token', value);
  await AsyncStorage.setItem('refresh_token', value);
  await AsyncStorage.setItem('password', value);
  await AsyncStorage.setItem('api_key', value);
  await AsyncStorage.setItem('session_id', value);
  await AsyncStorage.setItem('lastLogin', value);
  await AsyncStorage.setItem('last_login', value);
  await AsyncStorage.setItem('last_token_refresh', value);
  await AsyncStorage.setItem('lastTokenRefreshAt', value);
  await AsyncStorage.setItem('lastPasswordChange', value);
  await AsyncStorage.setItem('last_password_reset', value);
  await AsyncStorage.setItem('token_expiry', value);
  await AsyncStorage.setItem('token_type', value);
  await AsyncStorage.setItem('password_hint', value);
  await AsyncStorage.setItem('show_password', value);
  await AsyncStorage.setItem('has_pin', value);
  await AsyncStorage.setItem('tokenizer_enabled', value);
  await AsyncStorage.setItem('notification_token', value);
  await AsyncStorage.setItem('lastEmail', value);
  await AsyncStorage.setItem('last_phone_number', value);
}
