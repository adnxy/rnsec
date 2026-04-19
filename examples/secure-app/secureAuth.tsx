import * as SecureStore from 'expo-secure-store';

// SAFE: Auth file WITH session timeout/expiry logic
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

export async function login(username: string, password: string) {
  const response = await fetch('https://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });

  const data = await response.json();

  // Store token with expiry timestamp
  await SecureStore.setItemAsync('session_token', data.token);
  await SecureStore.setItemAsync('token_expiry', String(Date.now() + SESSION_TIMEOUT));

  return data;
}

export async function authenticate() {
  const token = await SecureStore.getItemAsync('session_token');
  const expiry = await SecureStore.getItemAsync('token_expiry');

  if (!token || !expiry) return false;

  // Check session timeout
  if (Date.now() > Number(expiry)) {
    await autoLogout();
    return false;
  }

  return true;
}

async function autoLogout() {
  await SecureStore.deleteItemAsync('session_token');
  await SecureStore.deleteItemAsync('token_expiry');
}
