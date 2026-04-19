import AsyncStorage from '@react-native-async-storage/async-storage';

// Rule: session management has no limits on duration
// Auth file with login logic but no safeguards
export async function login(username: string, password: string) {
  const response = await fetch('https://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });

  const data = await response.json();

  // Store token without any duration limits
  await AsyncStorage.setItem('session_token', data.token);
  await AsyncStorage.setItem('user_data', JSON.stringify(data.user));

  return data;
}

export async function authenticate() {
  const token = await AsyncStorage.getItem('session_token');
  // No duration or validity check
  return !!token;
}
