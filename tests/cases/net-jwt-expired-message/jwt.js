import AsyncStorage from '@react-native-async-storage/async-storage';
export async function load() {
  const t = await AsyncStorage.getItem('jwt_token');
  if (!t) throw new Error('Session expired');
  return t;
}
