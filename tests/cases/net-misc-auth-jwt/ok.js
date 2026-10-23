import AsyncStorage from '@react-native-async-storage/async-storage';
import jwtDecode from 'jwt-decode';
export async function load() {
  const t = await AsyncStorage.getItem('jwt_token');
  return jwtDecode(t).exp;
}
export async function loadAccess() {
  const t = await AsyncStorage.getItem('access_token');
  return t;
}
