import * as Keychain from 'react-native-keychain';
import * as SecureStore from 'expo-secure-store';
import { setItemAsync, ALWAYS } from 'expo-secure-store';

export async function save(t) {
  await Keychain.setGenericPassword('u', t, { accessible: Keychain.ACCESSIBLE.ALWAYS });
  await SecureStore.setItemAsync('k', t, { keychainAccessible: SecureStore.ALWAYS_THIS_DEVICE_ONLY });
  await setItemAsync('k', t, { keychainAccessible: ALWAYS });
  await Keychain.setInternetCredentials('s', 'u', t, { accessible: 'AccessibleAlways' });
}
