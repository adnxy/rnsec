import * as Keychain from 'react-native-keychain';
import * as SecureStore from 'expo-secure-store';

export async function save(t) {
  await Keychain.setGenericPassword('u', t, { accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
  await SecureStore.setItemAsync('k', t, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY });
}
