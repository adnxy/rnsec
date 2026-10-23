import * as LocalAuthentication from 'expo-local-authentication';
const pin = '1234';
export async function unlock() {
  await LocalAuthentication.authenticateAsync({ fallbackLabel: 'Use passcode' });
  return pin;
}
