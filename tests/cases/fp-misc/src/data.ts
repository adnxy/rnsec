import * as LocalAuthentication from 'expo-local-authentication';

export async function load(response: Response) {
  const parsed = JSON.parse(await response.text());
  return parsed;
}

export function runDynamic(code: string) {
  return eval(code);
}

export async function unlock() {
  const result = await LocalAuthentication.authenticateAsync({ promptMessage: 'Unlock' });
  return result.success;
}

export function report(error: Error) {
  console.error(error);
}
