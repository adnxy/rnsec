import { useAuthRequest } from 'expo-auth-session';

export function useLogin() {
  return useAuthRequest(
    {
      clientId: 'abc',
      usePKCE: false,
      redirectUri: 'myapp://cb',
    },
    discovery
  );
}
