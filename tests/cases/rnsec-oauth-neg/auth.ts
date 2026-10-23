import * as AuthSession from 'expo-auth-session';

export const request = new AuthSession.AuthRequest({
  clientId: 'abc',
  usePKCE: true,
  responseType: AuthSession.ResponseType.Code,
  redirectUri: 'myapp://cb',
  extraParams: { useNonce: 'false' },
});
export const url = 'https://idp.example.com/authorize?client_id=abc&response_type=code&redirect_uri=myapp://cb';
export const loose = { useNonce: false };
