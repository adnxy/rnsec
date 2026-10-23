import * as AuthSession from 'expo-auth-session';
import { authorize } from 'react-native-app-auth';

export const request = new AuthSession.AuthRequest({
  clientId: 'abc',
  usePKCE: false,
  responseType: AuthSession.ResponseType.Token,
  redirectUri: 'myapp://cb',
});
export const url = 'https://idp.example.com/authorize?client_id=abc&response_type=token&redirect_uri=myapp://cb';
export const cfg = { issuer: 'https://idp.example.com', clientId: 'abc', redirectUrl: 'myapp://cb', scopes: ['openid'], useNonce: false };
export const login = () => authorize(cfg);
