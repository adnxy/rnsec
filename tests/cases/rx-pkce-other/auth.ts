import { authorize } from 'react-native-app-auth';

export const login = () =>
  authorize({
    issuer: 'https://idp.example.com',
    clientId: 'abc',
    redirectUrl: 'myapp://cb',
    usePKCE: false,
  });
