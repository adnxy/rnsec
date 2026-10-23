import { fetch as pinnedFetch } from 'react-native-ssl-pinning';
export const a = pinnedFetch('https://api.example-corp.com', { method: 'GET', disableAllSecurity: false, sslPinning: { certs: ['c'] } });
