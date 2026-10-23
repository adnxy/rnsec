import { Linking } from 'react-native';

export function commentOnly(go: (u: string) => void) {
  // check the url here eventually
  Linking.addEventListener('url', (e) => {
    go(e.url);
  });
}

export function checkoutName(goCheckout: (u: string) => void) {
  Linking.addEventListener('url', (e) => goCheckout(e.url));
}
