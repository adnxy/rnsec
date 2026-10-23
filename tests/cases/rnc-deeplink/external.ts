import { Linking } from 'react-native';
import { handleUrl } from './handler';

Linking.addEventListener('url', handleUrl);

export function initial(go: (u: string | null) => void) {
  Linking.getInitialURL().then((url) => {
    go(url);
  });
}
