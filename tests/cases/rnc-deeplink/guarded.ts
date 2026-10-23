import { Linking } from 'react-native';

export function listen(go: (path: string) => void) {
  Linking.addEventListener('url', ({ url }) => {
    const parsed = new URL(url);
    if (parsed.hostname !== 'app.example.com') return;
    go(parsed.pathname);
  });
}

const onUrl = (e: { url: string }) => {
  if (isAllowedUrl(e.url)) open(e.url);
};
export const listenNamed = () => Linking.addEventListener('url', onUrl);

declare function isAllowedUrl(u: string): boolean;
declare function open(u: string): void;
