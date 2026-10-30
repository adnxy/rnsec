import { Linking } from 'react-native';
import { useState } from 'react';
import { Note } from './models';
import { useRoute } from '@react-navigation/native';
import { SUPPORT_URL, AppUrls } from './constants';
import strings from './strings';

const PRIVACY = 'https://example.com/privacy';
const TERMS_URL = `https://example.com/terms`;
enum Links { Help = 'https://example.com/help' }

export function constants(id: string, phone: string) {
  Linking.openURL('https://example.com');
  Linking.openURL(PRIVACY);
  Linking.openURL(TERMS_URL);
  Linking.openURL(SUPPORT_URL);
  Linking.openURL(AppUrls.privacy);
  Linking.openURL(Links.Help);
  Linking.openURL(strings('learn_more_url'));
  Linking.openURL(`https://example.com/tx/${id}`);
  Linking.openURL('https://example.com/tx/' + id);
  Linking.openURL(`tel:${phone}`);
  Linking.openURL(`mailto:${phone}?subject=hi`);
  const local = `https://example.com/a/${id}`;
  Linking.openURL(local);
}

export function routeParam() {
  const route = useRoute<any>();
  const { target } = route.params;
  Linking.openURL(target);
}

export async function serverData() {
  const res = await fetch('https://example.com/banner');
  const banner = await res.json();
  Linking.openURL(banner.deeplink);
}

export function dynamicScheme(scheme: string, path: string) {
  Linking.openURL(`${scheme}://${path}`);
}

export function bareParam(url: string) {
  Linking.openURL(url);
}

export function deepLinkEvent() {
  Linking.addEventListener('url', ({ url }) => {
    Linking.openURL(url);
  });
}

// ----------------------------------------------------------------------------------------------------------------------------------
// the validation above is only a neighbour of the call below when it is within the look-around window of the previous function

export function guarded(url: string) {
  if (url.startsWith('https://') && Linking.canOpenURL(url)) {
    Linking.openURL(url);
  }
}

// ----------------------------------------------------------------------------------------------------------------------------------

export function Payload({ action }: any) {
  const [target, setTarget] = useState('');
  setTarget(action.url);
  return <Button onPress={() => Linking.openURL(target)} />;
}

// ----------------------------------------------------------------------------------------------------------------------------------

export async function storedNote(id: string) {
  const note = await Note.load(id);
  await Linking.openURL(note.source_url);
}
