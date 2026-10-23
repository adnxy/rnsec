import React from 'react';
import { WebView } from 'react-native-webview';

export function StoreLocator() {
  return <WebView source={{ uri: 'https://stores.example.com/map' }} geolocationEnabled={true} />;
}
