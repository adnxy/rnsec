import React from 'react';
import { Platform } from 'react-native';
import { WebView } from 'react-native-webview';

const layout =
  Platform.OS === 'ios'
    ? require('./layout/index.html')
    : { uri: 'file:///android_asset/layout/index.html' };

export function Chart() {
  return <WebView originWhitelist={['*']} source={layout} />;
}

export function Remote({ url }: { url: string }) {
  return <WebView originWhitelist={['*']} source={{ uri: url }} />;
}
