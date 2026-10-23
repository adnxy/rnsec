import React from 'react';
import { WebView } from 'react-native-webview';

export function Account({ token }: { token: string }) {
  return (
    <WebView
      source={{ uri: 'https://app.example.com/account', headers: { Authorization: `Bearer ${token}` } }}
      cacheEnabled
    />
  );
}
