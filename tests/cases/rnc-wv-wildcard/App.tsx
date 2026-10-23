import React from 'react';
import { WebView } from 'react-native-webview';

export function Dynamic({ url }: { url: string }) {
  return <WebView source={{ uri: url }} originWhitelist={['*']} />;
}

export function Literal() {
  return <WebView source={{ uri: 'https://example.com' }} originWhitelist={['*']} />;
}

export function StaticHtml() {
  return <WebView source={{ html: '<p>hello</p>' }} originWhitelist={['*']} />;
}

export function AlreadyInsecureWebView() {
  return <WebView source={{ uri: 'https://example.com' }} originWhitelist={['*']} javaScriptEnabled={true} />;
}

export function Defaults() {
  return <WebView source={{ uri: 'https://example.com' }} originWhitelist={['http://*', 'https://*']} />;
}

export function Narrow() {
  return <WebView source={{ uri: 'https://example.com' }} originWhitelist={['https://example.com']} />;
}
