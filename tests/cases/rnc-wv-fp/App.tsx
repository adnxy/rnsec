import React from 'react';
import { WebView } from 'react-native-webview';

export function StaticHtml() {
  return (
    <WebView
      source={{ html: '<h1>Terms</h1>' }}
      javaScriptEnabled={true}
      domStorageEnabled={true}
      onMessage={() => {}}
    />
  );
}

export function LocalPage() {
  return <WebView source={require('./page.html')} javaScriptEnabled={true} />;
}

const guard = (e: any) => {
  if (e.nativeEvent.url !== 'https://app.example.com/') return;
};

export function CheckedHandler() {
  return <WebView source={{ uri: 'https://app.example.com/' }} onMessage={guard} />;
}

export function DescriptionOnly() {
  return <WebView source={{ html: '<p>Product description</p>' }} />;
}

export function NoSource() {
  return <WebView />;
}

export function LocalFileAccess() {
  return <WebView source={{ html: '<p>local</p>' }} allowFileAccess={true} />;
}
