import React from 'react';
import { WebView, WebView as RNWebView } from 'react-native-webview';
import { handleElsewhere } from './handlers';

export function BareJs({ target }: { target: string }) {
  return <WebView source={{ uri: target }} javaScriptEnabled />;
}

export function FixedHost({ id }: { id: string }) {
  return <WebView source={{ uri: `https://app.example.com/items/${id}` }} javaScriptEnabled={true} onShouldStartLoadWithRequest={() => true} />;
}

export function UnknownHandler() {
  return <WebView source={{ uri: 'https://app.example.com/' }} onMessage={handleElsewhere} />;
}

export function UncheckedHandler() {
  return <WebView source={{ uri: 'https://app.example.com/' }} onMessage={(e) => run(e.nativeEvent.data)} />;
}

export function UniversalFileAccess() {
  return <WebView source={{ html: '<p>x</p>' }} allowUniversalAccessFromFileURLs={true} />;
}

export function Aliased() {
  return <RNWebView source={{ uri: 'https://x.example.com' }} allowFileAccess={true} />;
}

export function Mixed() {
  return <WebView source={{ uri: 'https://x.example.com' }} mixedContentMode={'always'} />;
}

export function InlineScript() {
  return <WebView source={{ html: '<script>window.x = 1</script>' }} />;
}

export function RemoteStorage() {
  return <WebView source={{ uri: 'https://app.example.com/' }} javaScriptEnabled={true} domStorageEnabled={true} onShouldStartLoadWithRequest={() => true} />;
}

declare function run(data: string): void;
