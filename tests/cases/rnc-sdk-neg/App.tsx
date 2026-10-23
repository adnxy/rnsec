import React from 'react';
import { View } from 'react-native';

// payment screen: adjustPadding only changes layout, there is no attribution SDK here
function adjustPadding(base: number) {
  return base + 4;
}

export default function App() {
  return <View style={{ padding: adjustPadding(8) }} />;
}
