import React from 'react';
import * as SecureStore from 'expo-secure-store';

// payment, banking, health, crypto, transaction, authentication, biometric
export default function App() {
  SecureStore.getItemAsync('transactions');
  return null;
}
