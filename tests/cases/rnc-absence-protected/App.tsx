import React from 'react';
import { StripeProvider } from '@stripe/stripe-react-native';

export default function App() {
  return <StripeProvider publishableKey="pk_test_x" children={null} />;
}
