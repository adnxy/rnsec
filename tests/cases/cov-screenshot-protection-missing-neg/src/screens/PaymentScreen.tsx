import React, { useEffect, useState } from 'react';
import { View, TextInput } from 'react-native';
import * as ScreenCapture from 'expo-screen-capture';

export default function PaymentScreen() {
  const [cardNumber, setCardNumber] = useState('');
  useEffect(() => {
    ScreenCapture.preventScreenCaptureAsync();
  }, []);
  return (
    <View>
      <TextInput placeholder="Card number" value={cardNumber} onChangeText={setCardNumber} />
    </View>
  );
}
