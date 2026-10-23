import React, { useState } from 'react';
import { View, TextInput } from 'react-native';

export default function PaymentScreen() {
  const [cardNumber, setCardNumber] = useState('');
  return (
    <View>
      <TextInput placeholder="Card number" value={cardNumber} onChangeText={setCardNumber} />
    </View>
  );
}
