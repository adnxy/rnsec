import React from 'react';
import { View, Text } from 'react-native';
import * as SecureStore from 'expo-secure-store';

// Good practices - no hardcoded secrets, using secure storage
export default function App() {
  const [user, setUser] = React.useState<any>(null);

  const saveUserToken = async () => {
    // ✓ Using secure storage instead of AsyncStorage
    const token = await getTokenFromSecureSource();
    await SecureStore.setItemAsync('user_token', token);
  };

  const fetchData = async () => {
    // ✓ Using HTTPS
    const response = await fetch('https://api.example.com/users');
    const data = await response.json();
    
    // ✓ No sensitive data in logs
    console.log('User data fetched successfully');
    return data;
  };

  const getTokenFromSecureSource = async (): Promise<string> => {
    // ✓ Token retrieved from environment or secure config
    return process.env.API_TOKEN || '';
  };

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>Secure React Native App</Text>
    </View>
  );
}







