import React from 'react';
import { View, Text, Linking } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as AuthSession from 'expo-auth-session';
import { WebView } from 'react-native-webview';

// Good practices - no hardcoded secrets, using secure storage
export default function App() {
  const [user, setUser] = React.useState<any>(null);

  const saveUserToken = async () => {
    // SAFE: Using secure storage instead of AsyncStorage
    const token = await getTokenFromSecureSource();
    await SecureStore.setItemAsync('user_token', token);
  };

  const fetchData = async () => {
    // SAFE: Using HTTPS
    const response = await fetch('https://api.example.com/users');
    const data = await response.json();

    // SAFE: No sensitive data in logs
    console.log('User data fetched successfully');
    return data;
  };

  const getTokenFromSecureSource = async (): Promise<string> => {
    // SAFE: Token retrieved from environment or secure config
    return process.env.API_TOKEN || '';
  };

  // SAFE: Linking.openURL with hardcoded string literal - should NOT trigger INSECURE_LINKING_OPEN
  const openDocs = () => {
    Linking.openURL('https://docs.example.com');
  };

  // SAFE: Linking.openURL with validation - should NOT trigger INSECURE_LINKING_OPEN
  const openValidatedUrl = (url: string) => {
    if (url.startsWith('https://')) {
      Linking.openURL(url);
    }
  };

  // SAFE: Navigation without sensitive params - should NOT trigger SENSITIVE_NAVIGATION_PARAMS
  const goToScreen = (navigation: any) => {
    navigation.navigate('Details', { itemId: 42, title: 'Hello' });
  };

  // SAFE: AuthSession with PKCE enabled (default) - should NOT trigger EXPO_AUTH_SESSION_NO_PKCE
  const [request, response, promptAsync] = AuthSession.useAuthRequest({
    clientId: 'my-client-id',
    usePKCE: true,
    redirectUri: 'myapp://redirect',
  });

  // SAFE: Secure WebSocket - should NOT trigger INSECURE_WEBSOCKET
  const ws = new WebSocket('wss://api.example.com/socket');

  // SAFE: No hardcoded IP in URL - should NOT trigger HARDCODED_IP_ADDRESS
  const apiUrl = process.env.API_URL || 'https://api.example.com';

  // SAFE: Using __DEV__ guard for IP - should NOT trigger
  const devServer = __DEV__ ? 'http://192.168.1.100:3000' : 'https://api.example.com';

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>Secure React Native App</Text>

      {/* SAFE: WebView debugging behind __DEV__ - should NOT trigger ANDROID_WEBVIEW_DEBUG_ENABLED */}
      <WebView
        source={{ uri: 'https://example.com' }}
        webContentsDebuggingEnabled={__DEV__}
      />
    </View>
  );
}







