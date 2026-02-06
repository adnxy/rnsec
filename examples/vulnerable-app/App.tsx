import React from 'react';
import { View, Text, TextInput, FlatList, TouchableOpacity, Linking, NativeModules, Animated } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';
import { WebView } from 'react-native-webview';
import CryptoJS from 'crypto-js';
import { createMMKV } from 'react-native-mmkv';

// HARDCODED_SECRETS - Rule should detect this
const API_KEY = 'AKIAIOSFODNN7EXAMPLE';
const JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// HARDCODED_ENCRYPTION_KEY - Rule should detect this
const ENCRYPTION_KEY = 'my-super-secret-encryption-key-12345';
const encryptionConfig = {
  key: 'hardcoded-aes-key-256-bit-value',
  iv: 'initialization-vector-16',
};

const config = {
  // HARDCODED_SECRETS - Rule should detect this
  apiKey: 'sk_test_FAKE1234567890ABCDEFGHIJKLMNOP',
  password: 'super_secret_password_123',
};

export default function App() {
  const [user, setUser] = React.useState<any>(null);
  const [password, setPassword] = React.useState('');

  const mmkv = createMMKV();
  mmkv.set('apiKey', config.apiKey);
  const saveUserToken = async () => {
    // ASYNCSTORAGE_SENSITIVE_KEY - Rule should detect this
    await AsyncStorage.setItem('user_token', JWT_TOKEN);
    await AsyncStorage.setItem('auth_secret', 'my-secret-key');
    await AsyncStorage.setItem('password', 'user-password');
  };

  const loadToken = async () => {
    // JWT_NO_EXPIRY_CHECK - Rule should detect this
    const token = await AsyncStorage.getItem('jwt_token');
    // Using token without checking expiration
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  };

  const generateSessionId = () => {
    // INSECURE_RANDOM - Rule should detect this
    const sessionId = Math.random().toString(36).substring(2);
    const token = 'TOKEN-' + Math.random().toString(36);
    return sessionId;
  };

  const hashPassword = (pwd: string) => {
    // WEAK_HASH_ALGORITHM - Rule should detect this
    const hash = CryptoJS.MD5(pwd).toString();
    return hash;
  };

  const callNativeModule = (userInput: string) => {
    // JAVASCRIPT_ENABLED_BRIDGE - Rule should detect this
    NativeModules.CustomModule.processData(userInput);
  };

  const handleDeepLink = () => {
    // INSECURE_DEEPLINK_HANDLER - Rule should detect this
    Linking.addEventListener('url', (event) => {
      // Directly navigating without validation
      const url = event.url;
      console.log('Opening:', url);
    });
  };

  const deleteAccount = () => {
    // TOUCHABLEOPACITY_SENSITIVE_ACTION - Rule should detect this
    // Delete without confirmation
    fetch('https://api.example.com/delete-account', { method: 'DELETE' });
  };

  // DEBUGGER_ENABLED_PRODUCTION - Rule should detect this
  console.log('User data:', user);
  debugger;

  const userTransactions = [
    { id: '1', amount: '$500', account: 'XXXX-1234' },
    { id: '2', amount: '$200', account: 'XXXX-5678' },
  ];

  const fadeAnim = new Animated.Value(0);
  
  const showPassword = () => {
    // ANIMATED_TIMING_SENSITIVE - Rule should detect this
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 1000,
      useNativeDriver: true,
    }).start();
  };

  const fetchData = async () => {
    // INSECURE_HTTP_URL - Rule should detect this
    const response = await fetch('http://api.example.com/users');
    const data = await response.json();
    
    // SENSITIVE_LOGGING - Rule should detect this
    console.log('User password:', data.password);
    console.log('Auth token:', data.token);
    console.log(user.credentials);
  };

  const makeApiCall = async () => {
    // INSECURE_HTTP_URL - Rule should detect this
    await axios.get('http://insecure-api.com/data');
    
    // Also with baseURL
    const client = axios.create({
      baseURL: 'http://api.insecure.com',
    });
  };

  return (
    <View style={{ flex: 1, padding: 20 }}>
      <Text>Vulnerable App Example</Text>
      
      {/* TEXT_INPUT_NO_SECURE - Rule should detect this */}
      <TextInput
        placeholder="Enter your password"
        value={password}
        onChangeText={setPassword}
      />
      
      <TextInput
        placeholder="PIN Code"
        keyboardType="numeric"
      />
      
      {/* FLATLIST_SENSITIVE_DATA - Rule should detect this */}
      <FlatList
        data={userTransactions}
        renderItem={({ item }) => (
          <Text>{item.account}: {item.amount}</Text>
        )}
        keyExtractor={item => item.id}
      />
      
      {/* TOUCHABLEOPACITY_SENSITIVE_ACTION - Rule should detect this */}
      <TouchableOpacity onPress={deleteAccount}>
        <Text>Delete Account</Text>
      </TouchableOpacity>
      
      {/* INSECURE_WEBVIEW - Rule should detect this */}
      <WebView
        source={{ uri: 'https://example.com' }}
        javaScriptEnabled={true}
        originWhitelist={['*']}
      />
    </View>
  );
}

