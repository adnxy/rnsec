import React from 'react';
import { View, Text, Alert } from 'react-native';

const FIREBASE_API_KEY = 'AIzaSyDemoKey1234567890123456789012';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const STRIPE_KEY = 'sk_live_51H8h9h9h9h9h9h9h9h9h9h9h9h9h9h9h9h';
const GITHUB_TOKEN = 'ghp_ExampleToken1234567890123456789012';

const testPassword = 'password123';
const testUser = 'admin';

const API_URL = 'http://localhost:3000/debug/api';
const DEV_ENDPOINT = 'http://192.168.1.100:8080/test';

if (window.__REDUX_DEVTOOLS_EXTENSION__) {
  console.log('Redux DevTools enabled');
}

alert('Debug mode active');

const TestApp = () => {
  return (
    <View>
      <Text>Test App with vulnerabilities</Text>
    </View>
  );
};

export default TestApp;

