import React from 'react';
import { TextInput } from 'react-native';

const TOKEN_KEY = 'auth_token_storage_slot_v2';
const PASSWORD_KEY = 'user_password_slot_name';
const tokenizerEnabled = 'tokenizer_enabled_flag_value';
const bypass = 'bypass_all_checks_flag_value_here';
const passport = 'passport_screen_route_name';
const apiKey = process.env.API_KEY;
const secret = process.env.CLIENT_SECRET ?? undefined;
const labels = {
  password: '',
  passwordLabel: 'Password',
  confirmPassword: 'Confirm password',
  forgotPassword: 'forgot-password',
  token: 'auth.token.label',
  secret: 'Enter your secret here please',
  apiKey: 'YOUR_API_KEY_HERE_PLEASE',
  tokenType: 'Bearer',
  tokenUrl: 'https://auth.example-corp.com/oauth/token',
};
const form = { password: 'password', username: 'username' };

export function Login() {
  const [password, setPassword] = React.useState('');
  return <TextInput secureTextEntry value={password} onChangeText={setPassword} placeholder="Password" />;
}
export { TOKEN_KEY, PASSWORD_KEY, tokenizerEnabled, bypass, passport, apiKey, secret, labels, form };
