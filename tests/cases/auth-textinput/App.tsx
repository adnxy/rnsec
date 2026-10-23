import React from 'react';
import { TextInput } from 'react-native';

export function Form({ passportNumber, setPassportNumber, password, setPassword }) {
  return (
    <>
      <TextInput value={passportNumber} onChangeText={setPassportNumber} placeholder="Passport" />
      <TextInput placeholder="Passwordless sign-in email" />
      <TextInput value={password} onChangeText={setPassword} placeholder="Password" />
    </>
  );
}

export function Spread(props) {
  return <TextInput {...props} placeholder="Password" />;
}
export function Auto() {
  return <TextInput autoComplete="current-password" />;
}
