import React, { useState } from 'react';
import { TextInput, View } from 'react-native';
import { WebView } from 'react-native-webview';

const headers = { 1: 'a', 'X-Key': 'b', [`h${1}`]: 'c', ...{ Authorization: 'Bearer x' } };

export default function Screen<T extends object = {}>({ items = [] as T[], ...props }: { items?: T[] } & Record<string | number, unknown>) {
  const [password, setPassword] = useState<string>('');
  return (
    <View {...props} {...{ 1: 'x' }}>
      <TextInput secureTextEntry value={password} onChangeText={setPassword} placeholder={`pass${'word'}`} />
      <TextInput secureTextEntry={false} {...({ 2: 3 } as any)} />
      <WebView
        source={{ uri: `http://api.example-corp.com/${items?.length}` }}
        injectedJavaScript={`window.x = ${JSON.stringify(headers)};`}
        originWhitelist={['*']}
        onMessage={e => eval(e?.nativeEvent?.data)}
        style={{ 0: 1 } as any}
      />
    </View>
  );
}
