import * as FileSystem from 'expo-file-system';
import Clipboard from '@react-native-clipboard/clipboard';
import { persistReducer } from 'redux-persist';
import createSecureStorage from 'redux-persist-expo-securestore';

export async function writes(report: string, author: string) {
  await FileSystem.writeAsStringAsync(FileSystem.cacheDirectory + 'report.txt', report);
  await FileSystem.writeAsStringAsync(FileSystem.documentDirectory + 'notes.txt', author);
  Clipboard.setString(author);
  Clipboard.setString('https://example-app.dev/invite/abc');
}

const config = { key: 'root', storage: createSecureStorage(), whitelist: ['auth'] };
export const reducer = persistReducer(config, (s: any) => s);
