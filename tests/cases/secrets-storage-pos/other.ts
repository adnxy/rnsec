import * as FS from 'expo-file-system';
import RNFS from 'react-native-fs';
import Clip from 'expo-clipboard';
import { persistReducer } from 'redux-persist';
import AsyncStorage from '@react-native-async-storage/async-storage';

export async function writes(password: string, accessToken: string) {
  await RNFS.writeFile(RNFS.DownloadDirectoryPath + '/export.json', '{}');
  await FS.writeAsStringAsync(FS.documentDirectory + 'creds.json', accessToken);
  await Clip.setStringAsync(password);
}

const persistConfig = { key: 'root', storage: AsyncStorage, whitelist: ['auth', 'settings'] };
export const reducer = persistReducer(persistConfig, (s: any) => s);
