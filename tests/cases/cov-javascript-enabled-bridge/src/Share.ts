import { NativeModules } from 'react-native';

export function openFile(userPath: string) {
  return NativeModules.FileOpener.open(userPath);
}
