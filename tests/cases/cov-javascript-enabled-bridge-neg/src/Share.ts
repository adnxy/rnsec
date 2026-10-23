import { NativeModules } from 'react-native';
import { validatePath } from './validate';

export function openFile(userPath: string) {
  const safePath = validatePath(userPath);
  return NativeModules.FileOpener.open(safePath);
}
