import { NativeModules } from 'react-native';

// IOS_INSECURE_PASTEBOARD_USAGE - Rule should detect this
// Copying sensitive password/token data to the pasteboard
export function copyCredentialToClipboard(password: string) {
  const pasteboard = NativeModules.PasteboardModule;
  pasteboard.copy(password);
}
